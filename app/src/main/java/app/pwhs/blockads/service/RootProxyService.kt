package app.pwhs.blockads.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import app.pwhs.blockads.MainActivity
import app.pwhs.blockads.R
import kotlinx.coroutines.flow.asStateFlow
import app.pwhs.blockads.data.datastore.AppPreferences
import kotlinx.coroutines.flow.first
import app.pwhs.blockads.data.repository.FilterListRepository
import app.pwhs.blockads.data.dao.DnsLogDao
import app.pwhs.blockads.utils.AppNameResolver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.koin.java.KoinJavaComponent.getKoin
import timber.log.Timber

/**
 * Foreground service for Root/Proxy mode.
 * Uses iptables to redirect all DNS traffic (port 53) to the local Go engine
 * at 127.0.0.1:15353, instead of using VpnService.
 *
 * Lifecycle:
 * - onCreate: Initialize Go engine + Koin dependencies
 * - onStartCommand(ACTION_START): Apply iptables rules + start watchdog
 * - onStartCommand(ACTION_STOP): Teardown iptables + stop engine
 * - onDestroy / onTaskRemoved: Teardown iptables (failsafe)
 */
class RootProxyService : Service() {

    companion object {
        private const val NOTIFICATION_ID = 10
        private const val CHANNEL_ID = "blockads_root_proxy_channel"

        const val ACTION_START = "app.pwhs.blockads.ROOT_START"
        const val ACTION_STOP = "app.pwhs.blockads.ROOT_STOP"

        private val _state = kotlinx.coroutines.flow.MutableStateFlow(VpnState.STOPPED)
        val state: kotlinx.coroutines.flow.StateFlow<VpnState> = _state.asStateFlow()

        val isRunning: Boolean get() = _state.value == VpnState.RUNNING

        @Volatile
        var startTimestamp: Long = 0L
            private set

        fun start(context: Context) {
            val intent = Intent(context, RootProxyService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, RootProxyService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var watchdogJob: Job? = null
    private lateinit var appPrefs: AppPreferences
    private lateinit var filterRepo: FilterListRepository
    private lateinit var dnsLogDao: DnsLogDao
    private lateinit var appNameResolver: AppNameResolver
    private lateinit var goTunnelAdapter: GoTunnelAdapter

    override fun onCreate() {
        super.onCreate()
        val koin = getKoin()
        appPrefs = koin.get()
        filterRepo = koin.get()
        dnsLogDao = koin.get()
        appNameResolver = AppNameResolver(this)
        goTunnelAdapter = GoTunnelAdapter(
            context = this,
            filterRepo = filterRepo,
            dnsLogDao = dnsLogDao,
            scope = serviceScope,
            appNameResolver = appNameResolver,
            firewallManagerProvider = { null } // Per-app firewall not supported in MVP Root Mode
        )
        Timber.d("RootProxyService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProxy()
                return START_NOT_STICKY
            }
            else -> {
                startProxy()
                return START_STICKY
            }
        }
    }

    private fun startProxy() {
        if (_state.value == VpnState.RUNNING || _state.value == VpnState.STARTING) {
            Timber.d("RootProxyService already running/starting")
            return
        }
        
        _state.value = VpnState.STARTING

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        serviceScope.launch {
            try {
                // 1. Load filters (same as VPN mode)
                filterRepo.loadWhitelist()
                filterRepo.loadCustomRules()
                filterRepo.seedDefaultsIfNeeded()
                filterRepo.fetchAndSyncRemoteFilterLists()
                val result = filterRepo.loadAllEnabledFilters()
                Timber.d("Filters loaded for Root Proxy mode: ${result.getOrDefault(0)} domains")

                // 2. Start Go engine in standalone DNS server mode
                val protocol = appPrefs.dnsProtocol.first().name
                val primary = appPrefs.upstreamDns.first()
                val fallback = appPrefs.fallbackDns.first()
                val dohUrl = appPrefs.dohUrl.first()
                val safeSearch = appPrefs.safeSearchEnabled.first()
                val youtubeSafe = appPrefs.youtubeRestrictedMode.first()
                val responseType = appPrefs.dnsResponseType.first()

                goTunnelAdapter.configureDns(protocol, primary, fallback, dohUrl)
                goTunnelAdapter.configureSafeSearch(safeSearch, youtubeSafe)
                goTunnelAdapter.setBlockResponseType(responseType)
                
                goTunnelAdapter.startStandalone(port = 15353)
                Timber.d("Go engine standalone mode started on :15353")

                // 3. Apply iptables rules
                val success = IptablesManager.setupRules(this@RootProxyService)
                if (!success) {
                    Timber.e("Failed to apply iptables rules")
                    stopProxy()
                    return@launch
                }

                _state.value = VpnState.RUNNING
                startTimestamp = System.currentTimeMillis()
                Timber.d("Root Proxy mode active — DNS traffic redirected to :15353")

                // 4. Start watchdog
                startWatchdog()
            } catch (e: Exception) {
                Timber.e(e, "Failed to start Root Proxy mode")
                IptablesManager.teardownRules()
                stopSelf()
            }
        }
    }

    private fun stopProxy() {
        Timber.d("Stopping Root Proxy mode")
        _state.value = VpnState.STOPPING
        watchdogJob?.cancel()

        // Teardown iptables rules (critical — prevents internet loss)
        IptablesManager.teardownRules()

        // Stop Go engine
        goTunnelAdapter.stop()

        _state.value = VpnState.STOPPED
        startTimestamp = 0L
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /**
     * Watchdog monitors Go engine health every 10 seconds.
     * If the engine is dead, teardown iptables to prevent internet loss.
     */
    private fun startWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = serviceScope.launch {
            while (isActive && _state.value == VpnState.RUNNING) {
                delay(10_000)
                // TODO: Check Go engine health
                // if (!goEngine.isRunning()) {
                //     Timber.w("Go engine died — tearing down iptables")
                //     IptablesManager.teardownRules()
                //     isRunning = false
                //     stopSelf()
                //     break
                // }

                // For now, check if iptables rules are still active
                if (!IptablesManager.isActive()) {
                    Timber.w("iptables rules disappeared — re-applying")
                    IptablesManager.setupRules(this@RootProxyService)
                }
            }
        }
    }

    override fun onDestroy() {
        Timber.d("RootProxyService onDestroy — teardown iptables")
        _state.value = VpnState.STOPPED
        startTimestamp = 0L
        watchdogJob?.cancel()
        IptablesManager.teardownRules()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        Timber.d("RootProxyService onTaskRemoved — teardown iptables")
        IptablesManager.teardownRules()
        super.onTaskRemoved(rootIntent)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ── Notification ───────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Root Proxy Mode",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows when Root Proxy ad blocker is active"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.root_proxy_notification_text))
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
