package app.pwhs.blockads.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import app.pwhs.blockads.MainActivity
import app.pwhs.blockads.R
import app.pwhs.blockads.data.datastore.AppPreferences
import app.pwhs.blockads.data.repository.FilterListRepository
import app.pwhs.blockads.data.dao.FirewallRuleDao
import app.pwhs.blockads.util.AppNameResolver
import app.pwhs.blockads.util.BatteryMonitor
import app.pwhs.blockads.util.startOfDayMillis
import app.pwhs.blockads.widget.AdBlockWidgetProvider
import app.pwhs.blockads.worker.VpnResumeWorker
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import app.pwhs.blockads.data.dao.DnsLogDao
import app.pwhs.blockads.data.entities.DnsProtocol
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import timber.log.Timber

import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Holds all preference values read in parallel during VPN startup.
 * Uses data class for destructuring support.
 */
private data class PrefsSnapshot(
    val upstreamDns: String,
    val fallbackDns: String,
    val dnsResponseType: String,
    val dnsProtocol: DnsProtocol,
    val dohUrl: String,
    val whitelistedApps: Set<String>,
    val safeSearchEnabled: Boolean,
    val youtubeRestrictedMode: Boolean,
    val firewallEnabled: Boolean,
)

class AdBlockVpnService : VpnService() {

    companion object {
        private const val NOTIFICATION_ID = 1
        private const val REVOKED_NOTIFICATION_ID = 2
        private const val CHANNEL_ID = "blockads_vpn_channel"
        private const val ALERT_CHANNEL_ID = "blockads_vpn_alert_channel"
        private const val NETWORK_STABILIZATION_DELAY_MS = 2000L
        private const val RESTART_CLEANUP_DELAY_MS = 1000L
        const val ACTION_START = "app.pwhs.blockads.START_VPN"
        const val ACTION_STOP = "app.pwhs.blockads.STOP_VPN"
        const val ACTION_PAUSE_1H = "app.pwhs.blockads.PAUSE_VPN_1H"
        const val ACTION_RESTART = "app.pwhs.blockads.RESTART_VPN"

        /**
         * Request a VPN restart to apply new settings.
         * Only restarts if the VPN is currently running.
         */
        fun requestRestart(context: Context) {
            if (isRunning || isRestarting) {
                val intent = Intent(context, AdBlockVpnService::class.java).apply {
                    action = ACTION_RESTART
                }
                context.startService(intent)
            }
        }

        @Volatile
        var isRestarting = false
            private set

        @Volatile
        var isRunning = false
            private set

        @Volatile
        var isConnecting = false
            private set

        @Volatile
        var startTimestamp = 0L
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var filterRepo: FilterListRepository
    private lateinit var appPrefs: AppPreferences
    private lateinit var dnsLogDao: DnsLogDao
    private lateinit var goTunnelAdapter: GoTunnelAdapter
    private var networkMonitor: NetworkMonitor? = null
    private val retryManager =
        VpnRetryManager(maxRetries = 5, initialDelayMs = 1000L, maxDelayMs = 60000L)
    private lateinit var batteryMonitor: BatteryMonitor
    private lateinit var notificationHelper: NotificationHelper
    private var firewallManager: FirewallManager? = null
    private lateinit var firewallRuleDao: FirewallRuleDao
    private lateinit var appNameResolver: AppNameResolver
    private var batteryMonitoringJob: kotlinx.coroutines.Job? = null
    private var notificationUpdateJob: kotlinx.coroutines.Job? = null

    private var vpnStartTime: Long = 0L

    @Volatile
    private var todayBlockedCount: Int = 0

    // Cached all-time blocked count for milestone checks (avoids DB queries on hot path)
    private val allTimeBlockedCount = AtomicLong(0)

    @Volatile
    private var nextMilestoneThreshold: Long? = null

    @Volatile
    private var isReconnecting = false

    /** Current connecting phase for progress notification */
    @Volatile
    var connectingPhase: String = ""
        private set

    override fun onCreate() {
        super.onCreate()
        val koin = org.koin.java.KoinJavaComponent.getKoin()
        filterRepo = koin.get()
        appPrefs = koin.get()
        dnsLogDao = koin.get()
        
        appNameResolver = AppNameResolver(this)
        goTunnelAdapter = GoTunnelAdapter(
            vpnService = this,
            filterRepo = filterRepo,
            dnsLogDao = dnsLogDao,
            scope = serviceScope,
            appNameResolver = appNameResolver,
            firewallManagerProvider = { firewallManager },
        )
        
        firewallRuleDao = koin.get()
        batteryMonitor = BatteryMonitor(this)
        notificationHelper = NotificationHelper(this, appPrefs)

        // Initialize network monitor
        networkMonitor = NetworkMonitor(
            context = this,
            onNetworkAvailable = { onNetworkAvailable() },
            onNetworkLost = { onNetworkLost() }
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }

            ACTION_PAUSE_1H -> {
                pauseVpn()
                return START_NOT_STICKY
            }

            ACTION_RESTART -> {
                restartVpn()
                return START_STICKY
            }

            else -> {
                startVpn()
                return START_STICKY
            }
        }
    }

    private fun restartVpn() {
        if (isRestarting) return
        if (!isRunning && !isConnecting) return

        isRestarting = true
        Timber.d("Restarting VPN to apply new settings")

        // Stop packet processing
        isRunning = false
        isConnecting = false
        isReconnecting = true

        // Stop monitoring
        networkMonitor?.stopMonitoring()
        stopBatteryMonitoring()
        stopNotificationUpdates()

        // Stop Go tunnel engine so its running flags are reset
        goTunnelAdapter.stop()

        // Close current VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Timber.e(e, "Error closing VPN interface during restart")
        }
        vpnInterface = null

        // Reset retry manager for fresh start
        retryManager.reset()

        // Brief delay to let old VPN resources (file descriptors, sockets) clean up
        serviceScope.launch {
            delay(RESTART_CLEANUP_DELAY_MS)

            isRestarting = false
            startVpn()
        }
    }

    private fun startVpn() {
        if (isRunning || isConnecting) return
        isConnecting = true

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        // Start network monitoring
        networkMonitor?.startMonitoring()

        serviceScope.launch {
            try {
                val startupTime = System.currentTimeMillis()

                // ── Phase 1: Load filters ──
                // Always call loadAllEnabledFilters() — the fingerprint cache inside
                // FilterListRepository handles the fast path (~50ms mmap if unchanged,
                // full rebuild only when enabled filters or cache files change).
                connectingPhase = getString(R.string.vpn_phase_loading_filters)
                updateNotification()

                // Load whitelist + custom rules (fast, small sets) BEFORE the large filter trie
                // This ensures they are immediately available for the Go engine.
                filterRepo.loadWhitelist()
                filterRepo.loadCustomRules()

                filterRepo.seedDefaultsIfNeeded()
                val result = filterRepo.loadAllEnabledFilters()
                Timber.d("Filters loaded: ${result.getOrDefault(0)} domains")

                // ── Phase 2: Read all preferences in parallel ──
                connectingPhase = getString(R.string.vpn_phase_preparing_dns)
                updateNotification()

                val (
                    upstreamDns, fallbackDns, dnsResponseType, dnsProtocol,
                    dohUrl, whitelistedApps, safeSearchEnabled,
                    youtubeRestrictedMode, firewallEnabled
                ) = coroutineScope {
                    val d1 = async { appPrefs.upstreamDns.first() }
                    val d2 = async { appPrefs.fallbackDns.first() }
                    val d3 = async { appPrefs.dnsResponseType.first() }
                    val d4 = async { appPrefs.dnsProtocol.first() }
                    val d5 = async { appPrefs.dohUrl.first() }
                    val d6 = async { appPrefs.getWhitelistedAppsSnapshot() }
                    val d7 = async { appPrefs.safeSearchEnabled.first() }
                    val d8 = async { appPrefs.youtubeRestrictedMode.first() }
                    val d9 = async { appPrefs.firewallEnabled.first() }
                    PrefsSnapshot(
                        d1.await(), d2.await(), d3.await(), d4.await(),
                        d5.await(), d6.await(), d7.await(), d8.await(), d9.await()
                    )
                }

                // Load firewall rules if enabled
                if (firewallEnabled) {
                    val fwManager = FirewallManager(this@AdBlockVpnService, firewallRuleDao)
                    fwManager.loadRules()
                    firewallManager = fwManager
                    Timber.d("Firewall enabled, rules loaded")
                } else {
                    firewallManager = null
                }

                // Periodically refresh firewall rules and enabled state while the VPN coroutine is running.
                launch {
                    var lastEnabled = firewallEnabled
                    while (true) {
                        try {
                            val currentEnabled = appPrefs.firewallEnabled.first()

                            if (currentEnabled) {
                                if (!lastEnabled || firewallManager == null) {
                                    val fwManager =
                                        FirewallManager(this@AdBlockVpnService, firewallRuleDao)
                                    fwManager.loadRules()
                                    firewallManager = fwManager
                                    Timber.d("Firewall enabled or re-enabled, rules loaded")
                                } else {
                                    try {
                                        firewallManager?.loadRules()
                                        Timber.d("Firewall rules reloaded")
                                    } catch (e: Exception) {
                                        Timber.e("Error reloading firewall rules: $e")
                                    }
                                }
                            } else if (lastEnabled) {
                                firewallManager = null
                                Timber.d("Firewall disabled via preference change")
                            }

                            lastEnabled = currentEnabled
                        } catch (e: Exception) {
                            Timber.e(e, "Error while monitoring firewall preference")
                        }

                        delay(5_000)
                    }
                }


                // ── Phase 3: Establish VPN tunnel ──
                connectingPhase = getString(R.string.vpn_phase_establishing)
                updateNotification()

                var vpnEstablished = false
                while (!vpnEstablished && retryManager.shouldRetry()) {
                    vpnEstablished = establishVpn(whitelistedApps)

                    if (!vpnEstablished && retryManager.shouldRetry()) {
                        Timber
                            .w("VPN establishment failed, retrying... (${retryManager.getRetryCount()}/${retryManager.getMaxRetries()})")
                        updateNotification()
                        retryManager.waitForRetry()
                    }
                }

                if (!vpnEstablished) {
                    Timber
                        .e("Failed to establish VPN after ${retryManager.getMaxRetries()} attempts")
                    isConnecting = false
                    connectingPhase = ""
                    stopVpn()
                    return@launch
                }

                // VPN established successfully - reset retry counter
                retryManager.reset()
                isConnecting = false
                connectingPhase = ""
                isReconnecting = false
                isRunning = true
                appPrefs.setVpnEnabled(true)
                vpnStartTime = System.currentTimeMillis()
                startTimestamp = vpnStartTime

                val startupElapsed = System.currentTimeMillis() - startupTime
                Timber.d("VPN startup completed in ${startupElapsed}ms")

                // Initialize cached all-time blocked count for milestone checks
                val cachedTotal = dnsLogDao.getBlockedCountSync().toLong()
                allTimeBlockedCount.set(cachedTotal)
                val lastMilestone = appPrefs.lastMilestoneBlocked.first()
                nextMilestoneThreshold = notificationHelper.nextMilestoneThreshold(lastMilestone)

                updateNotification() // Update to normal notification
                Timber.d("VPN established successfully")

                // Update home screen widgets
                AdBlockWidgetProvider.sendUpdateBroadcast(this@AdBlockVpnService)

                // Log initial battery state
                batteryMonitor.logBatteryStatus()

                // Start periodic battery monitoring
                startBatteryMonitoring()

                // Start periodic notification updates with stats
                startNotificationUpdates()

                // Configure and start Go tunnel engine
                goTunnelAdapter.configureDns(
                    protocol = dnsProtocol.name,
                    primary = upstreamDns,
                    fallback = fallbackDns,
                    dohUrl = dohUrl
                )
                goTunnelAdapter.setBlockResponseType(dnsResponseType)
                goTunnelAdapter.configureSafeSearch(safeSearchEnabled, youtubeRestrictedMode)

                // Dynamically update Go Engine Native Tries whenever filters change (enabled/disabled/deleted)
                // We use drop(1) because start() already calls updateTries() once on boot.
                launch {
                    filterRepo.domainCountFlow.drop(1).collectLatest { count ->
                        Timber.d("Filter count changed to $count. Dynamically updating Native Go Tries.")
                        goTunnelAdapter.updateTries()
                    }
                }
                
                vpnInterface?.let {
                    // start() blocks the coroutine while reading from TUN
                    goTunnelAdapter.start(it)
                }

            } catch (e: Exception) {
                Timber.e(e, "VPN startup failed")
                isConnecting = false
                stopVpn()
            }
        }
    }

    private fun establishVpn(whitelistedApps: Set<String>): Boolean {
        return try {
            // Establish VPN — only route DNS traffic, NOT all traffic
            // We use a fake DNS server IP (10.0.0.1) and only route that IP
            // through the TUN. All other traffic uses the normal network.
            val builder = Builder()
                .setSession("BlockAds")
                .addAddress("10.0.0.2", 32)
                .addRoute("10.0.0.1", 32)    // Only route fake DNS IP through TUN
                .addDnsServer("10.0.0.1")     // System sends DNS queries here
                .addAddress("fd00::2", 128)   // IPv6 TUN address
                .addRoute("fd00::1", 128)     // Route IPv6 DNS through TUN
                .addDnsServer("fd00::1")       // IPv6 DNS server
                .setBlocking(true)
                .setMtu(1500)

            // Exclude our own app from VPN to avoid loops
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Timber.w(e, "Could not exclude self from VPN")
            }

            // Exclude whitelisted apps from VPN
            for (appPackage in whitelistedApps) {
                try {
                    builder.addDisallowedApplication(appPackage)
                    Timber.d("Excluded from VPN: $appPackage")
                } catch (e: Exception) {
                    Timber.w(e, "Could not exclude $appPackage from VPN")
                }
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Timber.e("Failed to establish VPN interface")
                return false
            }

            true
        } catch (e: Exception) {
            Timber.e(e, "Error establishing VPN")
            false
        }
    }

    private fun pauseVpn() {
        Timber.d("Pausing VPN for 1 hour")

        // Schedule resume after 1 hour
        val resumeWork = OneTimeWorkRequestBuilder<VpnResumeWorker>()
            .setInitialDelay(1, TimeUnit.HOURS)
            .build()
        WorkManager.getInstance(this).enqueueUniqueWork(
            VpnResumeWorker.WORK_NAME,
            androidx.work.ExistingWorkPolicy.REPLACE,
            resumeWork
        )

        // Stop VPN but show paused notification
        stopVpn(showStoppedNotification = false)
        showPausedNotification()
    }

    private fun showPausedNotification() {
        createNotificationChannel()

        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val startIntent = Intent(this, AdBlockVpnService::class.java).apply {
            action = ACTION_START
        }
        val startPendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            PendingIntent.getForegroundService(
                this, 3, startIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            PendingIntent.getService(
                this, 3, startIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        }

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val notification = builder
            .setContentTitle(getString(R.string.vpn_paused_title))
            .setContentText(getString(R.string.vpn_paused_text))
            .setSmallIcon(R.drawable.ic_shield_off)
            .setOngoing(false)
            .setContentIntent(pendingIntent)
            .addAction(
                Notification.Action.Builder(
                    null, getString(R.string.vpn_stopped_action_enable), startPendingIntent
                ).build()
            )
            .build()

        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun stopVpn(showStoppedNotification: Boolean = true) {
        isConnecting = false
        isRunning = false
        isReconnecting = false
        isRestarting = false
        startTimestamp = 0L

        // Stop Go tunnel engine
        goTunnelAdapter.stop()

        // Stop network monitoring
        networkMonitor?.stopMonitoring()

        // Stop battery monitoring
        stopBatteryMonitoring()

        // Stop notification updates
        stopNotificationUpdates()

        runBlocking {
            appPrefs.setVpnEnabled(false)
        }

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Timber.e("Error closing VPN interface: $e")
        }
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (showStoppedNotification) {
            stopForeground(STOP_FOREGROUND_DETACH)
            showStoppedNotification()
        } else {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
        stopSelf()
        Timber.d("VPN stopped")

        // Update home screen widgets
        AdBlockWidgetProvider.sendUpdateBroadcast(this)
    }

    override fun onRevoke() {
        Timber.w("VPN revoked by system or user")
        // Update preferences to reflect VPN is no longer enabled
        // Use a non-cancellable context to ensure preference is updated
        serviceScope.launch(NonCancellable) {
            appPrefs.setVpnEnabled(false)
        }
        showRevokedNotification()
        stopVpn(showStoppedNotification = false)
        super.onRevoke()
    }

    override fun onDestroy() {
        isConnecting = false
        isRunning = false
        isReconnecting = false
        isRestarting = false
        startTimestamp = 0L

        // Stop network monitoring
        networkMonitor?.stopMonitoring()

        // Stop battery monitoring
        stopBatteryMonitoring()

        // Stop notification updates
        stopNotificationUpdates()

        serviceScope.cancel()
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_description)
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createAlertNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                ALERT_CHANNEL_ID,
                getString(R.string.vpn_alert_channel_name),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = getString(R.string.vpn_alert_channel_description)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun showRevokedNotification() {
        createAlertNotificationChannel()

        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 2, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, ALERT_CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val notification = builder
            .setContentTitle(getString(R.string.vpn_revoked_title))
            .setContentText(getString(R.string.vpn_revoked_text))
            .setSmallIcon(R.drawable.ic_error)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(REVOKED_NOTIFICATION_ID, notification)
    }

    private fun showStoppedNotification() {
        createNotificationChannel()

        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val startIntent = Intent(this, AdBlockVpnService::class.java).apply {
            action = ACTION_START
        }
        val startPendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            PendingIntent.getForegroundService(
                this, 3, startIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        } else {
            PendingIntent.getService(
                this, 3, startIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        }

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val notification = builder
            .setContentTitle(getString(R.string.vpn_stopped_title))
            .setContentText(getString(R.string.vpn_stopped_text))
            .setSmallIcon(R.drawable.ic_shield_off)
            .setOngoing(false)
            .setContentIntent(pendingIntent)
            .addAction(
                Notification.Action.Builder(
                    null, getString(R.string.vpn_stopped_action_enable), startPendingIntent
                ).build()
            )
            .build()

        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun buildNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, AdBlockVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val pauseIntent = Intent(this, AdBlockVpnService::class.java).apply {
            action = ACTION_PAUSE_1H
        }
        val pausePendingIntent = PendingIntent.getService(
            this, 4, pauseIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val title = when {
            isReconnecting -> getString(R.string.vpn_notification_reconnecting)
            retryManager.getRetryCount() > 0 -> getString(R.string.vpn_notification_retrying)
            isConnecting && connectingPhase.isNotEmpty() -> getString(R.string.status_connecting)
            else -> getString(R.string.vpn_notification_title)
        }

        val text = when {
            isReconnecting -> getString(R.string.vpn_notification_reconnecting_text)
            retryManager.getRetryCount() > 0 -> getString(
                R.string.vpn_notification_retry_text,
                retryManager.getRetryCount(),
                retryManager.getMaxRetries()
            )

            isConnecting && connectingPhase.isNotEmpty() -> connectingPhase

            isRunning -> {
                val uptimeStr = formatUptime(System.currentTimeMillis() - vpnStartTime)
                val todayBlocked = todayBlockedCount
                getString(R.string.vpn_notification_stats_today, todayBlocked, uptimeStr)
            }

            else -> getString(R.string.vpn_notification_text)
        }

        return builder
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .addAction(
                Notification.Action.Builder(
                    null, getString(R.string.vpn_notification_action_pause), pausePendingIntent
                ).build()
            )
            .addAction(
                Notification.Action.Builder(
                    null, getString(R.string.vpn_notification_action_stop), stopPendingIntent
                ).build()
            )
            .build()
    }

    private fun updateNotification() {
        val notification = buildNotification()
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, notification)
        // update home screen widgets as well
        AdBlockWidgetProvider.sendUpdateBroadcast(this)
    }

    private fun onNetworkAvailable() {
        Timber.d("Network available - checking VPN status")

        // Use serviceScope to avoid blocking the callback thread
        serviceScope.launch {
            val autoReconnect = appPrefs.autoReconnect.first()
            val vpnWasEnabled = appPrefs.vpnEnabled.first()

            // If VPN should be running but isn't, try to reconnect
            if (autoReconnect && vpnWasEnabled && !isRunning && !isConnecting && !isReconnecting) {
                Timber.d("Auto-reconnecting VPN after network became available")
                isReconnecting = true

                // Wait a bit for network to stabilize
                delay(NETWORK_STABILIZATION_DELAY_MS)

                if (!isRunning && !isConnecting) {
                    retryManager.reset()
                    startVpn()
                }
                isReconnecting = false
            }
        }
    }

    private fun onNetworkLost() {
        Timber.d("Network lost")
        // Note: We don't stop the VPN when network is lost, as it may come back
        // The VPN will automatically reconnect when network is available again
    }

    /**
     * Start periodic battery monitoring to track battery usage.
     * Logs battery status every 5 minutes while VPN is running.
     */
    private fun startBatteryMonitoring() {
        // Cancel any existing monitoring job
        batteryMonitoringJob?.cancel()

        batteryMonitoringJob = serviceScope.launch {
            while (isRunning) {
                try {
                    delay(5 * 60 * 1000L) // Wait 5 minutes
                    if (isRunning) {
                        batteryMonitor.logBatteryStatus()
                    }
                } catch (e: Exception) {
                    Timber.e("Error monitoring battery: $e")
                    break
                }
            }
        }
    }

    private fun stopBatteryMonitoring() {
        batteryMonitoringJob?.cancel()
        batteryMonitoringJob = null
    }

    /**
     * Start periodic notification updates to refresh stats display.
     * Updates the notification every 30 seconds while VPN is running.
     */
    private fun startNotificationUpdates() {
        notificationUpdateJob?.cancel()

        notificationUpdateJob = serviceScope.launch {
            while (isRunning) {
                try {
                    // Refresh today's blocked count from database
                    todayBlockedCount = dnsLogDao.getBlockedCountSinceSync(startOfDayMillis())

                    delay(30_000L) // Update every 30 seconds
                    if (isRunning) {
                        updateNotification()
                    }
                } catch (e: Exception) {
                    Timber.e(e, "Error updating notification")
                    break
                }
            }
        }
    }

    private fun stopNotificationUpdates() {
        notificationUpdateJob?.cancel()
        notificationUpdateJob = null
    }

    private fun formatUptime(millis: Long): String {
        val totalSeconds = millis / 1000
        val hours = totalSeconds / 3600
        val minutes = (totalSeconds % 3600) / 60
        val seconds = totalSeconds % 60
        return if (hours > 0) {
            String.format(Locale.getDefault(), "%d:%02d:%02d", hours, minutes, seconds)
        } else {
            String.format(Locale.getDefault(), "%d:%02d", minutes, seconds)
        }
    }

    /**
     * Wrapper for VPN service's protect method, exposed for GoTunnelAdapter.
     */
    fun protectSocket(fd: Int): Boolean {
        return protect(fd)
    }
}
