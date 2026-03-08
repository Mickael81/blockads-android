package app.pwhs.blockads.ui.dnsprovider

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.pwhs.blockads.data.datastore.AppPreferences
import app.pwhs.blockads.data.entities.DnsCategory
import app.pwhs.blockads.data.entities.DnsProtocol
import app.pwhs.blockads.data.entities.DnsProvider
import app.pwhs.blockads.data.entities.DnsProviders
import app.pwhs.blockads.service.AdBlockVpnService
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class DnsProviderViewModel(
    private val appPrefs: AppPreferences,
    application: Application
) : AndroidViewModel(application) {

    val fallbackDns: StateFlow<String> = appPrefs.fallbackDns
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5000),
            AppPreferences.DEFAULT_FALLBACK_DNS
        )

    val selectedProviderId: StateFlow<String?> = combine(
        appPrefs.dnsProviderId,
        appPrefs.upstreamDns
    ) { providerId, upstreamDns ->
        // If provider ID is set, use it
        providerId ?: // Otherwise, try to detect provider from current upstream DNS
        DnsProviders.getByIp(upstreamDns)?.id
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    val customDnsEnabled: StateFlow<Boolean> = combine(
        appPrefs.dnsProviderId,
        appPrefs.upstreamDns
    ) { providerId, upstreamDns ->
        // Custom DNS is enabled if no provider ID is set and IP doesn't match any preset
        providerId == null && DnsProviders.getByIp(upstreamDns) == null
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), false)

    /**
     * Unified display value for the custom DNS input.
     * Shows the current DNS server in the format the user originally entered:
     * - Plain DNS: IP address (e.g., "8.8.8.8")
     * - DoH: full URL (e.g., "https://dns.google/dns-query")
     * - DoT: tls:// prefix + server (e.g., "tls://dns.google")
     */
    val customDnsDisplay: StateFlow<String> = combine(
        appPrefs.dnsProtocol,
        appPrefs.upstreamDns,
        appPrefs.dohUrl
    ) { protocol, upstream, doh ->
        when (protocol) {
            DnsProtocol.DOH -> doh
            DnsProtocol.DOT -> "tls://$upstream"
            DnsProtocol.DOQ -> "quic://${doh.removePrefix("https://")}"
            DnsProtocol.PLAIN -> upstream
        }
    }.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5000),
        AppPreferences.DEFAULT_UPSTREAM_DNS
    )

    fun selectProvider(provider: DnsProvider) {
        viewModelScope.launch {
            appPrefs.setDnsProviderId(provider.id)
            appPrefs.setUpstreamDns(provider.ipAddress)

            // Set protocol based on provider capabilities
            if (provider.dohUrl != null) {
                appPrefs.setDnsProtocol(DnsProtocol.DOH)
                appPrefs.setDohUrl(provider.dohUrl)
            } else {
                appPrefs.setDnsProtocol(DnsProtocol.PLAIN)
            }

            // Set fallback DNS to a different provider for redundancy
            // Use privacy-friendly Quad9 <-> AdGuard pairing
            val fallbackProvider = when (provider.id) {
                DnsProviders.QUAD9.id -> DnsProviders.ADGUARD
                DnsProviders.ADGUARD.id -> DnsProviders.QUAD9
                else -> {
                    // Find first privacy provider different from selected
                    DnsProviders.ALL_PROVIDERS.firstOrNull {
                        it.id != provider.id && it.category == DnsCategory.PRIVACY
                    } ?: DnsProviders.QUAD9
                }
            }
            appPrefs.setFallbackDns(fallbackProvider.ipAddress)
            AdBlockVpnService.requestRestart(getApplication<Application>().applicationContext)
        }
    }

    fun setFallbackDns(dns: String) {
        viewModelScope.launch {
            appPrefs.setFallbackDns(dns.trim())
            AdBlockVpnService.requestRestart(getApplication<Application>().applicationContext)
        }
    }

    fun setCustomDns(upstream: String) {
        val trimmed = upstream.trim()
        if (trimmed.isBlank()) return // Guard against empty input

        viewModelScope.launch {
            appPrefs.setDnsProviderId(null)
            when {
                trimmed.startsWith("https://", ignoreCase = true) -> {
                    appPrefs.setDnsProtocol(DnsProtocol.DOH)
                    appPrefs.setDohUrl(trimmed)
                    // Extract host from DoH URL for upstream fallback identification
                    val host = try {
                        java.net.URL(trimmed).host
                    } catch (_: Exception) { trimmed }
                    appPrefs.setUpstreamDns(host)
                }
                trimmed.startsWith("quic://", ignoreCase = true) -> {
                    // Convert quic://host/path to https://host/path for DoH3 transport
                    val httpsUrl = trimmed.replaceFirst("quic://", "https://", ignoreCase = true)
                    // Ensure path exists (default to /dns-query if none)
                    val finalUrl = if (java.net.URL(httpsUrl).path.isNullOrBlank())
                        "$httpsUrl/dns-query" else httpsUrl
                    appPrefs.setDnsProtocol(DnsProtocol.DOQ)
                    appPrefs.setDohUrl(finalUrl)
                    val host = try {
                        java.net.URL(finalUrl).host
                    } catch (_: Exception) { trimmed }
                    appPrefs.setUpstreamDns(host)
                }
                trimmed.startsWith("tls://", ignoreCase = true) -> {
                    appPrefs.setDnsProtocol(DnsProtocol.DOT)
                    appPrefs.setUpstreamDns(trimmed.removePrefix("tls://").removePrefix("TLS://"))
                }
                else -> {
                    appPrefs.setDnsProtocol(DnsProtocol.PLAIN)
                    appPrefs.setUpstreamDns(trimmed)
                }
            }
            AdBlockVpnService.requestRestart(getApplication<Application>().applicationContext)
        }
    }
}
