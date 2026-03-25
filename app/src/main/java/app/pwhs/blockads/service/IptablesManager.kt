package app.pwhs.blockads.service

import android.content.Context
import com.topjohnwu.superuser.Shell
import timber.log.Timber

/**
 * Manages iptables rules for Root/Proxy mode.
 * Redirects all outbound DNS traffic (port 53 UDP/TCP) to the local
 * Go engine at 127.0.0.1:15353, excluding this app's own UID to prevent
 * infinite redirect loops.
 *
 * Uses a custom chain (BLOCKADS_DNS) for clean setup/teardown.
 *
 * Architecture:
 * - nat table:    REDIRECT port 53 → 15353 (DNS interception)
 * - filter table: DROP port 853 (block DoT to force plain DNS)
 * - settings:     Disable Android Private DNS (forces port 53 fallback)
 */
object IptablesManager {

    private const val CHAIN = "BLOCKADS_DNS"
    private const val CHAIN_FILTER = "BLOCKADS_DOT"
    private const val LOCAL_DNS_PORT = 15353

    /**
     * Actively request root access. This will trigger the Magisk/KernelSU
     * permission prompt if it hasn't been granted yet.
     */
    fun isRootAvailable(): Boolean {
        return Shell.cmd("true").exec().isSuccess
    }

    /**
     * Apply iptables rules to redirect DNS traffic.
     *
     * @param context App context (used to get UID)
     * @param blockDoT If true, blocks DoT (port 853) to force DNS fallback to port 53
     * @return true if at least IPv4 rules succeeded
     */
    fun setupRules(context: Context, blockDoT: Boolean = true): Boolean {
        val uid = context.applicationInfo.uid
        Timber.d("Setting up iptables rules for UID=$uid, blockDoT=$blockDoT")

        // Always teardown first (idempotent)
        teardownRules()

        // ══════════════════════════════════════════════════════════════
        // Step 0: Disable Android Private DNS so system uses port 53
        // This is CRITICAL — without this, Android 9+ uses DoT (853)
        // and our port 53 redirect never sees traffic.
        // ══════════════════════════════════════════════════════════════
        Shell.cmd("settings put global private_dns_mode off").exec()
        Timber.d("Disabled Android Private DNS (forced plain DNS mode)")

        // ══════════════════════════════════════════════════════════════
        // Step 1: nat table — REDIRECT port 53 → local engine
        // ══════════════════════════════════════════════════════════════
        val ipv4Nat = buildList {
            add("iptables -t nat -N $CHAIN")
            // Skip our own app's traffic (prevents infinite loop)
            add("iptables -t nat -A $CHAIN -m owner --uid-owner $uid -j RETURN")
            // Redirect UDP DNS → local engine
            add("iptables -t nat -A $CHAIN -p udp --dport 53 -j REDIRECT --to-ports $LOCAL_DNS_PORT")
            // Redirect TCP DNS → local engine
            add("iptables -t nat -A $CHAIN -p tcp --dport 53 -j REDIRECT --to-ports $LOCAL_DNS_PORT")
            // Hook into OUTPUT chain
            add("iptables -t nat -A OUTPUT -j $CHAIN")
        }

        // ══════════════════════════════════════════════════════════════
        // Step 2: filter table — DROP port 853 (DoT)
        // NOTE: DROP is NOT valid in nat table! Must use filter table.
        // ══════════════════════════════════════════════════════════════
        val ipv4Filter = if (blockDoT) {
            buildList {
                add("iptables -t filter -N $CHAIN_FILTER")
                add("iptables -t filter -A $CHAIN_FILTER -m owner --uid-owner $uid -j RETURN")
                add("iptables -t filter -A $CHAIN_FILTER -p tcp --dport 853 -j REJECT")
                add("iptables -t filter -A OUTPUT -j $CHAIN_FILTER")
            }
        } else emptyList()

        // Execute IPv4 rules
        val allIpv4 = ipv4Nat + ipv4Filter
        val result4 = Shell.cmd(*allIpv4.toTypedArray()).exec()
        val success4 = result4.isSuccess

        if (success4) {
            Timber.d("IPv4 iptables setup SUCCESS")
        } else {
            Timber.e("IPv4 iptables setup FAILED: err=${result4.err}, out=${result4.out}")
        }

        // ══════════════════════════════════════════════════════════════
        // IPv6 — try independently, many Android kernels lack ip6tables nat
        // ══════════════════════════════════════════════════════════════
        val ipv6Nat = buildList {
            add("ip6tables -t nat -N $CHAIN")
            add("ip6tables -t nat -A $CHAIN -m owner --uid-owner $uid -j RETURN")
            add("ip6tables -t nat -A $CHAIN -p udp --dport 53 -j REDIRECT --to-ports $LOCAL_DNS_PORT")
            add("ip6tables -t nat -A $CHAIN -p tcp --dport 53 -j REDIRECT --to-ports $LOCAL_DNS_PORT")
            add("ip6tables -t nat -A OUTPUT -j $CHAIN")
        }

        val ipv6Filter = if (blockDoT) {
            buildList {
                add("ip6tables -t filter -N $CHAIN_FILTER")
                add("ip6tables -t filter -A $CHAIN_FILTER -m owner --uid-owner $uid -j RETURN")
                add("ip6tables -t filter -A $CHAIN_FILTER -p tcp --dport 853 -j REJECT")
                add("ip6tables -t filter -A OUTPUT -j $CHAIN_FILTER")
            }
        } else emptyList()

        val allIpv6 = ipv6Nat + ipv6Filter
        val result6 = Shell.cmd(*allIpv6.toTypedArray()).exec()
        if (result6.isSuccess) {
            Timber.d("IPv6 ip6tables setup SUCCESS")
        } else {
            Timber.w("IPv6 ip6tables setup FAILED (ignoring): err=${result6.err}, out=${result6.out}")
        }

        return success4
    }

    /**
     * Remove all BlockAds iptables rules and restore Private DNS.
     * Safe to call multiple times. Uses 2>/dev/null to suppress errors.
     */
    fun teardownRules(): Boolean {
        val commands = listOf(
            // IPv4 nat chain
            "iptables -t nat -D OUTPUT -j $CHAIN 2>/dev/null",
            "iptables -t nat -F $CHAIN 2>/dev/null",
            "iptables -t nat -X $CHAIN 2>/dev/null",
            // IPv4 filter chain (DoT blocking)
            "iptables -t filter -D OUTPUT -j $CHAIN_FILTER 2>/dev/null",
            "iptables -t filter -F $CHAIN_FILTER 2>/dev/null",
            "iptables -t filter -X $CHAIN_FILTER 2>/dev/null",
            // IPv6 nat chain
            "ip6tables -t nat -D OUTPUT -j $CHAIN 2>/dev/null",
            "ip6tables -t nat -F $CHAIN 2>/dev/null",
            "ip6tables -t nat -X $CHAIN 2>/dev/null",
            // IPv6 filter chain (DoT blocking)
            "ip6tables -t filter -D OUTPUT -j $CHAIN_FILTER 2>/dev/null",
            "ip6tables -t filter -F $CHAIN_FILTER 2>/dev/null",
            "ip6tables -t filter -X $CHAIN_FILTER 2>/dev/null",
            // Restore Android Private DNS to automatic mode
            "settings put global private_dns_mode opportunistic",
        )

        Shell.cmd(*commands.toTypedArray()).exec()
        Timber.d("iptables teardown done, Private DNS restored")
        return true
    }

    /**
     * Check if our iptables rules are currently active.
     */
    fun isActive(): Boolean {
        val result = Shell.cmd(
            "iptables -t nat -L OUTPUT -n 2>/dev/null | grep $CHAIN"
        ).exec()
        return result.out.any { it.contains(CHAIN) }
    }
}
