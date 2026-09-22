package com.rmail.app.net

import com.rmail.app.data.MailboxConfig
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket

/**
 * Chooses which of a mailbox's addresses to connect to (#388).
 *
 * Local addresses come first, but only those on the phone's own /24 — the
 * same rule the daemon uses.  Private ranges are reused on every network, so
 * probing 192.168.1.10 from a café's wifi would knock on some stranger's
 * device.  Public addresses follow in list order.
 *
 * Blocking: call from Dispatchers.IO.
 */
object HostPicker {
    private const val LOCAL_TIMEOUT_MS = 1_000
    private const val PUBLIC_TIMEOUT_MS = 3_000

    // The address that answered at the start of the last sync cycle, per
    // mailbox.  Each sync re-probes (the phone may have changed networks
    // since); everything between syncs reuses the answer.
    private val lastGood = mutableMapOf<String, String>()

    /**
     * [learnedLan] is the LAN address the daemon reported via /api/myaddress.
     * [fresh] re-probes and replaces the remembered answer; the sync cycle
     * passes true, other calls use what the last sync found.
     */
    @Synchronized
    fun pick(config: MailboxConfig, learnedLan: String? = null, fresh: Boolean = false): String {
        val candidates = candidates(config, learnedLan)
        if (candidates.isEmpty()) return config.host

        if (!fresh) {
            lastGood[config.id]?.let { host ->
                if (candidates.any { it.first == host }) return host
            }
        }
        for ((host, timeout) in candidates) {
            if (reachable(host, config.port, timeout)) {
                lastGood[config.id] = host
                return host
            }
        }
        lastGood.remove(config.id)
        // Nothing answered.  Hand back the primary so the caller's own
        // connect attempt produces the error the user sees.
        return config.hosts.firstOrNull() ?: candidates.first().first
    }

    /** Forget the remembered winner, e.g. after a connection failure. */
    @Synchronized
    fun forget(config: MailboxConfig) { lastGood.remove(config.id) }

    private fun candidates(config: MailboxConfig, learnedLan: String?): List<Pair<String, Int>> {
        val mine = ownIpv4s()
        val local = (config.localHosts + listOfNotNull(learnedLan?.takeIf { it.isNotBlank() }))
            .distinct()
            .filter { addr -> mine.any { sameLan(it, addr) } }
            .map { it to LOCAL_TIMEOUT_MS }
        val public = config.hosts.filter { h -> local.none { it.first == h } }
            .map { it to PUBLIC_TIMEOUT_MS }
        return local + public
    }

    private fun reachable(host: String, port: Int, timeoutMs: Int): Boolean = try {
        Socket().use { it.connect(InetSocketAddress(host, port), timeoutMs) }
        true
    } catch (_: Exception) { false }

    private fun ownIpv4s(): List<String> = try {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.toList() }
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
    } catch (_: Exception) { emptyList() }

    private fun sameLan(a: String, b: String): Boolean {
        val pa = a.substringBeforeLast('.', "")
        return pa.isNotEmpty() && pa.count { it == '.' } == 2 && pa == b.substringBeforeLast('.', "")
    }
}
