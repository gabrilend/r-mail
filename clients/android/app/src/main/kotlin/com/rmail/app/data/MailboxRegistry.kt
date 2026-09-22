package com.rmail.app.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

data class MailboxConfig(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "",
    /** Public addresses or hostnames, tried in order after any local one. */
    val hosts: List<String> = emptyList(),
    /**
     * Private (LAN) addresses of the server.  Only reachable from inside its
     * network, so each is probed briefly before the public list.
     */
    val localHosts: List<String> = emptyList(),
    val port: Int = 8025,
    val token: String = "",
    val bgSyncIntervalMinutes: Int = 15,
    val notificationDetail: String = "full",
    val mailboxPath: String = ""  // server-side mailbox directory, learned from sync
) {
    /** Primary address, for display: the first public one, else the first local one. */
    val host: String get() = hosts.firstOrNull() ?: localHosts.firstOrNull() ?: ""

    /** Private addresses go to [localHosts], everything else to [hosts]. */
    fun withAddressesSorted(): MailboxConfig {
        val (priv, pub) = hosts.partition { isPrivateIpv4(it) }
        return if (priv.isEmpty()) this
        else copy(hosts = pub, localHosts = (localHosts + priv).distinct())
    }

    val isConfigured: Boolean get() =
        (hosts.isNotEmpty() || localHosts.isNotEmpty()) && token.isNotBlank()
}

class MailboxRegistry(private val context: Context) {

    private val file = File(context.filesDir, "mailboxes.json")

    fun loadAll(): List<MailboxConfig> {
        if (!file.exists()) return emptyList()
        return try {
            val arr = JSONArray(file.readText())
            (0 until arr.length()).map { i -> parseConfig(arr.getJSONObject(i)) }
        } catch (_: Exception) { emptyList() }
    }

    fun get(id: String): MailboxConfig? = loadAll().find { it.id == id }

    fun add(config: MailboxConfig) {
        val list = loadAll().toMutableList()
        list.add(config)
        save(list)
    }

    fun update(config: MailboxConfig) {
        val list = loadAll().toMutableList()
        val idx = list.indexOfFirst { it.id == config.id }
        if (idx >= 0) {
            list[idx] = config
            save(list)
        }
    }

    fun remove(id: String) {
        val list = loadAll().toMutableList()
        list.removeAll { it.id == id }
        save(list)
        // Clean up the mailbox directory
        val dir = File(context.filesDir, "mailbox-$id")
        if (dir.exists()) dir.deleteRecursively()
    }

    fun save(configs: List<MailboxConfig>) {
        val arr = JSONArray()
        configs.forEach { arr.put(toJson(it)) }
        file.writeText(arr.toString(2))
    }

    /**
     * One-time migration from the old single-mailbox Settings/mailbox-0 layout.
     * Returns the migrated config's ID, or null if no migration was needed.
     */
    fun migrateFromLegacy(): String? {
        if (file.exists()) return null  // already migrated
        val oldDir = File(context.filesDir, "mailbox-0")
        if (!oldDir.exists()) return null  // nothing to migrate

        val prefs = context.getSharedPreferences("rmail_settings", Context.MODE_PRIVATE)
        val host = prefs.getString("server_host", "") ?: ""
        val port = prefs.getInt("server_port", 8025)
        val token = prefs.getString("device_token", "") ?: ""

        if (host.isBlank()) return null  // never configured

        val config = MailboxConfig(
            id = UUID.randomUUID().toString(),
            name = "",  // will be populated from daemon on first sync
            hosts = listOf(host),
            port = port,
            token = token,
            bgSyncIntervalMinutes = prefs.getInt("bg_sync_interval", 15),
            notificationDetail = prefs.getString("notification_detail", "full") ?: "full"
        )

        // Rename directory
        val newDir = File(context.filesDir, "mailbox-${config.id}")
        oldDir.renameTo(newDir)

        // Write registry
        save(listOf(config))

        // Clean up old prefs (keep colors — they're global)
        prefs.edit()
            .remove("server_host").remove("server_port").remove("device_token")
            .remove("swipe_to_delete").remove("bg_sync_interval").remove("notification_detail")
            .apply()

        return config.id
    }

    private fun parseConfig(obj: JSONObject) = MailboxConfig(
        id = obj.getString("id"),
        name = obj.optString("name", ""),
        hosts = obj.optJSONArray("hosts")?.let { a -> (0 until a.length()).map { a.getString(it) } }
            ?: listOfNotNull(obj.optString("host", "").ifBlank { null }),
        localHosts = obj.optJSONArray("local_hosts")?.let { a -> (0 until a.length()).map { a.getString(it) } }
            ?: emptyList(),
        port = obj.optInt("port", 8025),
        token = obj.optString("token", ""),
        bgSyncIntervalMinutes = obj.optInt("bg_sync_interval", 15),
        notificationDetail = obj.optString("notification_detail", "full"),
        mailboxPath = obj.optString("mailbox_path", "")
    ).withAddressesSorted()  // a pre-list config may hold a LAN address as its host

    private fun toJson(c: MailboxConfig) = JSONObject().apply {
        put("id", c.id)
        put("name", c.name)
        put("host", c.host)  // read by builds that predate the lists
        put("hosts", JSONArray(c.hosts))
        put("local_hosts", JSONArray(c.localHosts))
        put("port", c.port)
        put("token", c.token)
        put("bg_sync_interval", c.bgSyncIntervalMinutes)
        put("notification_detail", c.notificationDetail)
        put("mailbox_path", c.mailboxPath)
    }
}

/** Same ranges as the daemon's is_private_ipv4 (#388). */
fun isPrivateIpv4(addr: String): Boolean {
    val parts = addr.split(".")
    if (parts.size != 4) return false
    val o = parts.map { it.toIntOrNull() ?: return false }
    if (o.any { it !in 0..255 }) return false
    val (a, b) = o
    return a == 10 || a == 127 ||
        (a == 192 && b == 168) ||
        (a == 172 && b in 16..31) ||
        (a == 169 && b == 254) ||
        (a == 100 && b in 64..127)
}
