package com.rmail.app.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

data class MailboxConfig(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "",
    val host: String = "",
    val port: Int = 8025,
    val token: String = "",
    val swipeToDelete: Boolean = true,
    val bgSyncIntervalMinutes: Int = 15,
    val notificationDetail: String = "full"
) {
    val isConfigured: Boolean get() = host.isNotBlank() && token.isNotBlank()
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
            host = host,
            port = port,
            token = token,
            swipeToDelete = prefs.getBoolean("swipe_to_delete", true),
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
        host = obj.optString("host", ""),
        port = obj.optInt("port", 8025),
        token = obj.optString("token", ""),
        swipeToDelete = obj.optBoolean("swipe_to_delete", true),
        bgSyncIntervalMinutes = obj.optInt("bg_sync_interval", 15),
        notificationDetail = obj.optString("notification_detail", "full")
    )

    private fun toJson(c: MailboxConfig) = JSONObject().apply {
        put("id", c.id)
        put("name", c.name)
        put("host", c.host)
        put("port", c.port)
        put("token", c.token)
        put("swipe_to_delete", c.swipeToDelete)
        put("bg_sync_interval", c.bgSyncIntervalMinutes)
        put("notification_detail", c.notificationDetail)
    }
}
