package com.rmail.app.data

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

class Settings(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("rmail_settings", Context.MODE_PRIVATE)

    var serverHost: String
        get() = prefs.getString("server_host", "") ?: ""
        set(v) = prefs.edit { putString("server_host", v) }

    var serverPort: Int
        get() = prefs.getInt("server_port", 8787)
        set(v) = prefs.edit { putInt("server_port", v) }

    var deviceToken: String
        get() = prefs.getString("device_token", "") ?: ""
        set(v) = prefs.edit { putString("device_token", v) }

    // Theme — stored as ARGB int
    var bgColor: Int
        get() = prefs.getInt("bg_color", 0xFF000000.toInt())
        set(v) = prefs.edit { putInt("bg_color", v) }

    var fgColor: Int
        get() = prefs.getInt("fg_color", 0xFFDAA520.toInt())
        set(v) = prefs.edit { putInt("fg_color", v) }

    var swipeToDelete: Boolean
        get() = prefs.getBoolean("swipe_to_delete", true)
        set(v) = prefs.edit { putBoolean("swipe_to_delete", v) }

    // Background sync interval in minutes (WorkManager minimum is 15)
    var bgSyncIntervalMinutes: Int
        get() = prefs.getInt("bg_sync_interval", 15)
        set(v) = prefs.edit { putInt("bg_sync_interval", v.coerceAtLeast(15)) }

    // "full" = sender + subject, "sender" = sender only, "none" = no preview
    var notificationDetail: String
        get() = prefs.getString("notification_detail", "full") ?: "full"
        set(v) = prefs.edit { putString("notification_detail", v) }

    val isConfigured: Boolean
        get() = serverHost.isNotBlank() && deviceToken.isNotBlank()
}
