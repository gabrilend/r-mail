package com.rmail.app.data

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

/**
 * Global settings only (theme). Per-mailbox settings live in MailboxConfig.
 */
class Settings(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("rmail_settings", Context.MODE_PRIVATE)

    // Theme — stored as ARGB int
    var bgColor: Int
        get() = prefs.getInt("bg_color", 0xFF000000.toInt())
        set(v) = prefs.edit { putInt("bg_color", v) }

    var fgColor: Int
        get() = prefs.getInt("fg_color", 0xFFFFD040.toInt())
        set(v) = prefs.edit { putInt("fg_color", v) }

    // Accent/secondary color for changed text, highlights, etc.
    var accentColor: Int
        get() = prefs.getInt("accent_color", 0xFF00E5FF.toInt())  // cyan
        set(v) = prefs.edit { putInt("accent_color", v) }
}
