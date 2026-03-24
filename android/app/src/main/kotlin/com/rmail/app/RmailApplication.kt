package com.rmail.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager

class RmailApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "New messages",
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = "Notifications for new r-mail messages"
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    companion object {
        const val CHANNEL_ID = "rmail_messages"
    }
}
