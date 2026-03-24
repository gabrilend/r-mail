package com.rmail.app.sync

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.rmail.app.data.MailStore
import com.rmail.app.data.Settings
import java.util.concurrent.TimeUnit

class SyncWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val settings = Settings(applicationContext)
        if (!settings.isConfigured) return Result.success()

        val store = MailStore(applicationContext)
        val manager = SyncManager(applicationContext, settings, store)

        return when (val result = manager.sync()) {
            is SyncResult.Success, is SyncResult.NewMessages -> Result.success()
            is SyncResult.Error -> {
                // Retry transient errors; give up on permanent ones
                if (result.message.contains("Decryption failed")) Result.failure()
                else Result.retry()
            }
        }
    }

    companion object {
        private const val WORK_NAME = "rmail_background_sync"

        fun schedule(context: Context, intervalMinutes: Int) {
            val interval = intervalMinutes.toLong().coerceAtLeast(15L)
            val request = PeriodicWorkRequestBuilder<SyncWorker>(interval, TimeUnit.MINUTES)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request
            )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        }
    }
}
