package com.rmail.app.sync

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.rmail.app.data.MailStore
import com.rmail.app.data.MailboxRegistry
import java.util.concurrent.TimeUnit

class SyncWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val registry = MailboxRegistry(applicationContext)
        val configs = registry.loadAll()
        if (configs.isEmpty()) return Result.success()

        var anyRetry = false
        for (config in configs) {
            if (!config.isConfigured) continue
            val store = MailStore(applicationContext, config.id)
            val manager = SyncManager(applicationContext, config, store)
            when (val result = manager.sync()) {
                is SyncResult.Error -> {
                    if (!result.message.contains("Decryption failed")) anyRetry = true
                }
                else -> {}
            }
        }
        return if (anyRetry) Result.retry() else Result.success()
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
