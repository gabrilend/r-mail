package com.rmail.app.sync

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.rmail.app.RmailApplication
import com.rmail.app.data.DeletedEntry
import com.rmail.app.data.InboxEntry
import com.rmail.app.data.MailStore
import com.rmail.app.data.MailboxConfig
import com.rmail.app.data.SyncRequest
import com.rmail.app.data.SyncState
import com.rmail.app.net.RmailClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

sealed class SyncResult {
    data class Success(val mailboxName: String? = null, val mailboxPath: String? = null) : SyncResult()
    data class NewMessages(val count: Int, val mailboxName: String? = null, val mailboxPath: String? = null) : SyncResult()
    data class Error(val message: String) : SyncResult()
}

class SyncManager(
    private val context: Context,
    private val config: MailboxConfig,
    private val store: MailStore,
    private val serverLanIp: String? = null
) {

    suspend fun sync(): SyncResult = withContext(Dispatchers.IO) {
        if (!config.isConfigured) return@withContext SyncResult.Error("Not configured")

        try {
            // Try LAN IP first (fast, same network), fall back to configured host
            val host = if (serverLanIp != null) {
                try {
                    val sock = java.net.Socket()
                    sock.connect(java.net.InetSocketAddress(serverLanIp, config.port), 1_000)
                    sock.close()
                    serverLanIp
                } catch (_: Exception) {
                    config.host
                }
            } else config.host
            val client = RmailClient(host, config.port, config.token)
            val state = store.readSyncState()

            // ── 1. Compute local diff ──────────────────────────────────────

            val deletedInbox = computeDeletedInbox(state)
            val (newOutbox, deletedOutbox) = computeOutboxDiff(state)
            val contactsHash = store.contactsHash()

            // Build phone's current inbox map (only entries whose files still exist)
            val currentInbox = state.inbox.filter { (_, entry) ->
                File(store.inbox, entry.filename).exists()
            }.mapValues { it.value.filename }

            val currentOutbox = store.listOutbox()

            // ── 2. Call /api/sync ──────────────────────────────────────────

            val req = SyncRequest(
                inbox = currentInbox,
                deletedInbox = deletedInbox,
                outbox = currentOutbox,
                deletedOutbox = deletedOutbox,
                contactsHash = contactsHash
            )
            val resp = client.sync(req)

            // ── 3. Apply server response ───────────────────────────────────

            var newCount = 0
            val newState = state.toMutable()

            // Remove inbox entries the server says are gone
            resp.removeInbox.forEach { id ->
                val entry = newState.inbox[id]
                if (entry != null) {
                    store.deleteInbox(entry.filename)
                    newState.inbox.remove(id)
                }
            }

            // Download new inbox files
            resp.fetchInbox.forEach { (id, entry) ->
                val data = client.downloadFile("inbox", entry.filename)
                store.writeInbox(entry.filename, data)
                newState.inbox[id] = entry
                newCount++
            }

            // Download new outbox files (created on desktop)
            resp.fetchOutbox.forEach { filename ->
                val data = client.downloadFile("outbox", filename)
                store.writeOutbox(filename, data.toString(Charsets.UTF_8))
                newState.outbox.add(filename)
            }

            // Upload new outbox files created on the phone
            val newOutboxSet = newOutbox.toSet()
            newOutbox.forEach { filename ->
                val content = store.readOutbox(filename).toByteArray(Charsets.UTF_8)
                client.uploadOutboxFile(filename, content)
                newState.outbox.add(filename)
            }

            // Remove outbox files the server says are done.
            // Skip files we just uploaded — server didn't know about them yet this cycle.
            resp.removeOutbox.forEach { filename ->
                if (filename !in newOutboxSet) {
                    store.deleteOutbox(filename)
                    newState.outbox.remove(filename)
                }
            }

            // Sync contacts — server includes full text when hashes differ, null when same
            if (resp.contacts != null) {
                val currentHash = store.contactsHash()
                val lastHash = state.contactsHash
                val phoneHasChanges = currentHash != null && currentHash != lastHash && lastHash != null
                if (phoneHasChanges) {
                    // User edited contacts on the phone since last sync — push them
                    val localContacts = store.readContacts()
                    if (localContacts.isNotBlank()) {
                        client.postContacts(localContacts)
                        newState.contactsHash = currentHash
                    }
                } else {
                    // No local changes — accept server's version (already in the response)
                    store.writeContacts(resp.contacts)
                    newState.contactsHash = store.contactsHash()
                }
            }

            // ── 4. Persist updated state ───────────────────────────────────

            store.writeSyncState(newState.toImmutable())

            // ── 5. Notify if new messages arrived ─────────────────────────

            if (newCount > 0) {
                val first = resp.fetchInbox.values.firstOrNull()
                postNotification(newCount, first?.from, first?.filename)
                return@withContext SyncResult.NewMessages(newCount, resp.mailboxName, resp.mailboxPath)
            }

            SyncResult.Success(resp.mailboxName, resp.mailboxPath)

        } catch (e: Exception) {
            SyncResult.Error(e.message ?: "Unknown sync error")
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun computeDeletedInbox(state: SyncState): List<DeletedEntry> =
        state.inbox.entries
            .filter { (_, entry) -> !File(store.inbox, entry.filename).exists() }
            .map { (id, entry) -> DeletedEntry(id, entry.from) }

    private fun computeOutboxDiff(state: SyncState): Pair<List<String>, List<String>> {
        val onDisk = store.listOutbox().toSet()
        val inState = state.outbox
        val newFiles = onDisk - inState       // created on phone since last sync
        val deleted = inState - onDisk        // deleted on phone since last sync
        return Pair(newFiles.toList(), deleted.toList())
    }

    private fun postNotification(count: Int, sender: String?, subject: String?) {
        val detail = config.notificationDetail
        if (detail == "off") return

        val title = if (count == 1) "New message" else "$count new messages"
        val text = when (detail) {
            "full" -> if (sender != null && subject != null) "$sender — $subject"
                      else sender ?: subject
            "sender" -> sender
            else -> null   // "none" — notification with no preview text
        }

        // Use the launcher intent to avoid a circular package dependency
        val intent = context.packageManager.getLaunchIntentForPackage(context.packageName)
            ?: Intent().apply { flags = Intent.FLAG_ACTIVITY_NEW_TASK }
        val pi = PendingIntent.getActivity(context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        val notification = NotificationCompat.Builder(context, RmailApplication.CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentTitle(title)
            .apply { if (text != null) setContentText(text) }
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()

        val nm = context.getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, notification)
    }

    companion object {
        private const val NOTIFICATION_ID = 1001
    }
}

// ── Mutable sync state helper ──────────────────────────────────────────────

private class MutableSyncState(
    val inbox: MutableMap<String, InboxEntry>,
    val outbox: MutableSet<String>,
    var contactsHash: String?
) {
    fun toImmutable() = SyncState(inbox.toMap(), outbox.toSet(), contactsHash)
}

private fun SyncState.toMutable() = MutableSyncState(
    inbox = inbox.toMutableMap(),
    outbox = outbox.toMutableSet(),
    contactsHash = contactsHash
)
