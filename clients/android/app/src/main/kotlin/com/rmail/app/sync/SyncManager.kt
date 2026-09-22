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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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

    // One sync at a time per process.  The app and the background worker
    // can both start one, and two cycles uploading the same attachment or
    // rewriting the same outbox file would trample each other.
    suspend fun sync(): SyncResult = syncLock.withLock { syncLocked() }

    private suspend fun syncLocked(): SyncResult = withContext(Dispatchers.IO) {
        if (!config.isConfigured) return@withContext SyncResult.Error("Not configured")

        try {
            // Local addresses on our own network first, then public ones (#388)
            val host = com.rmail.app.net.HostPicker.pick(config, serverLanIp, fresh = true)
            val client = RmailClient(host, config.port, config.token)
            // ── 0. Upload attachments still on the phone ──────────────────
            //
            // Done first, so a message whose attachments finish uploading
            // goes to the server in this same cycle.
            uploadPendingAttachments(client)

            // Hashes backfilled first, so the state every later write is
            // derived from already carries them.
            backfillOutboxHashes()
            val state = store.readSyncState()

            // ── 1. Compute local diff ──────────────────────────────────────

            val deletedInbox = computeDeletedInbox(state)
            val (newOutbox, deletedOutbox) = computeOutboxDiff(state)
            val changedOutbox = computeChangedOutbox(state)
            val contactsHash = store.contactsHash()

            // Build phone's current inbox map (only entries whose files still exist)
            val currentInbox = state.inbox.filter { (_, entry) ->
                File(store.inbox, entry.filename).exists()
            }.mapValues { it.value.filename }

            // A held file the server has never seen is left out: listing it
            // would read as "the phone has a file the server does not",
            // which is the server's cue to tell us to delete it.
            val currentOutbox = store.listOutbox()
                .filter { it in state.outbox || !store.isHeld(it) }

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

            // #386: every transfer below is durable the instant the server
            // acknowledges it, so the state recording it is committed right
            // then rather than batched into one write at the end of the
            // function. The old all-or-nothing commit meant any later failure
            // -- a contacts push, a download, a read timeout -- discarded the
            // record of work that had definitively succeeded, and the next
            // sync re-sent all of it. That produced 65 uploads for 44 files
            // in a single observed drain.
            //
            // The rule: state describing "what the server already has" is
            // written when the server says so, not when the cycle happens to
            // reach its end.

            // Download new inbox files (preserve the server's authoring mtime)
            resp.fetchInbox.forEach { (id, entry) ->
                val (data, mtimeMs) = client.downloadFileWithMtime("inbox", entry.filename)
                store.writeInbox(entry.filename, data, mtimeMs)
                newState.inbox[id] = entry
                newCount++
                store.writeSyncState(newState.toImmutable())
            }

            // Download new outbox files (created on desktop)
            resp.fetchOutbox.forEach { filename ->
                val (data, mtimeMs) = client.downloadFileWithMtime("outbox", filename)
                store.writeOutbox(filename, data.toString(Charsets.UTF_8), mtimeMs)
                newState.outbox.add(filename)
                store.outboxHash(filename)?.let { newState.outboxHashes[filename] = it }
                store.writeSyncState(newState.toImmutable())
            }

            // Upload new outbox files created on the phone (send the local
            // authoring time so the server and recipients preserve ordering)
            // -- and outbox files edited on the phone since they were last
            // sent, which the server passes on to recipients as an update.
            val newOutboxSet = newOutbox.toSet()
            (newOutbox + changedOutbox).forEach { filename ->
                val bytes = File(store.outbox, filename).readBytes()
                val mtimeSecs = File(store.outbox, filename).lastModified().let { if (it > 0) it / 1000 else null }
                client.uploadOutboxFile(filename, bytes, mtimeSecs)
                newState.outbox.add(filename)
                newState.outboxHashes[filename] = com.rmail.app.crypto.Crypto.sha256Hex(bytes)
                // The upload is on the server now. If the next one throws,
                // this one must not be sent again.
                store.writeSyncState(newState.toImmutable())
            }

            // Remove outbox files the server says are done.
            // Skip files we just uploaded — server didn't know about them yet this cycle.
            resp.removeOutbox.forEach { filename ->
                if (filename !in newOutboxSet && !store.isHeld(filename)) {
                    store.deleteOutbox(filename)
                    newState.outbox.remove(filename)
                    newState.outboxHashes.remove(filename)
                    store.writeSyncState(newState.toImmutable())
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
                        store.writeSyncState(newState.toImmutable())
                    }
                } else {
                    // No local changes — accept server's version (already in the response)
                    store.writeContacts(resp.contacts)
                    newState.contactsHash = store.contactsHash()
                }
            }

            // ── 4. Persist updated state ───────────────────────────────────

            // Final commit. Each step above already committed its own result
            // (#386), so this catches only the bookkeeping that has no
            // transfer of its own -- the removeInbox deletions and the
            // accepted-from-server contacts hash.
            store.writeSyncState(newState.toImmutable())

            // ── 5. Notify if new messages arrived ─────────────────────────

            if (newCount > 0) {
                val first = resp.fetchInbox.values.firstOrNull()
                postNotification(newCount, first?.from, first?.filename)
                return@withContext SyncResult.NewMessages(newCount, resp.mailboxName, resp.mailboxPath)
            }

            SyncResult.Success(resp.mailboxName, resp.mailboxPath)

        } catch (e: Exception) {
            // The remembered address may be the one that just failed; don't
            // hand it to other calls until the next sync re-probes.
            com.rmail.app.net.HostPicker.forget(config)
            SyncResult.Error(friendlySyncError(e))
        }
    }

    /**
     * Translate raw Java/network exceptions into messages a user can read
     * without needing context about sockets.  Transient timeouts are the
     * most common case (#320) — the server is alive but slow — so the
     * message explicitly calls out "will retry" so the user isn't alarmed
     * when the red box appears and then disappears on the next cycle.
     */
    private fun friendlySyncError(e: Exception): String {
        val raw = e.message ?: ""
        return when {
            e is java.net.SocketTimeoutException ||
                raw.contains("timed out", ignoreCase = true) ->
                "server didn't respond in time — will retry"
            e is java.net.ConnectException ||
                raw.contains("refused", ignoreCase = true) ->
                "server not reachable — will retry"
            e is java.net.UnknownHostException ->
                "server host couldn't be resolved"
            raw.contains("Decryption failed", ignoreCase = true) ->
                "wrong token or tampered response (check your contact token)"
            raw.isNotBlank() -> raw
            else -> "unknown sync error (${e::class.java.simpleName})"
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
        // created on phone since last sync, and not waiting on an upload
        val newFiles = (onDisk - inState).filterNot { store.isHeld(it) }
        val deleted = inState - onDisk        // deleted on phone since last sync
        return Pair(newFiles, deleted.toList())
    }

    /**
     * Outbox files the server already has that were edited here since.
     * The upload used to happen once, on first sight, so a later edit --
     * including the attachment line being rewritten to its server path --
     * never reached the server.  A file with no recorded hash (synced before
     * hashes were kept) is assumed unchanged; its hash is recorded now.
     */
    private fun computeChangedOutbox(state: SyncState): List<String> =
        state.outbox.filter { filename ->
            if (store.isHeld(filename)) return@filter false
            val then = state.outboxHashes[filename] ?: return@filter false
            val now = store.outboxHash(filename) ?: return@filter false
            then != now
        }

    private fun backfillOutboxHashes() {
        val state = store.readSyncState()
        val backfill = state.outbox
            .filter { it !in state.outboxHashes && !store.isHeld(it) }
            .mapNotNull { f -> store.outboxHash(f)?.let { f to it } }
            .toMap()
        if (backfill.isNotEmpty()) {
            store.writeSyncState(state.copy(outboxHashes = state.outboxHashes + backfill))
        }
    }

    /**
     * Upload everything the phone has that the server should: attachments
     * an outbox file still points at on the phone, then files added to the
     * Files tab.  Each `attach:` line is rewritten to the server path as its
     * upload completes.  A failure shows under the message (and in Files)
     * and is retried next sync; it no longer disappears into an empty catch.
     */
    private suspend fun uploadPendingAttachments(client: RmailClient) {
        // Legacy staging area (before files went into Files): copies whose
        // message was deleted before they uploaded.  The age check keeps
        // this away from a copy being made right now.
        val referenced = store.listOutbox().flatMap { store.localAttachRefs(it) }.joinToString("\n")
        store.pendingAttachments.listFiles()?.forEach { dir ->
            if (dir.path !in referenced &&
                System.currentTimeMillis() - dir.lastModified() > 60 * 60 * 1000L) {
                dir.deleteRecursively()
            }
        }

        outbox@ for (outboxFile in store.listOutbox()) {
            val refs = store.localAttachRefs(outboxFile)
            if (refs.isEmpty()) { UploadProgress.clear(outboxFile); continue }
            for (ref in refs) {
                val uri = android.net.Uri.parse(ref)
                val name = if (ref.startsWith("file://")) File(uri.path ?: ref).name
                           else displayName(uri) ?: uri.lastPathSegment ?: "attachment"
                try {
                    val serverPath = uploadOne(client, uri, name, outboxFile)
                    // Swap the reference for the server path, in every outbox
                    // file that names it.
                    for (f in store.listOutbox()) {
                        val text = store.readOutbox(f)
                        if (ref in text) store.writeOutbox(f, text.replace(ref, serverPath))
                    }
                // An attachment that can't be read holds its own message
                // only.  These used to return, which stopped every upload
                // after it -- one old message with a dead attachment kept
                // anything added to Files "waiting to upload" forever.
                } catch (e: SecurityException) {
                    UploadProgress.set(outboxFile,
                        "can't read $name any more — remove it and attach it again", error = true)
                    continue@outbox
                } catch (e: java.io.FileNotFoundException) {
                    UploadProgress.set(outboxFile,
                        "$name is gone from this phone — remove it and attach it again", error = true)
                    continue@outbox
                } catch (e: Exception) {
                    uploadFailed(client, outboxFile, name, e)
                    return  // the connection is probably down; stop for this cycle
                }
            }
            if (store.localAttachRefs(outboxFile).isEmpty()) UploadProgress.clear(outboxFile)
        }

        // Files added in the Files tab that no message is waiting on.
        for (name in store.pendingUploads()) {
            val file = File(store.attachments, name)
            if (!file.exists()) { store.setPendingUpload(name, false); continue }  // deleted here
            try {
                uploadOne(client, android.net.Uri.fromFile(file), name, null)
            } catch (e: Exception) {
                uploadFailed(client, null, name, e)
                return
            }
        }
    }

    /**
     * Upload one file and return its server path.  Progress shows under
     * [outboxFile] if given and against the file in the Files tab.  A file
     * that lives in Files stays there, renamed to whatever the server filed
     * it as (it may add -2, or match an identical file already there).
     */
    private suspend fun uploadOne(
        client: RmailClient, uri: android.net.Uri, name: String, outboxFile: String?
    ): String {
        val fileKey = "file:$name"
        val size = openSize(uri)
        val chunksDir = File(context.cacheDir, "upload-chunks/$name-${uri.toString().hashCode()}")
        val serverPath = context.contentResolver.openInputStream(uri).use { stream ->
            RmailClient.uploadFileCompressed(
                client, name, stream, size, context.cacheDir, chunksDir
            ) { phase, done, total ->
                val verb = if (phase == RmailClient.Companion.UploadPhase.ZIPPING)
                    "zipping" else "uploading"
                val line = "$verb $name… ${mb(done)} / ${mb(total)} MB"
                if (outboxFile != null) UploadProgress.set(outboxFile, line)
                UploadProgress.set(fileKey, "$verb… ${mb(done)} / ${mb(total)} MB")
            }
        } ?: throw java.io.IOException("server did not accept the upload")
        UploadProgress.clear(fileKey)

        if (uri.scheme == "file") {
            val local = File(uri.path ?: "")
            if (local.parentFile == store.attachments) {
                store.setPendingUpload(local.name, false)
                val serverName = File(serverPath).name
                if (serverName != local.name) {
                    val target = File(store.attachments, serverName)
                    // An existing file of that name is the server's identical copy.
                    if (target.exists()) local.delete() else local.renameTo(target)
                }
            } else if (local.path.startsWith(store.pendingAttachments.path)) {
                local.delete()
                local.parentFile?.takeIf { it != store.pendingAttachments }?.delete()
            }
        }
        return serverPath
    }

    private fun uploadFailed(client: RmailClient, outboxFile: String?, name: String, e: Exception) {
        val why = e.message ?: e.javaClass.simpleName
        if (outboxFile != null) {
            UploadProgress.set(outboxFile, "upload of $name failed ($why) — will retry", error = true)
        }
        UploadProgress.set("file:$name", "upload failed ($why) — will retry", error = true)
        try { client.remoteLog("warn", "upload failed for ${outboxFile ?: "Files"}/$name: $why") }
        catch (_: Exception) {}
    }

    private fun mb(bytes: Long) = "%.1f".format(bytes / (1024.0 * 1024.0))

    private fun openSize(uri: android.net.Uri): Long =
        if (uri.scheme == "file") File(uri.path ?: "").length()
        else context.contentResolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: 0L

    private fun displayName(uri: android.net.Uri): String? = try {
        context.contentResolver.query(
            uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null
        )?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
    } catch (_: Exception) { null }

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
        private val syncLock = Mutex()
    }
}

// ── Mutable sync state helper ──────────────────────────────────────────────

private class MutableSyncState(
    val inbox: MutableMap<String, InboxEntry>,
    val outbox: MutableSet<String>,
    var contactsHash: String?,
    val outboxHashes: MutableMap<String, String>
) {
    fun toImmutable() = SyncState(inbox.toMap(), outbox.toSet(), contactsHash,
        outboxHashes.filterKeys { it in outbox })
}

private fun SyncState.toMutable() = MutableSyncState(
    inbox = inbox.toMutableMap(),
    outbox = outbox.toMutableSet(),
    contactsHash = contactsHash,
    outboxHashes = outboxHashes.toMutableMap()
)
