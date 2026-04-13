package com.rmail.app.ui

import android.app.Application
import android.util.Log
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.rmail.app.data.AttachmentInfo
import com.rmail.app.data.MailMessage
import com.rmail.app.data.MailStore
import com.rmail.app.data.MailboxConfig
import com.rmail.app.data.MailboxRegistry
import com.rmail.app.data.Settings
import com.rmail.app.net.RmailClient
import com.rmail.app.sync.SyncManager
import com.rmail.app.sync.SyncResult
import com.rmail.app.sync.SyncWorker
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class SyncStatus { IDLE, SYNCING, ERROR }

class MainViewModel(application: Application) : AndroidViewModel(application) {

    val globalSettings = Settings(application)

    // #318: exposes readerColumns as observable Compose state so the
    // Read screen recomposes when the user taps the +/- buttons.
    private val _readerColumns = MutableStateFlow(globalSettings.readerColumns)
    val readerColumns: StateFlow<Int> = _readerColumns
    fun bumpReaderColumns() { _readerColumns.value = globalSettings.readerColumns }
    val registry = MailboxRegistry(application)

    // ── Mailbox list ────────────────────────────────────────────────────────

    private val _mailboxes = MutableStateFlow<List<MailboxConfig>>(emptyList())
    val mailboxes: StateFlow<List<MailboxConfig>> = _mailboxes

    private val _activeMailboxId = MutableStateFlow<String?>(null)
    val activeMailboxId: StateFlow<String?> = _activeMailboxId

    // ── Active mailbox state ────────────────────────────────────────────────

    private var activeConfig: MailboxConfig? = null
    var store: MailStore? = null
        private set

    private val _inboxFiles = MutableStateFlow<List<String>>(emptyList())
    val inboxFiles: StateFlow<List<String>> = _inboxFiles

    private val _outboxFiles = MutableStateFlow<List<String>>(emptyList())
    val outboxFiles: StateFlow<List<String>> = _outboxFiles

    private val _syncStatus = MutableStateFlow(SyncStatus.IDLE)
    val syncStatus: StateFlow<SyncStatus> = _syncStatus

    private val _syncError = MutableStateFlow<String?>(null)
    val syncError: StateFlow<String?> = _syncError

    private val _attachments = MutableStateFlow<List<AttachmentInfo>>(emptyList())
    val attachments: StateFlow<List<AttachmentInfo>> = _attachments

    private val _myAddress = MutableStateFlow<String?>(null)
    val myAddress: StateFlow<String?> = _myAddress

    private val _daemonName = MutableStateFlow<String?>(null)
    val daemonName: StateFlow<String?> = _daemonName

    private var serverLanIp: String? = null

    // #358: Pending compose draft delivered from ReadScreen (forward /
    // reply actions).  InboxScreen consumes it when it appears, fills
    // draftRecipients/draftSubject/draftBody, and clears the pending
    // value.  Null means "nothing queued."
    data class PendingDraft(
        val recipients: List<String>,
        val subject: String,
        val body: String,
        // #321: when non-null, the composer is in *edit* mode for this
        // outbox filename — Send becomes Save, the back gesture asks
        // for confirmation, and on save we overwrite this file rather
        // than generating a fresh name.
        val editingOutboxFilename: String? = null,
        // #321: existing `attach: ...` lines from the outbox file
        // being edited, preserved verbatim through the save round-trip.
        val attachLines: List<String> = emptyList()
    )
    private val _pendingDraft = MutableStateFlow<PendingDraft?>(null)
    val pendingDraft: StateFlow<PendingDraft?> = _pendingDraft
    fun queuePendingDraft(draft: PendingDraft) { _pendingDraft.value = draft }
    fun consumePendingDraft(): PendingDraft? {
        val d = _pendingDraft.value
        _pendingDraft.value = null
        return d
    }

    // #322: "I just hit Send" animation state.  The composable watches
    // `sendingBar` and phases itself: dots countdown → hold-at-3 until
    // sync completes → slide off + success/failure text → gone.
    //
    // The dot count is fixed small (15) and ticks quickly (5/s) so the
    // animation is decorative, not a literal timer.  Actual delivery
    // status drives the phase transitions via syncStatus updates.
    data class SendingBar(
        val startedAtMs: Long,
        val outboxFilename: String
    )
    private val _sendingBar = MutableStateFlow<SendingBar?>(null)
    val sendingBar: StateFlow<SendingBar?> = _sendingBar
    fun markSendingStart(filename: String) {
        _sendingBar.value = SendingBar(System.currentTimeMillis(), filename)
    }
    fun clearSendingBar() { _sendingBar.value = null }

    init {
        // Run migration from old single-mailbox layout
        registry.migrateFromLegacy()
        _mailboxes.value = registry.loadAll()

        // Schedule background sync for all mailboxes
        viewModelScope.launch(Dispatchers.IO) {
            val minInterval = _mailboxes.value
                .minOfOrNull { it.bgSyncIntervalMinutes } ?: 15
            SyncWorker.schedule(application, minInterval)
        }
    }

    fun refreshMailboxList() {
        _mailboxes.value = registry.loadAll()
    }

    // ── Mailbox selection ───────────────────────────────────────────────────

    private var pollingJob: Job? = null
    private val FOREGROUND_SYNC_INTERVAL_MS = 10_000L
    private var lastSyncTime = 0L

    fun selectMailbox(id: String) {
        val config = registry.get(id) ?: return
        activeConfig = config
        store = MailStore(getApplication(), id)
        _activeMailboxId.value = id
        _myAddress.value = null
        _daemonName.value = null
        serverLanIp = null
        _syncError.value = null
        _syncStatus.value = SyncStatus.IDLE
        refreshLocal()
        refreshLocalAttachments()
        triggerSync()
        startForegroundPolling()
    }

    fun deselectMailbox() {
        pollingJob?.cancel()
        pollingJob = null
        _activeMailboxId.value = null
        activeConfig = null
        store = null
        _inboxFiles.value = emptyList()
        _outboxFiles.value = emptyList()
        _attachments.value = emptyList()
        _myAddress.value = null
        _daemonName.value = null
    }

    private fun startForegroundPolling() {
        pollingJob?.cancel()
        pollingJob = viewModelScope.launch {
            while (true) {
                delay(1_000)
                val elapsed = System.currentTimeMillis() - lastSyncTime
                if (elapsed >= FOREGROUND_SYNC_INTERVAL_MS &&
                    _syncStatus.value != SyncStatus.SYNCING) {
                    triggerSync()
                }
            }
        }
    }

    // ── Active mailbox operations ───────────────────────────────────────────

    /** Immediately populate attachment list from locally cached files (no server call). */
    private fun refreshLocalAttachments() {
        val s = store ?: return
        val localFiles = s.attachments.listFiles()?.filter { it.isFile }?.map { file ->
            AttachmentInfo(
                filename = file.name,
                size = file.length(),
                category = inferCategory(file.name),
                onServer = false,  // unknown until server responds
                onDevice = true
            )
        }?.sortedBy { it.filename.lowercase() } ?: emptyList()
        _attachments.value = localFiles
    }

    fun refreshLocal() {
        val s = store ?: return
        _inboxFiles.value = s.listInbox()
        _outboxFiles.value = s.listOutbox()
    }

    fun triggerSync() {
        val config = activeConfig ?: return
        val s = store ?: return
        if (_syncStatus.value == SyncStatus.SYNCING) return
        viewModelScope.launch {
            _syncStatus.value = SyncStatus.SYNCING
            lastSyncTime = System.currentTimeMillis()
            val manager = SyncManager(getApplication(), config, s, serverLanIp)
            when (val result = manager.sync()) {
                is SyncResult.Success, is SyncResult.NewMessages -> {
                    _syncStatus.value = SyncStatus.IDLE
                    _syncError.value = null
                    refreshLocal()
                    if (_myAddress.value == null) fetchMyAddress()
                    // Update mailbox name from server if we don't have one
                    val serverName = when (result) {
                        is SyncResult.Success -> result.mailboxName
                        is SyncResult.NewMessages -> result.mailboxName
                        else -> null
                    }
                    val serverPath = when (result) {
                        is SyncResult.Success -> result.mailboxPath
                        is SyncResult.NewMessages -> result.mailboxPath
                        else -> null
                    }
                    val cfg = activeConfig
                    if (cfg != null) {
                        var updated = cfg
                        if (serverName != null && cfg.name.isBlank()) updated = updated.copy(name = serverName)
                        if (serverPath != null && cfg.mailboxPath.isBlank()) updated = updated.copy(mailboxPath = serverPath)
                        if (updated != cfg) updateMailbox(updated)
                    }
                }
                is SyncResult.Error -> {
                    _syncStatus.value = SyncStatus.ERROR
                    _syncError.value = result.message
                }
            }
        }
    }

    fun loadMessage(filename: String): MailMessage? {
        val s = store ?: return null
        return try { MailMessage(filename, s.readInbox(filename)) }
        catch (_: Exception) { null }
    }

    // #358: the sender of an inbox message lives in sync-state, not in
    // the message body.  Used by ReadScreen's Reply flow to pre-address
    // the composer.  The sync-state map is keyed by message id, so we
    // scan by filename.
    fun senderOfInbox(filename: String): String {
        val s = store ?: return ""
        return try {
            s.readSyncState().inbox.values
                .firstOrNull { it.filename == filename }
                ?.from ?: ""
        } catch (_: Exception) { "" }
    }

    // #357: enumerate things on this device that the home server doesn't
    // have a known-good copy of yet.  Used by the delete-mailbox
    // confirmation dialog so the user can see what they might lose by
    // severing the connection now.
    //
    // "Unsynced" here means:
    //   - local outbox files that the server hasn't confirmed
    //     delivery of
    //   - (future) in-flight chunked attachment uploads
    //   - (future) contacts edits not yet pushed
    //
    // Currently conservative: we report every local outbox file as
    // potentially unsynced because the phone's sync-state doesn't
    // separately track per-file delivery confirmation.  Better to
    // over-warn than under-warn on a destructive action.
    fun unsyncedSummary(): List<String> {
        val s = store ?: return emptyList()
        val items = mutableListOf<String>()
        s.listOutbox().forEach { items.add("outbox/$it") }
        return items
    }

    // #357: removeMailbox is defined further down alongside the other
    // registry-mutation helpers (updateMailbox etc.) — same body as
    // the one I had here originally.  Removed the duplicate.

    fun loadOutboxMessage(filename: String): MailMessage? {
        val s = store ?: return null
        return try { MailMessage(filename, s.readOutbox(filename)) }
        catch (_: Exception) { null }
    }

    fun deleteInboxMessage(filename: String) {
        store?.deleteInbox(filename)
        refreshLocal()
        triggerSync()
    }

    fun deleteOutboxFile(filename: String) {
        store?.deleteOutbox(filename)
        refreshLocal()
        triggerSync()
    }

    fun saveOutboxFile(filename: String, content: String) {
        store?.writeOutbox(filename, content)
        refreshLocal()
        triggerSync()
    }

    fun newOutboxFilename(): String {
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        return "$ts.txt"
    }

    fun getContactNames(): List<String> = store?.parseContactNames() ?: emptyList()

    fun readContacts(): String = store?.readContacts() ?: ""

    fun saveContacts(content: String) {
        store?.writeContacts(content)
    }

    fun loadAttachmentList() {
        val config = activeConfig ?: return
        val s = store ?: return
        val wasSyncing = _syncStatus.value == SyncStatus.SYNCING
        if (!wasSyncing) _syncStatus.value = SyncStatus.SYNCING
        viewModelScope.launch {
            try {
                val client = RmailClient(config.host, config.port, config.token)
                val serverList = withContext(Dispatchers.IO) { client.listAttachments() }
                val serverNames = serverList.map { it.filename }.toSet()

                // Mark server files with device presence, verify checksums.
                // Corrupt files are auto-repaired: only bad chunks are re-downloaded.
                val combined = withContext(Dispatchers.IO) {
                    serverList.map { info ->
                        var onDevice = s.isAttachmentCached(info.filename)
                        if (onDevice && info.checksum.isNotBlank()) {
                            val localFile = s.cachedAttachmentFile(info.filename)
                            val localHash = com.rmail.app.crypto.Crypto.sha256HexFile(localFile)
                            if (localHash != info.checksum) {
                                // File is corrupt — attempt chunk-level repair
                                val repaired = repairFile(client, info.filename, localFile)
                                onDevice = repaired
                                // Don't delete — leave the file for future repair attempts
                                // unless it's completely unrepairable (wrong size, etc.)
                            }
                        }
                        info.copy(onServer = true, onDevice = onDevice)
                    }.toMutableList()
                }

                // Add locally cached files not on the server
                withContext(Dispatchers.IO) {
                    s.attachments.listFiles()?.forEach { file ->
                        if (file.isFile && file.name !in serverNames) {
                            combined.add(AttachmentInfo(
                                filename = file.name,
                                size = file.length(),
                                category = inferCategory(file.name),
                                onServer = false,
                                onDevice = true
                            ))
                        }
                    }
                }

                _attachments.value = combined.sortedBy { it.filename.lowercase() }
            } catch (_: Exception) {
                // Offline — show only local files
                val s2 = store ?: run {
                    if (!wasSyncing) _syncStatus.value = SyncStatus.IDLE
                    return@launch
                }
                val localOnly = withContext(Dispatchers.IO) {
                    s2.attachments.listFiles()?.filter { it.isFile }?.map { file ->
                        AttachmentInfo(
                            filename = file.name,
                            size = file.length(),
                            category = inferCategory(file.name),
                            onServer = false,
                            onDevice = true
                        )
                    } ?: emptyList()
                }
                _attachments.value = localOnly.sortedBy { it.filename.lowercase() }
            }
            if (!wasSyncing) _syncStatus.value = SyncStatus.IDLE
        }
    }

    private fun inferCategory(filename: String): String {
        val ext = filename.substringAfterLast('.', "").lowercase()
        return when (ext) {
            "jpg", "jpeg", "png", "gif", "webp", "bmp", "svg" -> "image"
            "mp3", "wav", "ogg", "flac", "aac", "m4a" -> "audio"
            "mp4", "mkv", "avi", "mov", "webm" -> "video"
            "txt", "md", "log", "csv", "json", "xml", "html" -> "text"
            else -> "other"
        }
    }

    /**
     * Repair a corrupt local file by comparing per-chunk checksums with the
     * server and re-downloading only the mismatched chunks.
     * Returns true if repair succeeded, false if it failed.
     */
    /**
     * Repair a corrupt file using the chunk-file model. If chunk files still
     * exist from the download, verify each one and re-download bad chunks.
     * Then re-assemble and verify the whole file.
     */
    private fun repairFile(client: RmailClient, filename: String, localFile: File): Boolean {
        return try {
            val s = store ?: return false
            val chunksDir = File(s.attachments, ".downloads/$filename")

            // Get server manifest
            val (status, body) = client.get("/api/attachments/$filename/info")
            if (status != 200) return false
            val info = org.json.JSONObject(body.toString(Charsets.UTF_8))
            val chunkSize = info.optLong("chunk_size", 256L * 1024)
            val numChunks = info.getInt("num_chunks")
            val fileChecksum = info.optString("file_checksum", "")
            val serverChecksums = mutableListOf<String>()
            info.optJSONArray("chunk_checksums")?.let { arr ->
                for (i in 0 until arr.length()) serverChecksums.add(arr.optString(i, ""))
            }
            if (serverChecksums.size != numChunks) return false

            // If chunk files don't exist, re-chunk from the assembled file
            chunksDir.mkdirs()
            fun chunkFile(i: Int) = File(chunksDir, "chunk-%04d.bin".format(i))

            val hasChunkFiles = (0 until numChunks).any { chunkFile(it).exists() }
            if (!hasChunkFiles && localFile.exists()) {
                Log.i("rmail", "Re-chunking $filename for repair")
                localFile.inputStream().buffered().use { stream ->
                    val buf = ByteArray(chunkSize.toInt())
                    for (i in 0 until numChunks) {
                        var read = 0
                        while (read < chunkSize) {
                            val n = stream.read(buf, read, (chunkSize - read).toInt())
                            if (n <= 0) break
                            read += n
                        }
                        chunkFile(i).writeBytes(if (read == chunkSize.toInt()) buf else buf.copyOf(read))
                    }
                }
            }

            // Verify each chunk, delete bad ones
            val badChunks = mutableListOf<Int>()
            for (i in 0 until numChunks) {
                val cf = chunkFile(i)
                if (!cf.exists()) { badChunks.add(i); continue }
                val hash = com.rmail.app.crypto.Crypto.sha256Hex(cf.readBytes())
                if (hash != serverChecksums[i]) {
                    cf.delete()
                    badChunks.add(i)
                }
            }

            if (badChunks.isEmpty()) {
                Log.i("rmail", "Repair: all chunks verified for $filename, re-assembling")
            } else {
                Log.i("rmail", "Repairing $filename: ${badChunks.size}/$numChunks chunks need re-download")
                for (chunkIdx in badChunks) {
                    val (cs, cb) = client.get("/api/attachments/$filename/chunk/$chunkIdx")
                    if (cs != 200) { Log.e("rmail", "Repair: chunk $chunkIdx HTTP $cs"); return false }
                    val hash = com.rmail.app.crypto.Crypto.sha256Hex(cb)
                    if (hash != serverChecksums[chunkIdx]) {
                        Log.e("rmail", "Repair: chunk $chunkIdx still bad after re-download"); return false
                    }
                    chunkFile(chunkIdx).writeBytes(cb)
                }
            }

            // Re-assemble
            localFile.outputStream().buffered().use { out ->
                for (i in 0 until numChunks) {
                    chunkFile(i).inputStream().use { inp -> inp.copyTo(out) }
                }
            }

            // Verify whole file
            if (fileChecksum.isNotBlank()) {
                val repairedHash = com.rmail.app.crypto.Crypto.sha256HexFile(localFile)
                if (repairedHash != fileChecksum) {
                    Log.e("rmail", "Repair: whole-file checksum still wrong after re-assembly")
                    return false
                }
            }

            // Clean up chunks
            chunksDir.deleteRecursively()
            Log.i("rmail", "Repair succeeded for $filename")
            true
        } catch (e: Exception) {
            Log.e("rmail", "Repair failed for $filename: ${e.message}")
            false
        }
    }

    // Files currently being deleted (shown as spinner)
    private val _deletingFiles = MutableStateFlow<Set<String>>(emptySet())
    val deletingFiles: StateFlow<Set<String>> = _deletingFiles

    fun deleteAttachmentFromServer(filename: String) {
        val config = activeConfig ?: return
        _deletingFiles.value = _deletingFiles.value + filename
        viewModelScope.launch {
            try {
                val client = RmailClient(config.host, config.port, config.token)
                val ok = withContext(Dispatchers.IO) { client.deleteAttachment(filename) }
                if (ok) loadAttachmentList()
            } catch (_: Exception) {}
            _deletingFiles.value = _deletingFiles.value - filename
        }
    }

    fun deleteAttachmentFromDevice(filename: String) {
        val s = store ?: return
        _deletingFiles.value = _deletingFiles.value + filename
        viewModelScope.launch {
            withContext(Dispatchers.IO) { s.cachedAttachmentFile(filename).delete() }
            loadAttachmentList()
            _deletingFiles.value = _deletingFiles.value - filename
        }
    }

    // Download progress: filename -> (bytesDownloaded, totalBytes) or null when not downloading
    private val _downloadProgress = MutableStateFlow<Map<String, Pair<Long, Long>>>(emptyMap())
    val downloadProgress: StateFlow<Map<String, Pair<Long, Long>>> = _downloadProgress

    // Active download jobs, keyed by filename, so they can be cancelled
    private val downloadJobs = mutableMapOf<String, Job>()

    fun downloadAttachment(info: AttachmentInfo, onDone: (File?) -> Unit) {
        val config = activeConfig ?: run { onDone(null); return }
        val s = store ?: run { onDone(null); return }
        val job = viewModelScope.launch {
            try {
                _downloadProgress.value = _downloadProgress.value + (info.filename to (0L to info.size))

                val client = RmailClient(config.host, config.port, config.token)
                val file = s.cachedAttachmentFile(info.filename)

                withContext(Dispatchers.IO) {
                    val chunksDir = java.io.File(s.attachments, ".downloads/${info.filename}")
                    client.downloadAttachmentChunked(info.filename, file, chunksDir) { downloaded, total ->
                        _downloadProgress.value = _downloadProgress.value +
                            (info.filename to (downloaded to total))
                    }
                }

                _downloadProgress.value = _downloadProgress.value - info.filename
                downloadJobs.remove(info.filename)
                loadAttachmentList()  // refresh presence info
                onDone(file)
            } catch (e: Exception) {
                _downloadProgress.value = _downloadProgress.value - info.filename
                downloadJobs.remove(info.filename)
                when (e) {
                    is CancellationException -> {
                        s.cachedAttachmentFile(info.filename).delete()
                    }
                    is com.rmail.app.net.ChecksumMismatchException -> {
                        Log.w("rmail", "Download checksum mismatch for ${info.filename}, attempting repair")
                        val repairClient = RmailClient(config.host, config.port, config.token)
                        withContext(Dispatchers.IO) {
                            repairClient.remoteLog("warn", "Checksum mismatch after downloading ${info.filename}, attempting repair")
                        }
                        val repaired = withContext(Dispatchers.IO) {
                            repairFile(repairClient, info.filename, s.cachedAttachmentFile(info.filename))
                        }
                        if (repaired) {
                            Log.i("rmail", "Post-download repair succeeded for ${info.filename}")
                            withContext(Dispatchers.IO) {
                                repairClient.remoteLog("info", "Repair succeeded for ${info.filename}")
                            }
                            loadAttachmentList()
                            onDone(s.cachedAttachmentFile(info.filename))
                            return@launch
                        } else {
                            Log.e("rmail", "Post-download repair FAILED for ${info.filename}")
                            withContext(Dispatchers.IO) {
                                repairClient.remoteLog("error", "Repair FAILED for ${info.filename}")
                            }
                        }
                    }
                    else -> {
                        Log.e("rmail", "Download failed for ${info.filename}: ${e.message}")
                        try {
                            val logClient = RmailClient(config.host, config.port, config.token)
                            withContext(Dispatchers.IO) {
                                logClient.remoteLog("error", "Download failed for ${info.filename}: ${e.message}")
                            }
                        } catch (_: Exception) {}
                    }
                }
                onDone(null)
            }
        }
        downloadJobs[info.filename] = job
    }

    fun cancelDownload(filename: String) {
        downloadJobs[filename]?.cancel()
        downloadJobs.remove(filename)
        _downloadProgress.value = _downloadProgress.value - filename
        store?.cachedAttachmentFile(filename)?.delete()
    }

    private fun fetchMyAddress() {
        val config = activeConfig ?: return
        viewModelScope.launch {
            try {
                val client = RmailClient(config.host, config.port, config.token)
                val info = withContext(Dispatchers.IO) { client.getMyAddress() }
                if (info != null) {
                    val v6 = if (info.ipv6.isNotBlank()) " (IPv6: ${info.ipv6})" else ""
                    _myAddress.value = "${info.ip}:${info.port}$v6"
                    if (info.name.isNotBlank()) _daemonName.value = info.name
                    if (info.lanIp.isNotBlank()) serverLanIp = info.lanIp
                }
            } catch (_: Exception) {}
        }
    }

    fun uploadAttachmentsInBackground(outboxFilename: String, uris: List<Uri>) {
        val config = activeConfig ?: return
        val s = store ?: return
        if (uris.isEmpty()) return
        val daemonLabel = config.name.ifBlank { config.host }
        viewModelScope.launch {
            val client = RmailClient(config.host, config.port, config.token)
            // Check which files are already on the server to avoid re-uploading
            val serverFiles = _attachments.value.filter { it.onServer }.map { it.filename }.toSet()
            val mailboxPath = config.mailboxPath

            for (uri in uris) {
                val uriStr = uri.toString()
                if (!uriStr.startsWith("content://") && !uriStr.startsWith("file://")) continue
                try {
                    val filename = resolveFilename(uri) ?: "attachment"

                    // Skip upload if file already exists on server — just update the path
                    if (filename in serverFiles && mailboxPath.isNotBlank()) {
                        val serverPath = "$mailboxPath/attachments/$filename"
                        withContext(Dispatchers.IO) {
                            val file = File(s.outbox, outboxFilename)
                            if (file.exists()) {
                                val text = file.readText()
                                file.writeText(text.replace(uriStr, serverPath))
                            }
                        }
                        continue
                    }

                    val app = getApplication<Application>()

                    // Get file size for progress reporting
                    val fileSize = withContext(Dispatchers.IO) {
                        app.contentResolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: 0L
                    }

                    // Progress marker in the outbox file — throttled to once per second
                    val progressMarker = "\n\n---\n"
                    var lastProgressWrite = 0L
                    fun writeProgress(line: String) {
                        val now = System.currentTimeMillis()
                        if (now - lastProgressWrite < 1000) return
                        lastProgressWrite = now
                        try {
                            val file = File(s.outbox, outboxFilename)
                            if (!file.exists()) return
                            val text = file.readText()
                            val base = if (progressMarker in text)
                                text.substringBefore(progressMarker)
                            else text
                            file.writeText(base + progressMarker + line)
                        } catch (_: Exception) {}
                    }

                    val uploadChunksDir = java.io.File(app.cacheDir, "upload-chunks/$filename")
                    val serverPath = withContext(Dispatchers.IO) {
                        val stream = app.contentResolver.openInputStream(uri)
                        try {
                            RmailClient.uploadFileCompressed(
                                client, filename, stream, fileSize,
                                app.cacheDir, uploadChunksDir
                            ) { phase, processed, total ->
                                val processedMB = "%.1f".format(processed / (1024.0 * 1024.0))
                                val totalMB = "%.1f".format(total / (1024.0 * 1024.0))
                                val msg = when (phase) {
                                    RmailClient.Companion.UploadPhase.ZIPPING ->
                                        "zipping $filename... $processedMB MB / $totalMB MB"
                                    RmailClient.Companion.UploadPhase.SENDING ->
                                        "sending to $daemonLabel... $processedMB MB / $totalMB MB"
                                }
                                writeProgress(msg)
                            }
                        } finally {
                            stream?.close()
                        }
                    } ?: continue

                    // Upload done — replace URI with server path, remove progress
                    withContext(Dispatchers.IO) {
                        val file = File(s.outbox, outboxFilename)
                        if (file.exists()) {
                            var text = file.readText()
                            // Remove progress marker and everything after it
                            if (progressMarker in text) {
                                text = text.substringBefore(progressMarker)
                            }
                            file.writeText(text.replace(uriStr, serverPath))
                        }
                    }
                } catch (_: Exception) {}
            }
            refreshLocal()
        }
    }

    private fun resolveFilename(uri: Uri): String? {
        getApplication<Application>().contentResolver.query(
            uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME),
            null, null, null
        )?.use { cursor ->
            if (cursor.moveToFirst()) return cursor.getString(0)
        }
        return uri.lastPathSegment
    }

    // ── Mailbox management ──────────────────────────────────────────────────

    fun addMailbox(config: MailboxConfig) {
        registry.add(config)
        _mailboxes.value = registry.loadAll()
    }

    fun updateMailbox(config: MailboxConfig) {
        registry.update(config)
        if (activeConfig?.id == config.id) activeConfig = config
        _mailboxes.value = registry.loadAll()
    }

    fun removeMailbox(id: String) {
        if (_activeMailboxId.value == id) deselectMailbox()
        registry.remove(id)
        _mailboxes.value = registry.loadAll()
    }

    fun onSettingsSaved() {
        val config = activeConfig ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                SyncWorker.schedule(getApplication(), config.bgSyncIntervalMinutes)
            }
            triggerSync()
        }
    }

    /** Helper for screens that need to know if the active mailbox is configured */
    val isActiveConfigured: Boolean get() = activeConfig?.isConfigured == true

    /** Per-mailbox swipe-to-delete setting */
    val swipeToDelete: Boolean get() = activeConfig?.swipeToDelete ?: true
}
