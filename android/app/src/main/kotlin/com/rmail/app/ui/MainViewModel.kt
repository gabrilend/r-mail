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
            _syncError.value = null
            lastSyncTime = System.currentTimeMillis()
            val manager = SyncManager(getApplication(), config, s, serverLanIp)
            when (val result = manager.sync()) {
                is SyncResult.Success, is SyncResult.NewMessages -> {
                    _syncStatus.value = SyncStatus.IDLE
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
    private fun repairFile(client: RmailClient, filename: String, localFile: File): Boolean {
        return try {
            // Get server's chunk manifest
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

            // Compute local per-chunk checksums
            val localChecksums = mutableListOf<String>()
            localFile.inputStream().buffered().use { stream ->
                val buf = ByteArray(chunkSize.toInt())
                for (i in 0 until numChunks) {
                    var read = 0
                    while (read < chunkSize) {
                        val n = stream.read(buf, read, (chunkSize - read).toInt())
                        if (n <= 0) break
                        read += n
                    }
                    val chunkData = if (read == chunkSize.toInt()) buf else buf.copyOf(read)
                    localChecksums.add(com.rmail.app.crypto.Crypto.sha256Hex(chunkData))
                }
            }

            // Find mismatched chunks
            val badChunks = (0 until numChunks).filter { i ->
                i >= localChecksums.size || localChecksums[i] != serverChecksums[i]
            }

            if (badChunks.isEmpty()) return true // checksums all match after re-check

            Log.i("rmail", "Repairing $filename: ${badChunks.size}/$numChunks chunks corrupted")

            // Re-download only the bad chunks and patch the file
            val raf = java.io.RandomAccessFile(localFile, "rw")
            for (chunkIdx in badChunks) {
                val (chunkStatus, chunkBody) = client.get("/api/attachments/$filename/chunk/$chunkIdx")
                if (chunkStatus != 200) {
                    Log.e("rmail", "Repair failed: chunk $chunkIdx returned HTTP $chunkStatus")
                    raf.close(); return false
                }
                val hash = com.rmail.app.crypto.Crypto.sha256Hex(chunkBody)
                if (hash != serverChecksums[chunkIdx]) {
                    Log.e("rmail", "Repair failed: chunk $chunkIdx checksum mismatch after re-download " +
                        "(server may have a bad disk)")
                    raf.close(); return false
                }
                raf.seek(chunkIdx.toLong() * chunkSize)
                raf.write(chunkBody)
            }
            raf.close()

            // Verify whole file after repair
            if (fileChecksum.isNotBlank()) {
                val repairedHash = com.rmail.app.crypto.Crypto.sha256HexFile(localFile)
                if (repairedHash != fileChecksum) {
                    Log.e("rmail", "Repair failed: whole-file checksum still wrong after patching " +
                        "${badChunks.size} chunks — file may be wrong size")
                    return false
                }
            }
            Log.i("rmail", "Repair succeeded for $filename: ${badChunks.size} chunks replaced")
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
                    client.downloadAttachmentChunked(info.filename, file) { downloaded, total ->
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
                    _myAddress.value = "${info.ip}:${info.port}"
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

                    val serverPath = withContext(Dispatchers.IO) {
                        app.contentResolver.openInputStream(uri)?.use { stream ->
                            RmailClient.uploadFileCompressed(
                                client, filename, stream, fileSize, app.cacheDir
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
