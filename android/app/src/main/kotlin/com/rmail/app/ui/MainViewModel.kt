package com.rmail.app.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.rmail.app.data.AttachmentInfo
import com.rmail.app.data.MailMessage
import com.rmail.app.data.MailStore
import com.rmail.app.data.Settings
import com.rmail.app.net.RmailClient
import com.rmail.app.sync.SyncManager
import com.rmail.app.sync.SyncResult
import com.rmail.app.sync.SyncWorker
import kotlinx.coroutines.Dispatchers
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

    val settings = Settings(application)
    val store = MailStore(application)

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

    private val _serverLanIp = MutableStateFlow<String?>(null)

    init {
        // Defer to after the current composition completes (ViewModel is lazily created during
        // setContent, so Dispatchers.Main.immediate would run inline and block the first frame)
        viewModelScope.launch(Dispatchers.Main) {
            refreshLocal()
            if (settings.isConfigured) {
                triggerSync()
                withContext(Dispatchers.IO) {
                    SyncWorker.schedule(application, settings.bgSyncIntervalMinutes)
                }
                startForegroundPolling()
            }
        }
    }

    // TODO: re-evaluate sync model — consider push/inotify or longer interval for production
    private val FOREGROUND_SYNC_INTERVAL_MS = 10_000L
    private var lastSyncTime = 0L

    private fun startForegroundPolling() {
        viewModelScope.launch {
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

    fun refreshLocal() {
        _inboxFiles.value = store.listInbox()
        _outboxFiles.value = store.listOutbox()
    }

    fun triggerSync() {
        if (_syncStatus.value == SyncStatus.SYNCING) return
        viewModelScope.launch {
            _syncStatus.value = SyncStatus.SYNCING
            _syncError.value = null
            lastSyncTime = System.currentTimeMillis()
            val manager = SyncManager(getApplication(), settings, store, _serverLanIp.value)
            when (val result = manager.sync()) {
                is SyncResult.Success, is SyncResult.NewMessages -> {
                    _syncStatus.value = SyncStatus.IDLE
                    refreshLocal()
                    if (_myAddress.value == null) fetchMyAddress()
                }
                is SyncResult.Error -> {
                    _syncStatus.value = SyncStatus.ERROR
                    _syncError.value = result.message
                }
            }
        }
    }

    fun loadMessage(filename: String): MailMessage? {
        return try {
            val content = store.readInbox(filename)
            MailMessage(filename, content)
        } catch (_: Exception) {
            null
        }
    }

    fun loadOutboxMessage(filename: String): MailMessage? {
        return try {
            val content = store.readOutbox(filename)
            MailMessage(filename, content)
        } catch (_: Exception) {
            null
        }
    }

    fun deleteInboxMessage(filename: String) {
        store.deleteInbox(filename)
        refreshLocal()
        // Sync will notify the server of the deletion on next cycle
        triggerSync()
    }

    fun deleteOutboxFile(filename: String) {
        store.deleteOutbox(filename)
        refreshLocal()
        triggerSync()
    }

    fun saveOutboxFile(filename: String, content: String) {
        store.writeOutbox(filename, content)
        refreshLocal()
    }

    fun newOutboxFilename(): String {
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        return "$ts.txt"
    }

    fun getContactNames(): List<String> = store.parseContactNames()

    fun readContacts(): String = store.readContacts()

    fun saveContacts(content: String) {
        store.writeContacts(content)
    }

    fun loadAttachmentList() {
        viewModelScope.launch {
            if (!settings.isConfigured) return@launch
            try {
                val client = RmailClient(settings.serverHost, settings.serverPort, settings.deviceToken)
                val list = withContext(Dispatchers.IO) { client.listAttachments() }
                _attachments.value = list
            } catch (_: Exception) {}
        }
    }

    fun downloadAttachment(info: AttachmentInfo, onDone: (File?) -> Unit) {
        viewModelScope.launch {
            if (!settings.isConfigured) { onDone(null); return@launch }
            try {
                val client = RmailClient(settings.serverHost, settings.serverPort, settings.deviceToken)
                val data = withContext(Dispatchers.IO) { client.downloadAttachment(info.filename) }
                val file = store.cachedAttachmentFile(info.filename)
                file.writeBytes(data)
                onDone(file)
            } catch (_: Exception) {
                onDone(null)
            }
        }
    }

    private fun fetchMyAddress() {
        viewModelScope.launch {
            if (!settings.isConfigured) return@launch
            try {
                val client = RmailClient(settings.serverHost, settings.serverPort, settings.deviceToken)
                val info = withContext(Dispatchers.IO) { client.getMyAddress() }
                if (info != null) {
                    _myAddress.value = "${info.ip}:${info.port}"
                    if (info.name.isNotBlank()) _daemonName.value = info.name
                    if (info.lanIp.isNotBlank()) _serverLanIp.value = info.lanIp
                }
            } catch (_: Exception) {}
        }
    }

    /**
     * Upload attachments in the background, updating the outbox file as each one completes.
     * The outbox file is already saved with local URIs; this replaces them with server paths.
     */
    fun uploadAttachmentsInBackground(outboxFilename: String, uris: List<Uri>) {
        if (!settings.isConfigured || uris.isEmpty()) return
        viewModelScope.launch {
            val client = RmailClient(settings.serverHost, settings.serverPort, settings.deviceToken)
            for (uri in uris) {
                val uriStr = uri.toString()
                if (!uriStr.startsWith("content://") && !uriStr.startsWith("file://")) continue
                try {
                    val filename = resolveFilename(uri) ?: "attachment"
                    val data = withContext(Dispatchers.IO) {
                        getApplication<Application>().contentResolver.openInputStream(uri)?.readBytes()
                    } ?: continue
                    val serverPath = withContext(Dispatchers.IO) {
                        RmailClient.uploadFile(client, filename, data)
                    } ?: continue
                    // Replace the local URI with the server path in the outbox file
                    withContext(Dispatchers.IO) {
                        val file = java.io.File(store.outbox, outboxFilename)
                        if (file.exists()) {
                            val text = file.readText()
                            file.writeText(text.replace(uriStr, serverPath))
                        }
                    }
                } catch (_: Exception) {}
            }
            refreshLocal()
        }
    }

    private fun resolveFilename(uri: Uri): String? {
        // Try content resolver display name, fall back to last path segment
        getApplication<Application>().contentResolver.query(
            uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME),
            null, null, null
        )?.use { cursor ->
            if (cursor.moveToFirst()) return cursor.getString(0)
        }
        return uri.lastPathSegment
    }

    fun onSettingsSaved() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                SyncWorker.schedule(getApplication(), settings.bgSyncIntervalMinutes)
            }
            triggerSync()
        }
    }
}
