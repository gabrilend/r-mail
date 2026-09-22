package com.rmail.app.data

// Persisted per-message entry in sync-state.json
data class InboxEntry(val filename: String, val from: String)

// Local sync state persisted to sync-state.json
data class SyncState(
    val inbox: Map<String, InboxEntry>,   // messageId -> {filename, from}
    val outbox: Set<String>,              // known outbox filenames
    val contactsHash: String?,            // SHA-256 hex of last-synced contacts
    // SHA-256 of each outbox file as last sent to or received from the
    // server, so an edit made on the phone afterwards is sent again.
    val outboxHashes: Map<String, String> = emptyMap()
)

// A mail message loaded from disk
data class MailMessage(
    val filename: String,
    val content: String
) {
    // The daemon names every consent form this way.  Guessing from the
    // content misread any message with a line reading "accept" or "deny".
    val isConsent: Boolean get() = filename.endsWith("-consent-to-download-form")

    val previewLines: String get() = content.lines()
        .dropWhile { it.isBlank() }
        .take(3)
        .joinToString("\n")
}

// Outgoing sync request body
data class SyncRequest(
    val inbox: Map<String, String>,           // messageId -> filename (current phone state)
    val deletedInbox: List<DeletedEntry>,
    val outbox: List<String>,                 // current outbox filenames on phone
    val deletedOutbox: List<String>,
    val contactsHash: String?
)

data class DeletedEntry(val messageId: String, val from: String)

// Incoming sync response
data class SyncResponse(
    val fetchInbox: Map<String, InboxEntry>,  // messageId -> {filename, from} (new messages to download)
    val removeInbox: List<String>,            // messageIds to delete locally
    val fetchOutbox: List<String>,            // filenames to download from server outbox
    val removeOutbox: List<String>,           // filenames to delete locally
    val contacts: String?,                    // full contacts text, or null if hashes match
    val mailboxName: String?,                 // daemon's config name
    val mailboxPath: String?                  // mailbox directory path on server
)

data class AttachmentInfo(
    val filename: String,
    val size: Long,
    val category: String,   // image / audio / text / other / video
    val checksum: String = "",
    val onServer: Boolean = true,
    val onDevice: Boolean = false
)

data class UploadStartResult(val uploadId: String, val serverPath: String)
