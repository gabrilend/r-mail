package com.rmail.app.data

// Persisted per-message entry in sync-state.json
data class InboxEntry(val filename: String, val from: String)

// Local sync state persisted to sync-state.json
data class SyncState(
    val inbox: Map<String, InboxEntry>,   // messageId -> {filename, from}
    val outbox: Set<String>,              // known outbox filenames
    val contactsHash: String?             // SHA-256 hex of last-synced contacts
)

// A mail message loaded from disk
data class MailMessage(
    val filename: String,
    val content: String
) {
    val isConsent: Boolean get() =
        content.lines().any { it.trim().equals("accept", ignoreCase = true) ||
                               it.trim().equals("deny", ignoreCase = true) }

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
    val category: String   // image / audio / text / other
)

data class UploadStartResult(val uploadId: String, val serverPath: String)
