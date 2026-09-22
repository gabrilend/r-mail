package com.rmail.app.sync

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/**
 * Attachment upload status per outbox file, for the outbox list to show.
 *
 * This used to be written into the outbox file itself as a trailing
 * "zipping x MB / y MB" line.  The file was synced to the server mid-upload,
 * so that line was delivered to recipients as part of the message and never
 * changed again.  Status belongs in the UI, not in the mail.
 */
object UploadProgress {
    data class Status(val text: String, val error: Boolean = false)

    private val _state = MutableStateFlow<Map<String, Status>>(emptyMap())
    val state: StateFlow<Map<String, Status>> = _state

    fun set(outboxFile: String, text: String, error: Boolean = false) =
        _state.update { it + (outboxFile to Status(text, error)) }

    fun clear(outboxFile: String) = _state.update { it - outboxFile }
}
