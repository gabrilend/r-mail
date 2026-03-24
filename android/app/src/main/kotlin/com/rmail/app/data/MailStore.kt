package com.rmail.app.data

import android.content.Context
import com.rmail.app.crypto.Crypto
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * File-based storage mirroring the home daemon's directory layout.
 *
 *   filesDir/mailbox-0/
 *     inbox/        — received message files
 *     outbox/       — messages in flight
 *     attachments/  — downloaded attachment cache
 *     sync-state.json
 *     contacts
 */
class MailStore(context: Context) {

    val root: File = File(context.filesDir, "mailbox-0").also { it.mkdirs() }
    val inbox: File = File(root, "inbox").also { it.mkdirs() }
    val outbox: File = File(root, "outbox").also { it.mkdirs() }
    val attachments: File = File(root, "attachments").also { it.mkdirs() }
    private val syncStateFile = File(root, "sync-state.json")
    private val contactsFile = File(root, "contacts")

    // ── Inbox ──────────────────────────────────────────────────────────────

    fun listInbox(): List<String> = inbox.listFiles()?.map { it.name }?.sorted() ?: emptyList()

    fun readInbox(filename: String): String = File(inbox, filename).readText()

    fun writeInbox(filename: String, content: ByteArray) {
        File(inbox, filename).writeBytes(content)
    }

    fun deleteInbox(filename: String) {
        File(inbox, filename).delete()
    }

    // ── Outbox ─────────────────────────────────────────────────────────────

    fun listOutbox(): List<String> = outbox.listFiles()?.map { it.name }?.sorted() ?: emptyList()

    fun readOutbox(filename: String): String = File(outbox, filename).readText()

    fun writeOutbox(filename: String, content: String) {
        File(outbox, filename).writeText(content)
    }

    fun deleteOutbox(filename: String) {
        File(outbox, filename).delete()
    }

    // ── Sync state ─────────────────────────────────────────────────────────

    fun readSyncState(): SyncState {
        if (!syncStateFile.exists()) return SyncState(emptyMap(), emptySet(), null)
        return try {
            val obj = JSONObject(syncStateFile.readText())
            val inboxObj = obj.optJSONObject("inbox") ?: JSONObject()
            val inboxMap = mutableMapOf<String, InboxEntry>()
            inboxObj.keys().forEach { id ->
                val e = inboxObj.getJSONObject(id)
                inboxMap[id] = InboxEntry(e.getString("filename"), e.getString("from"))
            }
            val outboxArr = obj.optJSONArray("outbox") ?: JSONArray()
            val outboxSet = mutableSetOf<String>()
            for (i in 0 until outboxArr.length()) outboxSet.add(outboxArr.getString(i))
            SyncState(inboxMap, outboxSet, obj.optString("contacts_hash").ifBlank { null })
        } catch (_: Exception) {
            SyncState(emptyMap(), emptySet(), null)
        }
    }

    fun writeSyncState(state: SyncState) {
        val obj = JSONObject()
        val inboxObj = JSONObject()
        state.inbox.forEach { (id, entry) ->
            inboxObj.put(id, JSONObject().apply {
                put("filename", entry.filename)
                put("from", entry.from)
            })
        }
        obj.put("inbox", inboxObj)
        val outboxArr = JSONArray()
        state.outbox.forEach { outboxArr.put(it) }
        obj.put("outbox", outboxArr)
        if (state.contactsHash != null) obj.put("contacts_hash", state.contactsHash)
        syncStateFile.writeText(obj.toString(2))
    }

    // ── Contacts ───────────────────────────────────────────────────────────

    fun readContacts(): String =
        if (contactsFile.exists()) contactsFile.readText() else ""

    fun writeContacts(content: String) {
        contactsFile.writeText(content)
    }

    /**
     * Canonical contacts hash matching the server-side `canonical_contacts_hash()` in rmail.lua.
     *
     * Algorithm: parse all `name.key = value` lines, sort contacts by name, sort fields by key
     * within each contact, re-emit as `name.key = value`, then SHA-256 the result.
     *
     * Values are kept as-is (including any surrounding quotes) so the output matches the Lua
     * canonical serialization which also preserves the stored value format.
     */
    fun contactsHash(): String? {
        if (!contactsFile.exists()) return null
        val text = contactsFile.readText()

        // Parse into a nested map: contactName -> (fieldKey -> rawValue)
        val contacts = mutableMapOf<String, MutableMap<String, String>>()
        for (line in text.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("--")) continue
            val eqIdx = trimmed.indexOf('=')
            if (eqIdx < 0) continue
            val dotKey = trimmed.substring(0, eqIdx).trim()
            val value = trimmed.substring(eqIdx + 1).trim()
            val dotIdx = dotKey.lastIndexOf('.')
            if (dotIdx < 0) continue
            val name = dotKey.substring(0, dotIdx).trim()
            val key = dotKey.substring(dotIdx + 1).trim()
            contacts.getOrPut(name) { mutableMapOf() }[key] = value
        }

        // Serialize canonically (sorted names, sorted keys)
        val lines = mutableListOf<String>()
        for (name in contacts.keys.sorted()) {
            val fields = contacts[name]!!
            for (key in fields.keys.sorted()) {
                lines.add("$name.$key = ${fields[key]}")
            }
        }
        val canonical = lines.joinToString("\n")
        return Crypto.sha256Hex(canonical.toByteArray(Charsets.UTF_8))
    }

    // ── Attachments cache ──────────────────────────────────────────────────

    fun cachedAttachmentFile(filename: String): File = File(attachments, filename)

    fun isAttachmentCached(filename: String): Boolean =
        File(attachments, filename).exists()
}
