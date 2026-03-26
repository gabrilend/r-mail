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
class MailStore(context: Context, mailboxId: String) {

    val root: File = File(context.filesDir, "mailbox-$mailboxId").also { it.mkdirs() }
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
        contactsFile.writeText(alignContactsEquals(content))
    }

    /**
     * Pretty-print contacts: align equals signs per contact group.
     * Groups are separated by blank lines. Within each group, the = signs
     * align to the longest "name.field" prefix.
     */
    private fun alignContactsEquals(content: String): String {
        val result = StringBuilder()
        val group = mutableListOf<String>()

        fun flushGroup() {
            if (group.isEmpty()) return
            // Find the longest left-hand side (before =)
            val maxLhs = group.maxOf { line ->
                val eq = line.indexOf('=')
                if (eq > 0) line.substring(0, eq).trimEnd().length else 0
            }
            for (line in group) {
                val eq = line.indexOf('=')
                if (eq > 0 && maxLhs > 0) {
                    val lhs = line.substring(0, eq).trimEnd()
                    val rhs = line.substring(eq + 1).trimStart()
                    result.appendLine("${lhs.padEnd(maxLhs)} = $rhs")
                } else {
                    result.appendLine(line)
                }
            }
            group.clear()
        }

        for (line in content.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) {
                flushGroup()
                result.appendLine()
            } else if (trimmed.startsWith("#") || trimmed.startsWith("/")) {
                flushGroup()
                result.appendLine(line)
            } else {
                group.add(line)
            }
        }
        flushGroup()
        // Remove trailing blank lines
        return result.toString().trimEnd() + "\n"
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

        // Parse into a nested map: contactName -> (fieldKey -> unquotedValue)
        // Unquote values to match Lua's load_contacts() which strips surrounding quotes
        val contacts = mutableMapOf<String, MutableMap<String, String>>()
        for (line in text.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("/")) continue
            val eqIdx = trimmed.indexOf('=')
            if (eqIdx < 0) continue
            val dotKey = trimmed.substring(0, eqIdx).trim()
            val value = trimmed.substring(eqIdx + 1).trim().removeSurrounding("\"")
            val dotIdx = dotKey.lastIndexOf('.')
            if (dotIdx < 0) continue
            val name = dotKey.substring(0, dotIdx).trim()
            val key = dotKey.substring(dotIdx + 1).trim()
            contacts.getOrPut(name) { mutableMapOf() }[key] = value
        }

        // Serialize canonically (sorted names, sorted keys, quote non-numeric values)
        // Must match Lua's serialize_contacts_canonical() exactly
        val lines = mutableListOf<String>()
        for (name in contacts.keys.sorted()) {
            val fields = contacts[name]!!
            for (key in fields.keys.sorted()) {
                val raw = fields[key]!!
                val v = if (raw.matches(Regex("^\\d+$"))) raw else "\"$raw\""
                lines.add("$name.$key = $v")
            }
            lines.add("")  // blank line after each contact group
        }
        val canonical = lines.joinToString("\n")
        return Crypto.sha256Hex(canonical.toByteArray(Charsets.UTF_8))
    }

    /**
     * Parse the contacts file and return a sorted list of contact names,
     * excluding own-device entries (own = true).
     */
    fun parseContactNames(): List<String> {
        if (!contactsFile.exists()) return emptyList()
        val names = mutableSetOf<String>()
        val ownDevices = mutableSetOf<String>()
        for (line in contactsFile.readText().lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) continue
            val eqIdx = trimmed.indexOf('=')
            if (eqIdx < 0) continue
            val dotKey = trimmed.substring(0, eqIdx).trim()
            val value = trimmed.substring(eqIdx + 1).trim().removeSurrounding("\"")
            val dotIdx = dotKey.indexOf('.')
            if (dotIdx < 0) continue
            val name = dotKey.substring(0, dotIdx).trim()
            val field = dotKey.substring(dotIdx + 1).trim()
            if (name.isNotEmpty()) names.add(name)
            if (field == "own" && value == "true") ownDevices.add(name)
        }
        return (names - ownDevices).sorted()
    }

    // ── Attachments cache ──────────────────────────────────────────────────

    fun cachedAttachmentFile(filename: String): File = File(attachments, filename)

    fun isAttachmentCached(filename: String): Boolean =
        File(attachments, filename).exists()
}
