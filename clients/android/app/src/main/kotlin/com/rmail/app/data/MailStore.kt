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

    fun writeInbox(filename: String, content: ByteArray, mtimeMs: Long? = null) {
        val f = File(inbox, filename)
        f.writeBytes(content)
        if (mtimeMs != null && mtimeMs > 0) f.setLastModified(mtimeMs)
    }

    fun deleteInbox(filename: String) {
        File(inbox, filename).delete()
    }

    // ── Outbox ─────────────────────────────────────────────────────────────

    fun listOutbox(): List<String> = outbox.listFiles()?.map { it.name }?.sorted() ?: emptyList()

    fun readOutbox(filename: String): String = File(outbox, filename).readText()

    fun writeOutbox(filename: String, content: String, mtimeMs: Long? = null) {
        val f = File(outbox, filename)
        f.writeText(content)
        if (mtimeMs != null && mtimeMs > 0) f.setLastModified(mtimeMs)
    }

    fun deleteOutbox(filename: String) {
        File(outbox, filename).delete()
    }

    fun outboxHash(filename: String): String? {
        val f = File(outbox, filename)
        return if (f.exists()) com.rmail.app.crypto.Crypto.sha256Hex(f.readBytes()) else null
    }

    // ── Attachments waiting to upload ─────────────────────────────────────
    //
    // An attachment is copied here when the message is sent, so the upload
    // can be retried by any later sync.  The picker's content:// grant dies
    // with the app process; a copy of our own does not.

    val pendingAttachments: File = File(root, "pending-attachments").also { it.mkdirs() }

    // ── Files waiting to go to the server ─────────────────────────────────
    //
    // A file added on the phone -- picked in the Files tab, or attached to a
    // message -- is copied into attachments/, where the Files tab shows it,
    // and named here until the next sync uploads it.  Without the list the
    // phone could not tell its own new files from ones it downloaded.

    private val pendingUploadsFile = File(root, "pending-uploads.json")

    fun pendingUploads(): Set<String> = try {
        if (!pendingUploadsFile.exists()) emptySet()
        else JSONArray(pendingUploadsFile.readText()).let { a -> (0 until a.length()).map { a.getString(it) }.toSet() }
    } catch (_: Exception) { emptySet() }

    @Synchronized
    fun setPendingUpload(name: String, pending: Boolean) {
        val now = pendingUploads().let { if (pending) it + name else it - name }
        pendingUploadsFile.writeText(JSONArray(now.sorted()).toString())
    }

    /**
     * A name for a new file in attachments/ that clashes with nothing here
     * or in [taken] (the server's names, when known): photo.jpg, photo-2.jpg…
     * The server makes the final call; this only avoids overwriting a file
     * of ours, or having the checksum repair "fix" it into someone else's.
     */
    fun freeAttachmentName(wanted: String, taken: Set<String> = emptySet()): String {
        val clean = wanted.replace('/', '_').ifBlank { "attachment" }
        val dot = clean.lastIndexOf('.')
        val (stem, ext) = if (dot > 0) clean.substring(0, dot) to clean.substring(dot) else clean to ""
        var n = 1
        while (true) {
            val name = if (n == 1) clean else "$stem-$n$ext"
            if (!File(attachments, name).exists() && name !in taken) return name
            n++
        }
    }

    /**
     * `attach:` values in an outbox file's header that still point at the
     * phone rather than the server.  While any remain, the file is held back
     * from the server: sent early, the body would arrive promising a file
     * the server does not have.
     */
    fun localAttachRefs(filename: String): List<String> {
        val f = File(outbox, filename)
        if (!f.exists()) return emptyList()
        // Same header rule as the daemon's _scan_outbox_header: to:/attach:
        // lines, with blank and // lines passed over, until anything else.
        return f.readLines()
            .takeWhile { line ->
                val l = line.trimStart().lowercase()
                l.isEmpty() || l.startsWith("//") || l.startsWith("to:") || l.startsWith("attach:")
            }
            .mapNotNull { line ->
                if (!line.trimStart().lowercase().startsWith("attach:")) null
                else line.substringAfter(':').trim()
                    .takeIf { it.startsWith("content://") || it.startsWith("file://") }
            }
    }

    fun isHeld(filename: String): Boolean = localAttachRefs(filename).isNotEmpty()

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
            val hashesObj = obj.optJSONObject("outbox_hashes") ?: JSONObject()
            val hashes = hashesObj.keys().asSequence().associateWith { hashesObj.getString(it) }
            SyncState(inboxMap, outboxSet, obj.optString("contacts_hash").ifBlank { null }, hashes)
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
        obj.put("outbox_hashes", JSONObject(state.outboxHashes))
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
