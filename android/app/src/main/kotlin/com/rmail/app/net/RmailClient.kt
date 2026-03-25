package com.rmail.app.net

import com.rmail.app.crypto.Crypto
import com.rmail.app.data.AttachmentInfo
import com.rmail.app.data.DeletedEntry
import com.rmail.app.data.InboxEntry
import com.rmail.app.data.SyncRequest
import com.rmail.app.data.SyncResponse
import com.rmail.app.data.UploadStartResult
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.Socket

/**
 * Low-level client for the rmail AES-GCM-over-TCP protocol.
 *
 * Every call opens a fresh TCP connection, sends one encrypted HTTP-style request,
 * reads one encrypted response, and closes the socket. This matches the Lua server's
 * single-request-per-connection model.
 *
 * Wire format (both directions):
 *   [4-byte big-endian length][12-byte nonce][ciphertext + 16-byte GCM tag]
 */
class RmailClient(
    private val host: String,
    private val port: Int,
    token: String
) {
    private val key = Crypto.keyFromToken(token)

    // ── Core transport ─────────────────────────────────────────────────────

    /**
     * Send one request and return (statusCode, body).
     * Throws IOException on network errors.
     */
    private fun request(
        method: String,
        path: String,
        body: ByteArray = ByteArray(0),
        contentType: String? = null
    ): Pair<Int, ByteArray> {
        val sb = StringBuilder()
        sb.append("$method $path HTTP/1.0\r\n")
        if (body.isNotEmpty()) {
            if (contentType != null) sb.append("Content-Type: $contentType\r\n")
            sb.append("Content-Length: ${body.size}\r\n")
        }
        sb.append("\r\n")
        val header = sb.toString().toByteArray(Charsets.UTF_8)
        val request = header + body

        Socket(host, port).use { sock ->
            sock.soTimeout = 30_000
            val out = sock.getOutputStream()
            val inp = sock.getInputStream()

            out.write(Crypto.encryptFrame(request, key))
            out.flush()

            val plaintext = Crypto.decryptFrame(inp, key)
                ?: throw IOException("Decryption failed — wrong token or tampered response")

            // Parse HTTP-style response: "HTTP/1.0 200 OK\r\n...\r\n\r\nbody"
            val responseText = plaintext.toString(Charsets.ISO_8859_1)
            val headerEnd = responseText.indexOf("\r\n\r\n")
            if (headerEnd < 0) throw IOException("Malformed response: no header/body separator")

            val statusLine = responseText.substring(0, responseText.indexOf("\r\n"))
            val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull()
                ?: throw IOException("Malformed status line: $statusLine")

            // Body starts after \r\n\r\n — return as raw bytes
            val bodyStart = headerEnd + 4
            val responseBody = plaintext.copyOfRange(bodyStart, plaintext.size)
            return Pair(statusCode, responseBody)
        }
    }

    private fun get(path: String): Pair<Int, ByteArray> = request("GET", path)

    private fun post(path: String, json: JSONObject): Pair<Int, ByteArray> =
        request("POST", path, json.toString().toByteArray(Charsets.UTF_8), "application/json")

    private fun post(path: String, body: ByteArray): Pair<Int, ByteArray> =
        request("POST", path, body, "application/octet-stream")

    private fun put(path: String, body: ByteArray): Pair<Int, ByteArray> =
        request("PUT", path, body, "application/octet-stream")

    // ── API methods ────────────────────────────────────────────────────────

    /**
     * POST /api/sync — core sync manifest exchange.
     */
    fun sync(req: SyncRequest): SyncResponse {
        val body = JSONObject().apply {
            val inboxObj = JSONObject()
            req.inbox.forEach { (id, fn) -> inboxObj.put(id, fn) }
            put("inbox", inboxObj)

            val delInbox = JSONArray()
            req.deletedInbox.forEach { d ->
                delInbox.put(JSONObject().apply {
                    put("message_id", d.messageId)
                    put("from", d.from)
                })
            }
            put("deleted_inbox", delInbox)

            val outboxArr = JSONArray()
            req.outbox.forEach { outboxArr.put(it) }
            put("outbox", outboxArr)

            val delOutbox = JSONArray()
            req.deletedOutbox.forEach { delOutbox.put(it) }
            put("deleted_outbox", delOutbox)

            if (req.contactsHash != null) put("contacts_hash", req.contactsHash)
        }

        val (status, respBody) = post("/api/sync", body)
        if (status != 200) throw IOException("Sync failed: HTTP $status")

        val obj = JSONObject(respBody.toString(Charsets.UTF_8))

        val fetchInbox = mutableMapOf<String, InboxEntry>()
        obj.optJSONArray("fetch_inbox")?.let { arr ->
            for (i in 0 until arr.length()) {
                val e = arr.getJSONObject(i)
                val id = e.getString("message_id")
                fetchInbox[id] = InboxEntry(
                    filename = e.getString("filename"),
                    from = e.optString("from", "")
                )
            }
        }

        val removeInbox = mutableListOf<String>()
        obj.optJSONArray("remove_inbox")?.let { arr ->
            for (i in 0 until arr.length()) removeInbox.add(arr.getString(i))
        }

        val fetchOutbox = mutableListOf<String>()
        obj.optJSONArray("fetch_outbox")?.let { arr ->
            for (i in 0 until arr.length()) fetchOutbox.add(arr.getString(i))
        }

        val removeOutbox = mutableListOf<String>()
        obj.optJSONArray("remove_outbox")?.let { arr ->
            for (i in 0 until arr.length()) removeOutbox.add(arr.getString(i))
        }

        val contacts = obj.optString("contacts").ifBlank { null }

        return SyncResponse(fetchInbox, removeInbox, fetchOutbox, removeOutbox, contacts)
    }

    /**
     * GET /api/file/inbox/<filename> or /api/file/outbox/<filename>
     */
    fun downloadFile(type: String, filename: String): ByteArray {
        val (status, body) = get("/api/file/$type/$filename")
        if (status != 200) throw IOException("Download $type/$filename failed: HTTP $status")
        return body
    }

    /**
     * POST /api/file/outbox/<filename>
     */
    fun uploadOutboxFile(filename: String, content: ByteArray): Boolean {
        val (status, _) = post("/api/file/outbox/$filename", content)
        return status == 200
    }

    /**
     * GET /api/contacts
     */
    fun getContacts(): String {
        val (status, body) = get("/api/contacts")
        if (status != 200) throw IOException("Get contacts failed: HTTP $status")
        return body.toString(Charsets.UTF_8)
    }

    /**
     * POST /api/contacts
     */
    fun postContacts(content: String): Boolean {
        val (status, _) = post("/api/contacts", content.toByteArray(Charsets.UTF_8))
        return status == 200
    }

    /**
     * GET /api/attachments — list attachment metadata
     */
    fun listAttachments(): List<AttachmentInfo> {
        val (status, body) = get("/api/attachments")
        if (status != 200) throw IOException("List attachments failed: HTTP $status")
        val arr = JSONArray(body.toString(Charsets.UTF_8))
        return (0 until arr.length()).map { i ->
            val obj = arr.getJSONObject(i)
            AttachmentInfo(
                filename = obj.getString("filename"),
                size = obj.getLong("size"),
                category = obj.optString("category", "other")
            )
        }
    }

    /**
     * GET /api/attachments/<filename>
     */
    fun downloadAttachment(filename: String): ByteArray {
        val (status, body) = get("/api/attachments/$filename")
        if (status != 200) throw IOException("Download attachment $filename failed: HTTP $status")
        return body
    }

    /**
     * GET /api/myaddress — returns the daemon's public IP and port
     */
    fun getMyAddress(): Pair<String, Int>? {
        return try {
            val (status, body) = get("/api/myaddress")
            if (status != 200) return null
            val obj = JSONObject(body.toString(Charsets.UTF_8))
            Pair(obj.getString("ip"), obj.getInt("port"))
        } catch (_: Exception) {
            null
        }
    }

    /**
     * POST /api/upload/start — begin chunked upload
     */
    fun uploadStart(filename: String, numChunks: Int): UploadStartResult? {
        return try {
            val body = JSONObject().apply {
                put("filename", filename)
                put("num_chunks", numChunks)
            }
            val (status, respBody) = post("/api/upload/start", body)
            if (status != 200) return null
            val obj = JSONObject(respBody.toString(Charsets.UTF_8))
            UploadStartResult(obj.getString("upload_id"), obj.getString("server_path"))
        } catch (_: Exception) {
            null
        }
    }

    /**
     * PUT /api/upload/<id>/chunk/<n> — send one chunk
     */
    fun uploadChunk(uploadId: String, chunkN: Int, data: ByteArray): Boolean {
        return try {
            val (status, _) = put("/api/upload/$uploadId/chunk/$chunkN", data)
            status == 200
        } catch (_: Exception) {
            false
        }
    }

    /**
     * GET /peer-address — query this device's stored IP/port from a contact's daemon.
     * Used for IP recovery when the home server's address has changed.
     * contactToken is the token for the contact whose daemon we're querying.
     */
    fun getPeerAddress(contactToken: String): Pair<String, Int>? {
        return try {
            val contactKey = Crypto.keyFromToken(contactToken)
            // Build the request manually using a different key
            val reqText = "GET /peer-address HTTP/1.0\r\n\r\n"
            Socket(host, port).use { sock ->
                sock.soTimeout = 15_000
                val out = sock.getOutputStream()
                val inp = sock.getInputStream()
                out.write(Crypto.encryptFrame(reqText.toByteArray(), contactKey))
                out.flush()
                val plaintext = Crypto.decryptFrame(inp, contactKey) ?: return null
                val response = plaintext.toString(Charsets.UTF_8)
                val headerEnd = response.indexOf("\r\n\r\n")
                if (headerEnd < 0) return null
                val statusLine = response.substring(0, response.indexOf("\r\n"))
                if (!statusLine.contains(" 200 ")) return null
                val body = response.substring(headerEnd + 4)
                val obj = JSONObject(body)
                Pair(obj.getString("ip"), obj.getInt("port"))
            }
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        const val CHUNK_SIZE = 256 * 1024  // 256 KiB per chunk

        /**
         * Upload a file in chunks. Returns the server path to embed in the outbox file,
         * or null on failure.
         */
        suspend fun uploadFile(
            client: RmailClient,
            filename: String,
            data: ByteArray
        ): String? {
            val numChunks = (data.size + CHUNK_SIZE - 1) / CHUNK_SIZE
            val start = client.uploadStart(filename, numChunks) ?: return null
            for (i in 0 until numChunks) {
                val from = i * CHUNK_SIZE
                val to = minOf(from + CHUNK_SIZE, data.size)
                val ok = client.uploadChunk(start.uploadId, i, data.copyOfRange(from, to))
                if (!ok) return null
            }
            return start.serverPath
        }
    }
}
