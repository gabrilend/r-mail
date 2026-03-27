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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
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

        Socket().use { sock ->
            sock.connect(java.net.InetSocketAddress(host, port), 5_000)
            sock.soTimeout = 10_000
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
        val mailboxName = obj.optString("mailbox_name").ifBlank { null }
        val mailboxPath = obj.optString("mailbox_path").ifBlank { null }

        return SyncResponse(fetchInbox, removeInbox, fetchOutbox, removeOutbox, contacts,
            mailboxName, mailboxPath)
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
        val obj = JSONObject(body.toString(Charsets.UTF_8))
        val arr = obj.optJSONArray("files") ?: JSONArray()
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
    /**
     * Download an attachment in chunks, streaming directly to a file.
     * Uses parallel downloads (4 concurrent) for speed. Each chunk is a
     * separate encrypted request, so peak memory is ~4 chunks.
     * The server specifies chunk_size in the info response (typically 5MB).
     */
    suspend fun downloadAttachmentChunked(
        filename: String,
        destFile: java.io.File,
        onProgress: ((Long, Long) -> Unit)? = null
    ): Boolean {
        // Step 1: get file info
        val (infoStatus, infoBody) = get("/api/attachments/$filename/info")
        if (infoStatus != 200) throw IOException("Attachment info failed: HTTP $infoStatus")
        val info = JSONObject(infoBody.toString(Charsets.UTF_8))
        val totalSize = info.getLong("size")
        val numChunks = info.getInt("num_chunks")
        val chunkSize = info.optLong("chunk_size", 256L * 1024)

        // Step 2: pre-allocate file
        java.io.RandomAccessFile(destFile, "rw").use { it.setLength(totalSize) }

        // Step 3: download chunks in parallel, write each to its correct offset
        val downloaded = java.util.concurrent.atomic.AtomicLong(0)
        val parallelism = 4
        val semaphore = Semaphore(parallelism)
        val failed = java.util.concurrent.atomic.AtomicBoolean(false)

        coroutineScope {
            for (i in 0 until numChunks) {
                if (failed.get()) break
                semaphore.acquire()
                launch(Dispatchers.IO) {
                    try {
                        if (failed.get()) return@launch
                        val (status, body) = get("/api/attachments/$filename/chunk/$i")
                        if (status != 200) { failed.set(true); return@launch }
                        // Write chunk at its correct file offset
                        java.io.RandomAccessFile(destFile, "rw").use { raf ->
                            raf.seek(i.toLong() * chunkSize)
                            raf.write(body)
                        }
                        val total = downloaded.addAndGet(body.size.toLong())
                        onProgress?.invoke(total, totalSize)
                    } catch (_: Exception) {
                        failed.set(true)
                    } finally {
                        semaphore.release()
                    }
                }
            }
        }

        if (failed.get()) {
            destFile.delete()
            throw IOException("Chunked download failed")
        }
        return true
    }

    data class AddressInfo(val ip: String, val port: Int, val name: String, val lanIp: String)

    /**
     * GET /api/myaddress — returns the daemon's public IP, port, name, and LAN IP
     */
    fun getMyAddress(): AddressInfo? {
        return try {
            val (status, body) = get("/api/myaddress")
            if (status != 200) return null
            val obj = JSONObject(body.toString(Charsets.UTF_8))
            AddressInfo(
                obj.getString("ip"), obj.getInt("port"),
                obj.optString("name", ""), obj.optString("lan_ip", "")
            )
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

        /** Progress phases reported by the upload callback */
        enum class UploadPhase { ZIPPING, SENDING }

        /**
         * Upload a file: compress to a temp zip, then stream chunks to the server.
         * Matches the daemon-to-daemon path: compress first, then chunk the
         * compressed output. Peak memory usage is one chunk (~256KB).
         *
         * @param cacheDir  directory for the temp zip file (e.g. context.cacheDir)
         * @param onProgress called with (phase, bytesProcessed, totalBytes) — totalBytes
         *   is the uncompressed size during ZIPPING, compressed size during SENDING.
         *   May be called frequently; callers should throttle UI updates.
         */
        suspend fun uploadFileCompressed(
            client: RmailClient,
            filename: String,
            inputStream: java.io.InputStream,
            fileSize: Long,
            cacheDir: java.io.File,
            onProgress: ((UploadPhase, Long, Long) -> Unit)? = null
        ): String? {
            val zipFile = java.io.File(cacheDir, "rmail-upload-${System.currentTimeMillis()}.zip")
            try {
                // Step 1: compress
                var bytesRead = 0L
                java.util.zip.ZipOutputStream(zipFile.outputStream().buffered()).use { zos ->
                    zos.putNextEntry(java.util.zip.ZipEntry(filename))
                    val buf = ByteArray(65536)
                    var n: Int
                    while (inputStream.read(buf).also { n = it } > 0) {
                        zos.write(buf, 0, n)
                        bytesRead += n
                        onProgress?.invoke(UploadPhase.ZIPPING, bytesRead, fileSize)
                    }
                    zos.closeEntry()
                }

                // Step 2: stream compressed chunks to server
                val compressedSize = zipFile.length()
                val numChunks = ((compressedSize + CHUNK_SIZE - 1) / CHUNK_SIZE).toInt()
                val start = client.uploadStart(filename, numChunks) ?: return null
                var bytesSent = 0L

                zipFile.inputStream().buffered().use { fis ->
                    val chunkBuf = ByteArray(CHUNK_SIZE)
                    for (i in 0 until numChunks) {
                        var read = 0
                        while (read < CHUNK_SIZE) {
                            val r = fis.read(chunkBuf, read, CHUNK_SIZE - read)
                            if (r <= 0) break
                            read += r
                        }
                        val chunk = if (read == CHUNK_SIZE) chunkBuf else chunkBuf.copyOf(read)
                        if (!client.uploadChunk(start.uploadId, i, chunk)) return null
                        bytesSent += read
                        onProgress?.invoke(UploadPhase.SENDING, bytesSent, compressedSize)
                    }
                }
                return start.serverPath
            } finally {
                zipFile.delete()
            }
        }
    }
}
