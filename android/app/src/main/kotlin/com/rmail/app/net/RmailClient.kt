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

class ChecksumMismatchException(message: String) : IOException(message)

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

    // ── Persistent connection ───────────────────────────────────────────────
    // Reuses a single TCP connection for multiple requests. Reconnects
    // transparently if the connection is dead. The server supports keep-alive
    // via its coroutine event loop.

    private var sock: Socket? = null
    private var sockOut: java.io.OutputStream? = null
    private var sockInp: java.io.InputStream? = null

    @Synchronized
    private fun ensureConnected() {
        if (sock != null && sock!!.isConnected && !sock!!.isClosed) return
        sock?.close()
        val s = Socket()
        s.connect(java.net.InetSocketAddress(host, port), 5_000)
        s.soTimeout = 10_000
        sock = s
        sockOut = s.getOutputStream()
        sockInp = s.getInputStream()
    }

    @Synchronized
    fun close() {
        try { sock?.close() } catch (_: Exception) {}
        sock = null; sockOut = null; sockInp = null
    }

    // ── Core transport ─────────────────────────────────────────────────────

    /**
     * Send one request and return (statusCode, body).
     * Reuses the persistent connection. Reconnects once on failure.
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
        val reqBytes = header + body

        // Try on existing connection, reconnect once on failure
        for (attempt in 1..2) {
            try {
                ensureConnected()
                val out = sockOut!!
                val inp = sockInp!!

                out.write(Crypto.encryptFrame(reqBytes, key))
                out.flush()

                val plaintext = Crypto.decryptFrame(inp, key)
                    ?: throw IOException("Decryption failed — wrong token or tampered response")

                val responseText = plaintext.toString(Charsets.ISO_8859_1)
                val headerEnd = responseText.indexOf("\r\n\r\n")
                if (headerEnd < 0) throw IOException("Malformed response: no header/body separator")

                val statusLine = responseText.substring(0, responseText.indexOf("\r\n"))
                val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull()
                    ?: throw IOException("Malformed status line: $statusLine")

                val bodyStart = headerEnd + 4
                val responseBody = plaintext.copyOfRange(bodyStart, plaintext.size)
                return Pair(statusCode, responseBody)
            } catch (e: IOException) {
                close()  // force reconnect on next attempt
                if (attempt == 2) throw e
            }
        }
        throw IOException("request failed after 2 attempts")  // unreachable but satisfies compiler
    }

    internal fun get(path: String): Pair<Int, ByteArray> = request("GET", path)

    private fun post(path: String, json: JSONObject): Pair<Int, ByteArray> =
        request("POST", path, json.toString().toByteArray(Charsets.UTF_8), "application/json")

    private fun post(path: String, body: ByteArray): Pair<Int, ByteArray> =
        request("POST", path, body, "application/octet-stream")

    private fun delete(path: String): Pair<Int, ByteArray> = request("DELETE", path)

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
                category = obj.optString("category", "other"),
                checksum = obj.optString("checksum", "")
            )
        }
    }

    /**
     * GET /api/attachments/<filename>
     */
    /**
     * Download an attachment using the chunk-file model (matching daemon-to-daemon).
     * Each chunk is stored as a separate file in a temp directory. On resume,
     * the directory is scanned for existing chunks — no state file needed.
     * Existing chunks are verified concurrently with downloading missing ones.
     *
     * @param chunksDir directory for per-chunk temp files (e.g. attachments/.downloads/<filename>/)
     */
    suspend fun downloadAttachmentChunked(
        filename: String,
        destFile: java.io.File,
        chunksDir: java.io.File,
        onProgress: ((Long, Long) -> Unit)? = null
    ): Boolean {
        // Step 1: get file info including per-chunk checksums
        val (infoStatus, infoBody) = get("/api/attachments/$filename/info")
        if (infoStatus != 200) throw IOException("Attachment info failed: HTTP $infoStatus")
        val info = JSONObject(infoBody.toString(Charsets.UTF_8))
        val totalSize = info.getLong("size")
        val numChunks = info.getInt("num_chunks")
        val chunkSize = info.optLong("chunk_size", 256L * 1024)
        val fileChecksum = info.optString("file_checksum", "")

        val chunkChecksums = mutableMapOf<Int, String>()
        info.optJSONArray("chunk_checksums")?.let { arr ->
            for (i in 0 until arr.length()) {
                chunkChecksums[i] = arr.optString(i, "")
            }
        }

        // Step 2: scan chunks directory for existing chunks (resume detection)
        chunksDir.mkdirs()
        fun chunkFile(i: Int) = java.io.File(chunksDir, "chunk-%04d.bin".format(i))

        val existingChunks = mutableSetOf<Int>()
        for (i in 0 until numChunks) {
            if (chunkFile(i).exists()) existingChunks.add(i)
        }
        val missingChunks = (0 until numChunks).filter { it !in existingChunks }.toMutableList()

        val downloaded = java.util.concurrent.atomic.AtomicLong(
            existingChunks.sumOf { chunkFile(it).length() })
        onProgress?.invoke(downloaded.get(), totalSize)

        // Step 3: concurrently verify existing chunks AND download missing ones
        val runtime = Runtime.getRuntime()
        val freeHeap = runtime.maxMemory() - (runtime.totalMemory() - runtime.freeMemory())
        val maxConcurrent = ((freeHeap * 0.5) / chunkSize).toInt().coerceIn(2, 64)
        val semaphore = Semaphore(maxConcurrent)
        val failed = java.util.concurrent.atomic.AtomicReference<String?>(null)

        coroutineScope {
            // Verify existing chunks in background — bad chunks get added to download queue
            for (i in existingChunks.toList()) {
                launch(Dispatchers.IO) {
                    val expectedHash = chunkChecksums[i] ?: ""
                    if (expectedHash.isNotBlank()) {
                        val localHash = com.rmail.app.crypto.Crypto.sha256Hex(chunkFile(i).readBytes())
                        if (localHash != expectedHash) {
                            chunkFile(i).delete()
                            synchronized(missingChunks) { missingChunks.add(i) }
                        }
                    }
                }
            }

            // Download missing chunks concurrently
            // Use a snapshot — new entries from failed verification are picked up in a second pass
            val toDownload = synchronized(missingChunks) { missingChunks.toList() }
            for (i in toDownload) {
                kotlinx.coroutines.yield()
                if (failed.get() != null) break

                semaphore.acquire()
                launch(Dispatchers.IO) {
                    try {
                        if (failed.get() != null) return@launch
                        val expectedHash = chunkChecksums[i] ?: ""
                        var chunk: ByteArray? = null

                        for (attempt in 1..3) {
                            val (status, body) = get("/api/attachments/$filename/chunk/$i")
                            if (status != 200) {
                                failed.set("Chunk $i: HTTP $status")
                                return@launch
                            }
                            if (expectedHash.isNotBlank()) {
                                val actualHash = com.rmail.app.crypto.Crypto.sha256Hex(body)
                                if (actualHash == expectedHash) { chunk = body; break }
                            } else {
                                chunk = body; break
                            }
                        }

                        if (chunk == null) {
                            failed.set("Chunk $i failed checksum after 3 retries")
                            return@launch
                        }

                        chunkFile(i).writeBytes(chunk)
                        val total = downloaded.addAndGet(chunk.size.toLong())
                        onProgress?.invoke(total, totalSize)
                    } catch (e: Exception) {
                        if (failed.get() == null) failed.set("Chunk $i: ${e.message}")
                    } finally {
                        semaphore.release()
                    }
                }
            }
        }

        if (failed.get() != null) {
            // Chunks on disk are preserved for resume — no cleanup
            throw IOException("Chunked download failed: ${failed.get()}")
        }

        // Second pass: pick up any chunks that failed verification and were re-queued
        val stillMissing = synchronized(missingChunks) {
            (0 until numChunks).filter { !chunkFile(it).exists() }
        }
        if (stillMissing.isNotEmpty()) {
            // Download the re-queued chunks (from verification failures)
            coroutineScope {
                for (i in stillMissing) {
                    kotlinx.coroutines.yield()
                    launch(Dispatchers.IO) {
                        val expectedHash = chunkChecksums[i] ?: ""
                        for (attempt in 1..3) {
                            val (status, body) = get("/api/attachments/$filename/chunk/$i")
                            if (status != 200) continue
                            if (expectedHash.isNotBlank()) {
                                if (com.rmail.app.crypto.Crypto.sha256Hex(body) == expectedHash) {
                                    chunkFile(i).writeBytes(body)
                                    downloaded.addAndGet(body.size.toLong())
                                    onProgress?.invoke(downloaded.get(), totalSize)
                                    break
                                }
                            } else {
                                chunkFile(i).writeBytes(body)
                                break
                            }
                        }
                    }
                }
            }
        }

        // Step 4: assemble chunks into final file
        destFile.outputStream().buffered().use { out ->
            for (i in 0 until numChunks) {
                val cf = chunkFile(i)
                if (!cf.exists()) throw IOException("Chunk $i missing after download")
                cf.inputStream().use { inp -> inp.copyTo(out) }
            }
        }

        // Step 5: verify whole-file checksum
        if (fileChecksum.isNotBlank()) {
            val localHash = com.rmail.app.crypto.Crypto.sha256HexFile(destFile)
            if (localHash != fileChecksum) {
                // Don't delete chunks — repair can use them
                throw ChecksumMismatchException(
                    "File checksum mismatch after assembly ($localHash != $fileChecksum)")
            }
        }

        // Success — clean up chunk files
        chunksDir.deleteRecursively()
        return true
    }

    /**
     * DELETE /api/attachments/<filename> — delete an attachment from the server.
     */
    fun deleteAttachment(filename: String): Boolean {
        return try {
            val (status, _) = delete("/api/attachments/$filename")
            status == 200
        } catch (_: Exception) { false }
    }

    /**
     * POST /api/log — send a log message to the server's daemon log.
     */
    fun remoteLog(level: String, message: String) {
        try {
            post("/api/log", JSONObject().apply {
                put("level", level)
                put("message", message)
            })
        } catch (_: Exception) {} // best-effort, don't crash if server is unreachable
    }

    data class AddressInfo(val ip: String, val port: Int, val name: String, val lanIp: String, val ipv6: String)

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
                obj.optString("name", ""), obj.optString("lan_ip", ""),
                obj.optString("ipv6", "")
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

    data class UploadResumeResult(val uploadId: String, val serverPath: String, val missing: List<Int>)

    /**
     * POST /api/upload/resume — resume an interrupted upload.
     * Server responds with upload_id, server_path, and list of missing chunk indices.
     */
    fun uploadResume(filename: String, numChunks: Int, chunkChecksums: Map<Int, String>): UploadResumeResult? {
        return try {
            val body = JSONObject().apply {
                put("filename", filename)
                put("num_chunks", numChunks)
                val cs = JSONObject()
                chunkChecksums.forEach { (k, v) -> cs.put(k.toString(), v) }
                put("chunk_checksums", cs)
            }
            val (status, respBody) = post("/api/upload/resume", body)
            if (status != 200) return null
            val obj = JSONObject(respBody.toString(Charsets.UTF_8))
            val missing = mutableListOf<Int>()
            obj.optJSONArray("missing")?.let { arr ->
                for (i in 0 until arr.length()) missing.add(arr.getInt(i))
            }
            UploadResumeResult(obj.getString("upload_id"), obj.getString("server_path"), missing)
        } catch (_: Exception) { null }
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
         * Upload a file using the chunk-file model with resume support.
         * Compress to zip → chunk into files → send checksums to server →
         * upload only chunks the server doesn't have.
         *
         * @param chunksDir directory for chunk temp files (persists for resume)
         * @param cacheDir directory for the temp zip file
         */
        suspend fun uploadFileCompressed(
            client: RmailClient,
            filename: String,
            inputStream: java.io.InputStream?,
            fileSize: Long,
            cacheDir: java.io.File,
            chunksDir: java.io.File,
            onProgress: ((UploadPhase, Long, Long) -> Unit)? = null
        ): String? {
            chunksDir.mkdirs()
            fun chunkFile(i: Int) = java.io.File(chunksDir, "chunk-%04d.bin".format(i))

            // Step 1: check if chunks already exist (resume from previous zip+chunk)
            val existingChunks = chunksDir.listFiles()?.filter {
                it.name.startsWith("chunk-") && it.name.endsWith(".bin")
            }?.size ?: 0

            var numChunks: Int
            var compressedSize: Long

            if (existingChunks > 0) {
                // Resume: chunks already on disk from previous attempt
                numChunks = existingChunks
                compressedSize = (0 until numChunks).sumOf { chunkFile(it).length() }
            } else if (inputStream != null) {
                // Fresh upload: compress to zip, then split into chunk files
                val zipFile = java.io.File(cacheDir, "rmail-upload-${System.currentTimeMillis()}.zip")
                try {
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

                    // Split zip into chunk files
                    compressedSize = zipFile.length()
                    numChunks = ((compressedSize + CHUNK_SIZE - 1) / CHUNK_SIZE).toInt()
                    zipFile.inputStream().buffered().use { fis ->
                        val chunkBuf = ByteArray(CHUNK_SIZE)
                        for (i in 0 until numChunks) {
                            var read = 0
                            while (read < CHUNK_SIZE) {
                                val r = fis.read(chunkBuf, read, CHUNK_SIZE - read)
                                if (r <= 0) break
                                read += r
                            }
                            chunkFile(i).writeBytes(
                                if (read == CHUNK_SIZE) chunkBuf else chunkBuf.copyOf(read))
                        }
                    }
                } finally {
                    zipFile.delete()
                }
            } else {
                return null  // no input and no cached chunks
            }

            // Step 2: compute per-chunk checksums
            val checksums = mutableMapOf<Int, String>()
            for (i in 0 until numChunks) {
                checksums[i] = com.rmail.app.crypto.Crypto.sha256Hex(chunkFile(i).readBytes())
            }

            // Step 3: ask server which chunks are missing (resume-aware)
            val resume = client.uploadResume(filename, numChunks, checksums) ?: return null
            val missing = resume.missing

            // Step 4: upload only missing chunks
            var bytesSent = (numChunks - missing.size).toLong() * CHUNK_SIZE
            onProgress?.invoke(UploadPhase.SENDING, bytesSent, compressedSize)

            for (i in missing) {
                val data = chunkFile(i).readBytes()
                if (!client.uploadChunk(resume.uploadId, i, data)) return null
                bytesSent += data.size
                onProgress?.invoke(UploadPhase.SENDING, bytesSent, compressedSize)
            }

            // Success — clean up chunk files
            chunksDir.deleteRecursively()
            return resume.serverPath
        }
    }
}
