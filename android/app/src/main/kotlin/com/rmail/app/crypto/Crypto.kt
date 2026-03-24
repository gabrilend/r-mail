package com.rmail.app.crypto

import java.io.InputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object Crypto {

    private val rng = SecureRandom()

    /** Derives a 32-byte AES key from the shared token (same as Lua's sha256(token)). */
    fun keyFromToken(token: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(token.toByteArray(Charsets.UTF_8))
    }

    /**
     * Encrypt plaintext with AES-256-GCM.
     * Returns: 12-byte nonce || ciphertext || 16-byte GCM tag
     */
    fun encrypt(plaintext: ByteArray, key: ByteArray): ByteArray {
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        val ciphertextAndTag = cipher.doFinal(plaintext)
        return nonce + ciphertextAndTag
    }

    /**
     * Decrypt AES-256-GCM payload.
     * Input: 12-byte nonce || ciphertext || 16-byte GCM tag
     * Returns plaintext on success, null if auth tag fails (wrong key or tampered data).
     */
    fun decrypt(data: ByteArray, key: ByteArray): ByteArray? {
        if (data.size < 12 + 16) return null
        val nonce = data.copyOfRange(0, 12)
        val ciphertextAndTag = data.copyOfRange(12, data.size)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.doFinal(ciphertextAndTag)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Wrap plaintext into a length-prefixed encrypted frame for sending over TCP.
     * Wire format: [4-byte big-endian length][nonce+ciphertext+tag]
     * The length field contains the size of everything after it.
     */
    fun encryptFrame(plaintext: ByteArray, key: ByteArray): ByteArray {
        val payload = encrypt(plaintext, key)
        val len = payload.size
        return byteArrayOf(
            (len shr 24).toByte(),
            (len shr 16).toByte(),
            (len shr 8).toByte(),
            len.toByte()
        ) + payload
    }

    /**
     * Read and decrypt one length-prefixed frame from an InputStream.
     * Returns decrypted plaintext, or null if decryption fails.
     * Throws IOException on read errors.
     */
    fun decryptFrame(input: InputStream, key: ByteArray): ByteArray? {
        val lenBuf = input.readNBytes(4)
        if (lenBuf.size < 4) return null
        val length = ((lenBuf[0].toInt() and 0xFF) shl 24) or
                     ((lenBuf[1].toInt() and 0xFF) shl 16) or
                     ((lenBuf[2].toInt() and 0xFF) shl 8) or
                     (lenBuf[3].toInt() and 0xFF)
        if (length < 12 + 16) return null
        val payload = input.readNBytes(length)
        if (payload.size < length) return null
        return decrypt(payload, key)
    }

    /** SHA-256 hex string — used for contacts hash. */
    fun sha256Hex(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data).joinToString("") { "%02x".format(it) }
    }
}
