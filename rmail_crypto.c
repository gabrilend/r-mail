/*
 * rmail_crypto.c — AES-256-GCM encryption for rmail
 *
 * Exposes four functions to Lua:
 *
 *   crypto.sha256(str)                         -> 32-byte binary string
 *   crypto.random_bytes(n)                     -> n random bytes
 *   crypto.aes_gcm_encrypt(key32, nonce12, pt) -> ciphertext..tag (len+16 bytes)
 *   crypto.aes_gcm_decrypt(key32, nonce12, ct) -> plaintext or nil (auth failure)
 *
 * Packet format used by rmail:
 *   [4-byte big-endian length] [12-byte nonce] [ciphertext] [16-byte GCM tag]
 *
 * The framing and trial-decryption loop live in rmail.lua; this file is
 * purely the cryptographic primitives.
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <lua.h>
#include <lauxlib.h>

/* sha256(str) -> 32-byte binary string */
static int l_sha256(lua_State *L)
{
    size_t len;
    const unsigned char *data = (const unsigned char *)luaL_checklstring(L, 1, &len);
    unsigned char hash[32];
    unsigned int hash_len = 32;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    lua_pushlstring(L, (char *)hash, 32);
    return 1;
}

/* random_bytes(n) -> n cryptographically random bytes */
static int l_random_bytes(lua_State *L)
{
    int n = (int)luaL_checkinteger(L, 1);
    if (n <= 0 || n > 4096)
        return luaL_error(L, "random_bytes: n must be 1..4096");

    unsigned char *buf = (unsigned char *)malloc(n);
    if (!buf)
        return luaL_error(L, "random_bytes: out of memory");

    if (RAND_bytes(buf, n) != 1) {
        free(buf);
        return luaL_error(L, "random_bytes: RAND_bytes failed");
    }

    lua_pushlstring(L, (char *)buf, (size_t)n);
    free(buf);
    return 1;
}

/*
 * aes_gcm_encrypt(key32, nonce12, plaintext)
 *   -> ciphertext concatenated with 16-byte GCM auth tag
 *
 * key must be exactly 32 bytes (AES-256).
 * nonce must be exactly 12 bytes.
 * Returns a string of length #plaintext + 16.
 */
static int l_aes_gcm_encrypt(lua_State *L)
{
    size_t key_len, nonce_len, pt_len;
    const unsigned char *key   = (const unsigned char *)luaL_checklstring(L, 1, &key_len);
    const unsigned char *nonce = (const unsigned char *)luaL_checklstring(L, 2, &nonce_len);
    const unsigned char *pt    = (const unsigned char *)luaL_checklstring(L, 3, &pt_len);

    if (key_len != 32 || nonce_len != 12)
        return luaL_error(L, "aes_gcm_encrypt: key must be 32 bytes, nonce must be 12 bytes");

    /* output buffer: ciphertext (same length as plaintext) + 16-byte tag */
    unsigned char *out = (unsigned char *)malloc(pt_len + 16);
    if (!out)
        return luaL_error(L, "aes_gcm_encrypt: out of memory");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int update_len = 0, final_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_EncryptUpdate(ctx, out, &update_len, pt, (int)pt_len);
    EVP_EncryptFinal_ex(ctx, out + update_len, &final_len);
    /* tag must be retrieved after EncryptFinal */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + update_len + final_len);
    EVP_CIPHER_CTX_free(ctx);

    lua_pushlstring(L, (char *)out, (size_t)(update_len + final_len + 16));
    free(out);
    return 1;
}

/*
 * aes_gcm_decrypt(key32, nonce12, ciphertext_with_tag)
 *   -> plaintext string, or nil if authentication fails
 *
 * ciphertext_with_tag is ciphertext followed by the 16-byte GCM tag
 * (as produced by aes_gcm_encrypt).
 * Returns nil on any error (wrong key, tampered ciphertext, bad lengths).
 */
static int l_aes_gcm_decrypt(lua_State *L)
{
    size_t key_len, nonce_len, input_len;
    const unsigned char *key   = (const unsigned char *)luaL_checklstring(L, 1, &key_len);
    const unsigned char *nonce = (const unsigned char *)luaL_checklstring(L, 2, &nonce_len);
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 3, &input_len);

    if (key_len != 32 || nonce_len != 12 || input_len < 16) {
        lua_pushnil(L);
        return 1;
    }

    size_t ct_len = input_len - 16;

    /* tag is the last 16 bytes; SET_TAG needs a non-const pointer */
    unsigned char tag[16];
    memcpy(tag, input + ct_len, 16);

    unsigned char *pt = (unsigned char *)malloc(ct_len + 1); /* +1 for safety */
    if (!pt)
        return luaL_error(L, "aes_gcm_decrypt: out of memory");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int update_len = 0, final_len = 0, auth_ok = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_DecryptUpdate(ctx, pt, &update_len, input, (int)ct_len);
    /* set expected tag before calling DecryptFinal */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    /* DecryptFinal returns 1 on auth success, 0 on failure */
    auth_ok = EVP_DecryptFinal_ex(ctx, pt + update_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (auth_ok == 1) {
        lua_pushlstring(L, (char *)pt, (size_t)(update_len + final_len));
    } else {
        lua_pushnil(L);
    }
    free(pt);
    return 1;
}

int luaopen_rmail_crypto(lua_State *L)
{
    lua_newtable(L);
    lua_pushcfunction(L, l_sha256);          lua_setfield(L, -2, "sha256");
    lua_pushcfunction(L, l_random_bytes);    lua_setfield(L, -2, "random_bytes");
    lua_pushcfunction(L, l_aes_gcm_encrypt); lua_setfield(L, -2, "aes_gcm_encrypt");
    lua_pushcfunction(L, l_aes_gcm_decrypt); lua_setfield(L, -2, "aes_gcm_decrypt");
    return 1;
}
