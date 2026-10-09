// rmail-seal.js — seal one rmail message inside a web page and send it to a mailbox
//
// Written by hand (2026-10-08) as the delivery script of the
// rmail-integration skill (SKILL.md beside this file).  Checked by
// r-mail/scripts/test-browser-sealer.sh: against the standards' published
// answers, against Node's built-in cipher for many message lengths, by a
// real daemon opening what it sealed, and in Firefox on a page that is NOT
// a secure page.
//
// What it does, for a non-programmer: rmail only accepts messages locked
// with a key both sides share.  This file builds that locked message in
// the browser and sends it as the body of an ordinary web POST -- the only
// way a web page can send anything.  The rmail daemon unwraps the POST and
// reads the locked message exactly as if another mailbox had sent it.
//
// WHY THE LOCK IS WRITTEN OUT HERE.  Browsers have AES-GCM and SHA-256
// built in (crypto.subtle), and crypto.randomUUID, but give them only to
// "secure" pages: https, this machine (localhost), or a local file.  A
// page served over plain http from another machine gets neither --
// measured in Firefox from http://192.168.1.100 by the W client session,
// 2026-10-08: isSecureContext false, crypto.subtle and randomUUID
// undefined, only crypto.getRandomValues present.  So this file does the
// arithmetic itself, on every page, secure or not: one way of sealing,
// and one way it can go wrong.  The only thing it takes from the browser
// is randomness (crypto.getRandomValues), which every page gets.
//
// The SHA-256, AES and GCM arithmetic is copied from the W client
// project's docs-seal.js (/mnt/mtwo/games/azeroth-core/custom-client/
// scripts/libs/docs-seal.js, written by that project's session and offered
// for this skill), which follows FIPS 180-4, FIPS 197 and NIST SP 800-38D.
//
// WHOSE TOKEN.  The token passed in is the website's own: the receiving
// mailbox has one contact per website, and that contact may send a plain
// message and nothing else (rmail issue #420, the listen-only contact).
// The token lives in the site's delivery script -- the code that calls
// sendMessage -- not in the page's text.  Anything a browser runs can be
// read by whoever loads the site, so treat it as known to anyone: that is
// why the contact it belongs to can do nothing but deliver a message.  A
// person's token is never put here.
//
// Wire format (rmail.lua, "A frame inside a web request"; docs/protocol.md):
//   frame   = [4-byte big-endian length][12-byte nonce][ciphertext + 16-byte tag]
//   length  = 12 + ciphertext + tag, from 28 bytes to 64 MiB
//   key     = SHA-256 of the token's UTF-8 bytes, exactly as written in
//             the receiver's contacts file (without its quotes)
//   inside  = an HTTP-style request: "POST /deliver HTTP/1.1", a
//             Content-Length header counting BYTES (not characters), a
//             blank line, and a JSON body
//   wrapper = POST with Content-Length = 4 + length, body = the frame
//
// Loaded as a plain <script> (not a module, which a page opened as a file
// cannot load), it offers window.RMAIL_SEAL; under Node, require() returns
// the same object:
//   sendMessage(url, token, subject, text[, fetchMode]) -> fetch's promise
//   sealMessage(token, subject, text) -> the frame, a Uint8Array
//   sha256(bytes), sealGcm(key, nonce, bytes), randomBytes(n), uuid()
// Every "bytes" is a Uint8Array.

(function (root) {
  "use strict";

  // {{{ sha256
  // The 64 round constants: the first 32 bits of the fractional parts of
  // the cube roots of the first 64 primes (FIPS 180-4, 4.2.2).
  var K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(bytes) {
    // Padding: a 1 bit, zeros, then the length in bits as 64 bits, to a
    // multiple of 64 bytes.
    var bitLength = bytes.length * 8;
    var padded = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    var view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000));
    view.setUint32(padded.length - 4, bitLength >>> 0);

    var h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    var w = new Uint32Array(64);
    for (var block = 0; block < padded.length; block += 64) {
      for (var t = 0; t < 16; t++) w[t] = view.getUint32(block + t * 4);
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
      for (t = 0; t < 64; t++) {
        var big1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var choose = (e & f) ^ (~e & g);
        var t1 = (k + big1 + choose + K256[t] + w[t]) >>> 0;
        var big0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var majority = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (big0 + majority) >>> 0;
        k = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
    }
    var out = new Uint8Array(32);
    var outView = new DataView(out.buffer);
    for (var i = 0; i < 8; i++) outView.setUint32(i * 4, h[i]);
    return out;
  }
  // }}}

  // {{{ aes
  // The substitution box, computed rather than typed out: each byte's
  // multiplicative inverse in GF(2^8), then an affine transform (FIPS 197,
  // 5.1.1). p walks every nonzero byte by repeated multiplication by 3,
  // while q walks the inverses by division by 3.
  var SBOX = new Uint8Array(256);
  (function () {
    var p = 1, q = 1;
    function rotl8(x, n) { return ((x << n) | (x >>> (8 - n))) & 0xff; }
    do {
      p = p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0);
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
      if (q & 0x80) q ^= 0x09;
      SBOX[p] = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63;
    } while (p !== 1);
    SBOX[0] = 0x63;
  })();

  function xtime(x) { return ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff; }

  // The 15 round keys of AES-256 as one 240-byte array (FIPS 197, 5.2).
  function expandKey(key) {
    var words = new Uint8Array(240);
    words.set(key);
    var rcon = 1;
    var temp = new Uint8Array(4);
    for (var i = 8; i < 60; i++) {
      for (var j = 0; j < 4; j++) temp[j] = words[(i - 1) * 4 + j];
      if (i % 8 === 0) {
        var first = temp[0];
        temp[0] = SBOX[temp[1]] ^ rcon; temp[1] = SBOX[temp[2]];
        temp[2] = SBOX[temp[3]]; temp[3] = SBOX[first];
        rcon = xtime(rcon);
      } else if (i % 8 === 4) {
        for (j = 0; j < 4; j++) temp[j] = SBOX[temp[j]];
      }
      for (j = 0; j < 4; j++) words[i * 4 + j] = words[(i - 8) * 4 + j] ^ temp[j];
    }
    return words;
  }

  // One 16-byte block through 14 rounds. Bytes are in column order, as the
  // standard lays out its state: byte r + 4c is row r, column c.
  function encryptBlock(roundKeys, input) {
    var s = new Uint8Array(16);
    var t = new Uint8Array(16);
    var i, c, r;
    for (i = 0; i < 16; i++) s[i] = input[i] ^ roundKeys[i];
    for (var round = 1; round <= 14; round++) {
      for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
      for (c = 0; c < 4; c++) {                         // row r moves r columns left
        for (r = 0; r < 4; r++) t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
      }
      if (round < 14) {                                 // the last round has no column mixing
        for (c = 0; c < 4; c++) {
          var a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
          var all = a0 ^ a1 ^ a2 ^ a3;
          s[4 * c]     = a0 ^ all ^ xtime(a0 ^ a1);
          s[4 * c + 1] = a1 ^ all ^ xtime(a1 ^ a2);
          s[4 * c + 2] = a2 ^ all ^ xtime(a2 ^ a3);
          s[4 * c + 3] = a3 ^ all ^ xtime(a3 ^ a0);
        }
      } else {
        s.set(t);
      }
      for (i = 0; i < 16; i++) s[i] ^= roundKeys[round * 16 + i];
    }
    return s;
  }
  // }}}

  // {{{ gcm
  // Multiplication in GF(2^128) as GCM defines it (SP 800-38D, algorithm
  // 1): bits read most significant first, reduced by R = 0xe1 followed by
  // fifteen zero bytes. Values are four 32-bit words, most significant first.
  function gfMultiply(x, y) {
    var z0 = 0, z1 = 0, z2 = 0, z3 = 0;
    var v0 = y[0], v1 = y[1], v2 = y[2], v3 = y[3];
    for (var i = 0; i < 128; i++) {
      if ((x[i >>> 5] >>> (31 - (i & 31))) & 1) { z0 ^= v0; z1 ^= v1; z2 ^= v2; z3 ^= v3; }
      var carry = v3 & 1;
      v3 = (v3 >>> 1) | (v2 << 31);
      v2 = (v2 >>> 1) | (v1 << 31);
      v1 = (v1 >>> 1) | (v0 << 31);
      v0 = v0 >>> 1;
      if (carry) v0 ^= 0xe1000000;
    }
    return [z0 >>> 0, z1 >>> 0, z2 >>> 0, z3 >>> 0];
  }

  function words(block) {
    var v = new DataView(block.buffer, block.byteOffset, 16);
    return [v.getUint32(0), v.getUint32(4), v.getUint32(8), v.getUint32(12)];
  }

  // AES-256-GCM sealing with a 12-byte nonce and no extra authenticated
  // data. Returns the ciphertext followed by the 16-byte tag, the layout
  // rmail (OpenSSL) reads after the nonce.
  function sealGcm(key, nonce, plain) {
    if (key.length !== 32 || nonce.length !== 12) throw new Error("sealGcm wants a 32-byte key and a 12-byte nonce");
    var roundKeys = expandKey(key);
    var hashKey = words(encryptBlock(roundKeys, new Uint8Array(16)));

    var counter = new Uint8Array(16);
    counter.set(nonce);
    counter[15] = 1;                                     // J0: the nonce, then the 32-bit count 1
    var tagMask = encryptBlock(roundKeys, counter);

    var out = new Uint8Array(plain.length + 16);
    var count = 1;
    for (var at = 0; at < plain.length; at += 16) {
      count = (count + 1) >>> 0;                         // only the last 32 bits count up
      new DataView(counter.buffer).setUint32(12, count);
      var stream = encryptBlock(roundKeys, counter);
      for (var i = 0; i < 16 && at + i < plain.length; i++) out[at + i] = plain[at + i] ^ stream[i];
    }

    // The tag: GHASH over the ciphertext (zero-padded to whole blocks),
    // then a block holding the bit lengths of the extra data (0) and of
    // the ciphertext, then masked with the encrypted J0.
    var y = [0, 0, 0, 0];
    var block = new Uint8Array(16);
    for (at = 0; at < plain.length; at += 16) {
      block.fill(0);
      block.set(out.subarray(at, Math.min(at + 16, plain.length)));
      var b = words(block);
      y = gfMultiply([y[0] ^ b[0], y[1] ^ b[1], y[2] ^ b[2], y[3] ^ b[3]], hashKey);
    }
    var bits = plain.length * 8;
    var lengths = [0, 0, Math.floor(bits / 0x100000000), bits >>> 0];
    y = gfMultiply([y[0] ^ lengths[0], y[1] ^ lengths[1], y[2] ^ lengths[2], y[3] ^ lengths[3]], hashKey);

    var tag = new DataView(out.buffer, plain.length, 16);
    for (i = 0; i < 4; i++) tag.setUint32(i * 4, y[i]);
    for (i = 0; i < 16; i++) out[plain.length + i] ^= tagMask[i];
    return out;
  }
  // }}}

  // {{{ randomness
  function randomBytes(n) {
    return root.crypto.getRandomValues(new Uint8Array(n));
  }

  // A version 4 UUID, made here because crypto.randomUUID is another
  // secure-pages-only gift.
  function uuid() {
    var b = randomBytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var hex = Array.prototype.map.call(b, function (x) { return (x < 16 ? "0" : "") + x.toString(16); }).join("");
    return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
  }
  // }}}

  // {{{ sealMessage
  // One plain message as one sealed frame.  The request inside counts its
  // body in bytes (TextEncoder's UTF-8), not characters: "é" is two bytes.
  // A fresh random message_id per message; a replayed frame carries the
  // same id, and rmail treats it as the message it already has.
  function sealMessage(token, subject, text) {
    var enc   = new TextEncoder();
    var body  = enc.encode(JSON.stringify({ type: "message", subject: subject,
                                            body: text, message_id: uuid() }));
    var head  = enc.encode("POST /deliver HTTP/1.1\r\nContent-Length: " + body.length + "\r\n\r\n");
    var plain = new Uint8Array(head.length + body.length);
    plain.set(head);
    plain.set(body, head.length);
    var nonce  = randomBytes(12);
    var sealed = sealGcm(sha256(enc.encode(token)), nonce, plain);
    var length = nonce.length + sealed.length;
    var frame  = new Uint8Array(4 + length);
    new DataView(frame.buffer).setUint32(0, length);     // big-endian
    frame.set(nonce, 4);
    frame.set(sealed, 16);
    return frame;
  }
  // }}}

  // {{{ sendMessage
  // Deliver one plain message to the mailbox at `url` (e.g.
  // "http://203.0.113.5:5555/") as the website whose token is given.
  // `fetchMode` is "no-cors" in a browser: the browser then sends the POST
  // without asking the mailbox's permission first and hands back an opaque
  // answer -- the page learns that an answer came, not what it said
  // (rmail sends no permission header).  A network failure, or a mailbox
  // that refused the frame and closed, rejects the promise.  Tests outside
  // a browser pass "cors" to see the web status.
  function sendMessage(url, token, subject, text, fetchMode) {
    return fetch(url, { method: "POST", mode: fetchMode || "no-cors",
                        headers: { "Content-Type": "text/plain" },
                        body: sealMessage(token, subject, text) });
  }
  // }}}

  var api = { sendMessage: sendMessage, sealMessage: sealMessage, sha256: sha256,
              sealGcm: sealGcm, randomBytes: randomBytes, uuid: uuid };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.RMAIL_SEAL = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
