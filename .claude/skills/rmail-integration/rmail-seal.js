// rmail-seal.js — seal one rmail message inside a web page and send it to a mailbox
//
// Written by hand (2026-10-08) as the reference for "a contact's own page"
// in SKILL.md beside this file; checked against a real daemon by
// r-mail/scripts/test-browser-sealer.sh, which runs it under Node 18+
// (the same WebCrypto and fetch a browser has).
//
// What it does, for a non-programmer: rmail only accepts messages locked
// with a key both sides share.  This file builds that locked message in
// the browser, using the browser's own built-in AES-GCM lock, and sends
// it as the body of an ordinary web POST -- the only way a web page can
// send anything.  The rmail daemon unwraps the POST and reads the locked
// message exactly as if another mailbox had sent it.
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

// {{{ async function keyFromToken
// The 32-byte AES key both sides derive from the shared token.
export async function keyFromToken(token) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
// }}}

// {{{ async function sealRequest
// One request, sealed into one frame (a Uint8Array).
export async function sealRequest(key, method, path, bodyText) {
    const enc   = new TextEncoder();
    const body  = enc.encode(bodyText);
    const head  = enc.encode(method + " " + path + " HTTP/1.1\r\nContent-Length: " +
                             body.length + "\r\n\r\n");
    const plain = new Uint8Array(head.length + body.length);
    plain.set(head);
    plain.set(body, head.length);
    // WebCrypto's AES-GCM appends the 16-byte tag to the ciphertext, which
    // is the order rmail expects
    const nonce  = crypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain));
    const length = nonce.length + sealed.length;
    const frame  = new Uint8Array(4 + length);
    new DataView(frame.buffer).setUint32(0, length, false);   // false = big-endian
    frame.set(nonce, 4);
    frame.set(sealed, 16);
    return frame;
}
// }}}

// {{{ async function openReply
// The daemon's answer to a sealed request, unsealed: {status, body}.
// Only readable when the page may read the response at all -- see
// sendMessage.  Throws when the answer does not open with this key.
export async function openReply(key, bytes) {
    const frame = new Uint8Array(bytes);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: frame.slice(4, 16) },
                                              key, frame.slice(16));
    const text  = new TextDecoder().decode(plain);
    const split = text.indexOf("\r\n\r\n");
    return { status: Number(text.match(/^HTTP\/\S+ (\d+)/)[1]), body: text.slice(split + 4) };
}
// }}}

// {{{ async function sendMessage
// Deliver one plain message to the mailbox at `url` (e.g.
// "http://127.0.0.1:5555/") as the contact whose token is given.
// `fetchMode` is "no-cors" in a browser: the browser then sends the POST
// without asking the daemon's permission first, and hands back an opaque
// answer -- the page learns only that an answer came, not what it said
// (rmail sends no permission headers).  Tests outside a browser pass
// "cors" to read the answer.
export async function sendMessage(url, token, subject, text, fetchMode = "no-cors") {
    const key   = await keyFromToken(token);
    const body  = JSON.stringify({ type: "message", subject: subject, body: text,
                                   message_id: crypto.randomUUID() });
    const frame = await sealRequest(key, "POST", "/deliver", body);
    const reply = await fetch(url, { method: "POST", mode: fetchMode,
                                     headers: { "Content-Type": "text/plain" }, body: frame });
    return { reply, key };
}
// }}}
