const crypto = require('crypto').webcrypto;

async function denc(data, password) {
    const raw = Buffer.from(data, 'base64');
    
    // Extract parts: salt, nonce, tag, ciphertext
    const salt = raw.subarray(0, 16);
    const nonce = raw.subarray(16, 32);
    const tag = raw.subarray(32, 48);
    const ciphertext = raw.subarray(48);

    const encoder = new TextEncoder();
    
    // Key material
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    
    // Derive key
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 1000,
            hash: "SHA-1"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );

    // Python pycryptodome appends the tag to the ciphertext when verifying in Web Crypto API
    // WebCrypto expects the ciphertext + tag combined for decrypt.
    const combinedCiphertext = new Uint8Array(ciphertext.length + tag.length);
    combinedCiphertext.set(ciphertext);
    combinedCiphertext.set(tag, ciphertext.length);

    try {
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: nonce
            },
            key,
            combinedCiphertext
        );
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (e) {
        console.error("Decryption failed", e);
        return null;
    }
}

async function run() {
    const pythonOutput = "MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTYTCN/Tj8ZlE3PrJEC6CEtS+ecs11COHtDu";
    const res = await denc(pythonOutput, "test_password");
    console.log("Decrypted:", res);
}

run();
