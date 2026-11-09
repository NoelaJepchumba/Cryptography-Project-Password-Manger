
"use strict";

const assert = require("assert");
const { subtle } = require("crypto").webcrypto;

const {
    padPassword,
    unpadPassword,
    encryptPassword,
    decryptPassword
} = require("../password-manager");

describe("Member 1 - Password Security Tests", function () {

    let aesKey;

    before(async function () {
        aesKey = await subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    });

    it("should pad passwords to a fixed length", function () {
        const padded = padPassword("hello123");

        assert.strictEqual(padded.length, 66);
    });

    it("should recover the original password after padding", function () {
        const password = "hello123";

        const padded = padPassword(password);
        const original = unpadPassword(padded);

        assert.strictEqual(original, password);
    });

    it("should reject passwords longer than 64 characters", function () {
        const password = "a".repeat(65);

        assert.throws(() => padPassword(password));
    });

    it("should encrypt and decrypt a password correctly", async function () {
        const encrypted = await encryptPassword(
            aesKey,
            "gmail.com",
            "hello123"
        );

        const decrypted = await decryptPassword(
            aesKey,
            "gmail.com",
            encrypted
        );

        assert.strictEqual(decrypted, "hello123");
    });

    it("should not expose the plaintext password in the encrypted record", async function () {
        const password = "mySecretPassword123";

        const encrypted = await encryptPassword(
            aesKey,
            "gmail.com",
            password
        );

        const serialized = JSON.stringify(encrypted);

        assert.strictEqual(serialized.includes(password), false);
    });

    it("should reject a record decrypted using the wrong domain (AAD)", async function () {
        const encrypted = await encryptPassword(
            aesKey,
            "gmail.com",
            "hello123"
        );

        await assert.rejects(async function () {
            await decryptPassword(
                aesKey,
                "yahoo.com",
                encrypted
            );
        });
    });

    it("should reject tampered ciphertext", async function () {
        const encrypted = await encryptPassword(
            aesKey,
            "gmail.com",
            "hello123"
        );

        const tampered = {
            ...encrypted,
            ciphertext: encrypted.ciphertext.slice(0, -4) + "AAAA"
        };

        await assert.rejects(async function () {
            await decryptPassword(
                aesKey,
                "gmail.com",
                tampered
            );
        });
    });

});
