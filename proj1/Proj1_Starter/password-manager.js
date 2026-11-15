"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

const SALT_LENGTH = 16;
const DERIVED_KEY_LENGTH = 512;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/**
 * Pads a password to a fixed 64-character length.
 * The first two characters store the original password length.
 */
function padPassword(password) {
    if (typeof password !== "string") {
        throw new TypeError("Password must be a string");
    }

    if (password.length > MAX_PASSWORD_LENGTH) {
        throw new Error("Password cannot exceed 64 characters");
    }

    const length = String(password.length).padStart(2, "0");
    const paddedPassword = password.padEnd(MAX_PASSWORD_LENGTH, "\0");

    return length + paddedPassword;
}

/**
 * Removes padding and returns the original password.
 */
function unpadPassword(paddedPassword) {
    const length = Number(paddedPassword.slice(0, 2));

    if (
        !Number.isInteger(length) ||
        length < 0 ||
        length > MAX_PASSWORD_LENGTH ||
        paddedPassword.length !== MAX_PASSWORD_LENGTH + 2
    ) {
        throw new Error("Invalid padded password");
    }

    return paddedPassword.slice(2, 2 + length);
}


/**
 * Encrypts a password using AES-GCM.
 * The domain name is authenticated as additional authenticated data (AAD).
 */
async function encryptPassword(aesKey, domain, password) {
    // Generate a fresh 12-byte initialization vector.
    const iv = getRandomBytes(12);

    // Pad the password before encryption.
    const paddedPassword = padPassword(password);

    // Convert the padded password and domain into buffers.
    const plaintext = stringToBuffer(paddedPassword);
    const additionalData = stringToBuffer(domain);

    // Encrypt using AES-GCM.
    const ciphertext = await subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
            additionalData: additionalData,
            tagLength: 128
        },
        aesKey,
        plaintext
    );

    // Store the IV and ciphertext in Base64 format.
    return {
        iv: encodeBuffer(iv),
        ciphertext: encodeBuffer(ciphertext)
    };
}

/**
 * Decrypts a password using AES-GCM.
 * Authentication fails if the wrong domain is supplied.
 */
async function decryptPassword(aesKey, domain, encryptedRecord) {
    const iv = decodeBuffer(encryptedRecord.iv);
    const ciphertext = decodeBuffer(encryptedRecord.ciphertext);

    const additionalData = stringToBuffer(domain);

    // AES-GCM verifies the authentication tag and AAD.
    const plaintext = await subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
            additionalData: additionalData,
            tagLength: 128
        },
        aesKey,
        ciphertext
    );

    const paddedPassword = bufferToString(plaintext);

    return unpadPassword(paddedPassword);
}


/********* Member 3 helpers: database management ********/

// Fixed label that is HMAC'd with the derived key to check the master password on load.
// Only a keyed MAC of a public constant is stored, never the password or a hash of it.
const PASSWORD_CHECK_LABEL = "keychain-password-check";

/**
 * Computes the lookup key for a domain: Base64(HMAC(hmacKey, domain)).
 * The KVS is indexed by this value, so domain names never appear in the clear.
 */
async function hmacDomain(hmacKey, name) {
    const tag = await subtle.sign("HMAC", hmacKey, stringToBuffer(name));
    return encodeBuffer(tag);
}

/**
 * Computes the password-check tag stored in the serialized keychain.
 */
async function computePasswordCheck(hmacKey) {
    return hmacDomain(hmacKey, PASSWORD_CHECK_LABEL);
}

/**
 * Returns Base64(SHA-256(str)). Used as the rollback/integrity checksum.
 */
async function sha256Base64(str) {
    const digest = await subtle.digest("SHA-256", stringToBuffer(str));
    return encodeBuffer(digest);
}

/**
 * Compares two strings without returning early on the first differing character.
 */
function constantTimeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}


/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
constructor(salt, aesKey, hmacKey, passwordCheck) {
    this.data = {
        salt: encodeBuffer(salt),
        passwordCheck: passwordCheck,
        kvs: {}
    };

    this.secrets = {
        aesKey: aesKey,
        hmacKey: hmacKey
    };
};

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
 
static async init(password) {

    if (typeof password !== "string") {
        throw new TypeError("Password must be a string");
    }

    // Generate a random salt.
    const salt = getRandomBytes(SALT_LENGTH);

    // Derive the AES-GCM and HMAC keys (one PBKDF2 call).
    const { aesKey, hmacKey } = await Keychain.deriveKeys(password, salt);

    // Store a password-check tag so load() can reject a wrong master password.
    const passwordCheck = await computePasswordCheck(hmacKey);

    // Return initialized Keychain.
    return new Keychain(salt, aesKey, hmacKey, passwordCheck);
}

/**
 * Derives the AES-GCM and HMAC keys from the master password and salt.
 * Shared by init() and load(); calls PBKDF2 exactly once.
 * (Key derivation logic written by Member 2, moved here unchanged so load() can reuse it.)
 */
static async deriveKeys(password, salt) {

    // Import the master password.
    const passwordKey = await subtle.importKey(
        "raw",
        stringToBuffer(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    // Derive 512 bits using PBKDF2.
    const derivedBits = await subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        passwordKey,
        DERIVED_KEY_LENGTH
    );

    // Split the derived material into two 256-bit keys.
    const derivedKeyBytes = new Uint8Array(derivedBits);

    const aesKeyBytes = derivedKeyBytes.slice(0, 32);
    const hmacKeyBytes = derivedKeyBytes.slice(32, 64);

    // Import AES-GCM key.
    const aesKey = await subtle.importKey(
        "raw",
        aesKeyBytes,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"]
    );

    // Import HMAC key.
    const hmacKey = await subtle.importKey(
        "raw",
        hmacKeyBytes,
        {
            name: "HMAC",
            hash: "SHA-256"
        },
        false,
        ["sign", "verify"]
    );

    return { aesKey, hmacKey };
}


  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    if (typeof password !== "string" || typeof repr !== "string") {
      throw new TypeError("Password and representation must be strings");
    }

    // 1. Rollback / tampering check against the trusted SHA-256 checksum.
    //    Done first, before anything in repr is trusted or used.
    if (trustedDataCheck !== undefined) {
      const checksum = await sha256Base64(repr);
      if (!constantTimeEqual(checksum, trustedDataCheck)) {
        throw new Error("Integrity check failed: keychain may have been tampered with or rolled back");
      }
    }

    // 2. Parse the serialized keychain.
    let contents;
    try {
      contents = JSON.parse(repr);
    } catch (e) {
      throw new Error("Invalid keychain representation");
    }
    if (!contents || typeof contents.salt !== "string" ||
        typeof contents.passwordCheck !== "string" ||
        typeof contents.kvs !== "object" || contents.kvs === null) {
      throw new Error("Invalid keychain representation");
    }

    // 3. Re-derive the keys from the password and the stored salt (one PBKDF2 call).
    const salt = decodeBuffer(contents.salt);
    const { aesKey, hmacKey } = await Keychain.deriveKeys(password, salt);

    // 4. Verify the master password.
    const expectedCheck = await computePasswordCheck(hmacKey);
    if (!constantTimeEqual(expectedCheck, contents.passwordCheck)) {
      throw new Error("Incorrect password");
    }

    // 5. Rebuild the keychain from the serialized kvs field.
    const keychain = new Keychain(salt, aesKey, hmacKey, contents.passwordCheck);
    keychain.data.kvs = contents.kvs;
    return keychain;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    // Only public data is serialized: salt, password-check tag and the encrypted kvs.
    // The keys in this.secrets are never written out.
    const serialized = JSON.stringify(this.data);
    const checksum = await sha256Base64(serialized);
    return [serialized, checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if (typeof name !== "string") {
      throw new TypeError("Domain name must be a string");
    }

    const lookupKey = await hmacDomain(this.secrets.hmacKey, name);

    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, lookupKey)) {
      return null;
    }

    // Decryption uses the domain as AAD, so a record swapped in from another
    // domain fails authentication and throws (swap-attack defense).
    try {
      return await decryptPassword(this.secrets.aesKey, name, this.data.kvs[lookupKey]);
    } catch (e) {
      throw new Error("Tampering detected: record for this domain failed authentication");
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if (typeof name !== "string" || typeof value !== "string") {
      throw new TypeError("Domain name and value must be strings");
    }

    const lookupKey = await hmacDomain(this.secrets.hmacKey, name);

    // Pads to 64 chars and encrypts with AES-GCM under a fresh IV, binding the domain as AAD.
    // Overwrites the existing record if the domain is already present.
    this.data.kvs[lookupKey] = await encryptPassword(this.secrets.aesKey, name, value);
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if (typeof name !== "string") {
      throw new TypeError("Domain name must be a string");
    }

    const lookupKey = await hmacDomain(this.secrets.hmacKey, name);

    if (Object.prototype.hasOwnProperty.call(this.data.kvs, lookupKey)) {
      delete this.data.kvs[lookupKey];
      return true;
    }
    return false;
  };
};


module.exports = {
    Keychain,
    padPassword,
    unpadPassword,
    encryptPassword,
    decryptPassword
};
