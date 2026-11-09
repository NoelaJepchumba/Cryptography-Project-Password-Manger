"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

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
  constructor() {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
    };

    throw "Not Implemented!";
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    throw "Not Implemented!";
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
    throw "Not Implemented!";
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
    throw "Not Implemented!";
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
    throw "Not Implemented!";
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
    throw "Not Implemented!";
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
    throw "Not Implemented!";
  };
};


module.exports = { Keychain }
module.exports = {
    Keychain,
    padPassword,
    unpadPassword,
    encryptPassword,
    decryptPassword
};
