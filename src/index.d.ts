/// <reference types="node" />
export interface ECDSASignature {
    v: number;
    r: Buffer;
    s: Buffer;
}
export interface Field {
    name: string;
    length?: number;
    allowLess?: boolean;
    allowZero?: boolean;
    default: any;
}
/**
 * Adds "0x" to a given `string` if it does not already start with "0x".
 * @param {string} str
 * @returns {string}
 */
export declare const addHexPrefix: (str: string) => string;
/**
 * Converts a `Buffer` into a hex `string`.
 * @param {Buffer} buf
 * @returns {string}
 */
export declare const bufferToHex: (buf: Buffer) => string;
/**
 * Signs a message with a private key and returns a `string` signature.
 * @param {Buffer|Array|string|number} message
 * @param {Buffer} privateKey
 * @param {number} chainId
 * @returns {string}
 */
export declare const ecSignMessage: (message: any, privateKey: Buffer, chainId?: number | undefined) => string;
/**
 * Checks if the signature is valid.
 * @param {Buffer|Array|string|number} message
 * @param {string} signature signature of the `message`
 * @param {string} publicKey
 * @param {number} chainId
 * @returns {boolean}
 */
export declare const ecVerifySig: (message: any, signature: string, publicKey: string, chainId?: number | undefined) => boolean;
/**
 * Returns the bitcoin's varint encoding of keccak-256 hash of `message`,
 * prefixed with the header 'AINetwork Signed Message:\n'.
 * @param {Buffer|Array|string|number} message
 * @returns {Buffer}
 */
export declare const hashMessage: (message: any) => Buffer;
/**
 * Checks whether the `str` is prefixed with "0x"
 * @param {string} str
 * @return {boolean}
 * @throws if the str input is not a string
 */
export declare const isHexPrefixed: (str: string) => boolean;
/**
 * Checks whether the `privateKey` is a valid private key (follows the rules of
 * the curve secp256k1).
 * @param {Buffer} privateKey
 * @returns {boolean}
 */
export declare const isValidPrivate: (privateKey: Buffer) => boolean;
/**
 * Checks where the `publicKey` is a valid public key (follows the rules of the
 * curve secp256k1 and meets the AIN requirements).
 * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
 * @param {boolean} isSEC1 Accept public keys in other formats
 * @returns {boolean}
 */
export declare const isValidPublic: (publicKey: Buffer, isSEC1?: boolean) => boolean;
/**
 * Creates Keccak hash of the input
 * @param {Buffer|Array|string|number} input
 * @param {number} bits The Keccak width
 * @returns {Buffer}
 */
export declare const keccak: (input: any, bits?: number) => Buffer;
/**
 * Returns the AI Network address of a given public key.
 * @param {Buffer} publicKey AIN public key | SEC1 encoded public key
 * @param {boolean} isSEC1 Key is SEC1 encoded
 * @returns {Buffer} lower 160 bits of the hash of `publicKey`
 */
export declare const pubToAddress: (publicKey: Buffer, isSEC1?: boolean) => Buffer;
/**
 * Serialize an object (e.g. tx data) using rlp encoding.
 * @param {string|Buffer|Array|Object} data
 * @param {Array<Field>} _fields
 * @returns {Buffer}
 * @throws if the data is invalid or the number of fields doesn't match
 */
export declare const serialize: (data: any, _fields?: Field[] | undefined) => Buffer;
/**
 * Pads and `message` with leading zeros till it has `length` bytes.
 * Truncates from the beginning if `message` is longer than `length`.
 * @param {Buffer|Array} message
 * @param {number} length the number of bytes the output should be
 * @param {boolean} right whether to start padding form the left or right
 * @return {Buffer|Array}
 */
export declare const setLength: (message: any, length: number, right?: boolean) => Buffer;
/**
 * Removes '0x' from a given `String` is present
 * @param {string} str the string value
 * @return {string}
 */
export declare const stripHexPrefix: (str: string) => string;
/**
 * Attempts to turn a value into a `Buffer`. As input it supports `Buffer`,
 * `String`, `Number`, null/undefined, `BN` and other objects with a
 * `toArray()` method.
 * @param {Buffer|Array|string|number} v
 * @returns {Buffer}
 */
export declare const toBuffer: (v: any) => Buffer;
/**
 * Returns a checksummed address.
 * @param {string} address
 * @returns {string}
 */
export declare const toChecksumAddress: (address: string) => string;
