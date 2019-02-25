"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const bn_js_1 = __importDefault(require("bn.js"));
const rlp = __importStar(require("rlp"));
const varuint_bitcoin_1 = require("varuint-bitcoin");
const assert_1 = __importDefault(require("assert"));
const createKeccakHash = require('keccak');
const secp256k1 = require('secp256k1');
const Buffer = require('safe-buffer').Buffer;
const SIGNED_MESSAGE_PREFIX = 'AINetwork Signed Message:\n';
const SIGNED_MESSAGE_PREFIX_BYTES = Buffer.from(SIGNED_MESSAGE_PREFIX, 'utf8');
const SIGNED_MESSAGE_PREFIX_LENGTH = varuint_bitcoin_1.encode(SIGNED_MESSAGE_PREFIX.length);
const TX_FIELDS = [{
        name: 'nonce',
        length: 32,
        allowLess: true,
        default: new Buffer([])
    }, {
        name: 'gasPrice',
        length: 32,
        allowLess: true,
        default: new Buffer([])
    }, {
        name: 'gasLimit',
        length: 32,
        allowLess: true,
        default: new Buffer([])
    }, {
        name: 'to',
        allowZero: true,
        length: 20,
        default: new Buffer([])
    }, {
        name: 'value',
        length: 32,
        allowLess: true,
        default: new Buffer([])
    }, {
        name: 'data',
        allowZero: true,
        default: new Buffer([])
    }, {
        name: 'v',
        allowZero: true,
        default: new Buffer([0x1c])
    }, {
        name: 'r',
        length: 32,
        allowZero: true,
        allowLess: true,
        default: new Buffer([])
    }, {
        name: 's',
        length: 32,
        allowZero: true,
        allowLess: true,
        default: new Buffer([])
    }];
/**
 * Adds "0x" to a given `string` if it does not already start with "0x".
 * @param {string} str
 * @returns {string}
 */
exports.addHexPrefix = function (str) {
    return exports.isHexPrefixed(str) ? str : '0x' + str;
};
/**
 * Converts a `Buffer` into a hex `string`.
 * @param {Buffer} buf
 * @returns {string}
 */
exports.bufferToHex = function (buf) {
    buf = exports.toBuffer(buf);
    return '0x' + buf.toString('hex');
};
// TODO: decrypt(ciphertext, privateKey)
/**
 * Signs a message with a private key and returns a `string` signature.
 * @param {Buffer|Array|string|number} message
 * @param {Buffer} privateKey
 * @param {number} chainId
 * @returns {string}
 */
exports.ecSignMessage = function (message, privateKey, chainId) {
    console.log("==== ecSignMessage ====");
    const hashedMsg = exports.hashMessage(message);
    console.log("hashedMsg:", hashedMsg);
    const signature = ecSignHash(hashedMsg, privateKey, chainId);
    console.log("signature:", signature);
    return exports.bufferToHex(Buffer.concat([
        exports.toBuffer(hashedMsg),
        exports.setLength(signature.r, 32),
        exports.setLength(signature.s, 32),
        exports.toBuffer(signature.v)
    ]));
};
/**
 * Checks if the signature is valid.
 * @param {Buffer|Array|string|number} message
 * @param {string} signature signature of the `message`
 * @param {string} publicKey
 * @param {number} chainId
 * @returns {boolean}
 */
exports.ecVerifySig = function (message, signature, publicKey, chainId) {
    console.log("==== ecVerifySig ====");
    console.log("signature:", signature);
    const sigBuffer = exports.toBuffer(signature);
    const len = sigBuffer.length;
    const lenHash = len - 65;
    const hashedMsg = sigBuffer.slice(0, lenHash);
    if (!hashedMsg.equals(exports.hashMessage(message))) {
        console.log("hashMessage(message):", exports.hashMessage(message));
        return false;
    }
    const sig = ecSplitSig(sigBuffer.slice(lenHash, len));
    console.log("sig:", sig);
    const pub = ecRecoverPub(hashedMsg, sig.r, sig.s, sig.v, chainId);
    console.log("pub:", pub);
    if (!secp256k1.verify(hashedMsg, sigBuffer.slice(lenHash, len - 1), exports.toBuffer(pub))) {
        console.log("invalid signature");
        return false;
    }
    const addr = exports.bufferToHex(exports.pubToAddress(pub.slice(1)));
    console.log("addr:", addr);
    if (exports.toChecksumAddress(publicKey) === exports.toChecksumAddress(addr)) {
        return true;
    }
    else {
        console.log("toChecksumAddress(addr):", exports.toChecksumAddress(addr));
        return false;
    }
};
// TODO: ecSignTransaction(txData, privateKey, chainId?)
// TODO: encrypt(plaintext, publicKey)
/**
 * Returns the bitcoin's varint encoding of keccak-256 hash of `message`,
 * prefixed with the header 'AINetwork Signed Message:\n'.
 * @param {Buffer|Array|string|number} message
 * @returns {Buffer}
 */
exports.hashMessage = function (message) {
    console.log("==== hashMessage ====");
    console.log("message:", message);
    const msgBytes = exports.toBuffer(message);
    console.log("msgBytes:", msgBytes);
    const msgLenBytes = varuint_bitcoin_1.encode(message.length);
    console.log("msgLenBytes:", msgLenBytes);
    const dataBytes = Buffer.concat([
        SIGNED_MESSAGE_PREFIX_LENGTH,
        SIGNED_MESSAGE_PREFIX_BYTES,
        msgLenBytes,
        msgBytes,
    ]);
    console.log("dataBytes:", dataBytes);
    return exports.keccak(exports.keccak(dataBytes));
};
/**
 * Checks whether the `str` is prefixed with "0x"
 * @param {string} str
 * @return {boolean}
 * @throws if the str input is not a string
 */
exports.isHexPrefixed = function (str) {
    if (typeof str !== 'string') {
        throw new Error('isHexPrefixed: input is not a string');
    }
    return str.slice(0, 2) === '0x';
};
/**
 * Checks whether the `privateKey` is a valid private key (follows the rules of
 * the curve secp256k1).
 * @param {Buffer} privateKey
 * @returns {boolean}
 */
exports.isValidPrivate = function (privateKey) {
    return secp256k1.privateKeyVerify(privateKey);
};
/**
 * Checks where the `publicKey` is a valid public key (follows the rules of the
 * curve secp256k1 and meets the AIN requirements).
 * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
 * @param {boolean} isSEC1 Accept public keys in other formats
 * @returns {boolean}
 */
exports.isValidPublic = function (publicKey, isSEC1 = false) {
    if (publicKey.length === 64) {
        // Convert to SEC1 for secp256k1
        return secp256k1.publicKeyVerify(Buffer.concat([Buffer.from([4]), publicKey]));
    }
    if (!isSEC1) {
        return false;
    }
    return secp256k1.publicKeyVerify(publicKey);
};
/**
 * Creates Keccak hash of the input
 * @param {Buffer|Array|string|number} input
 * @param {number} bits The Keccak width
 * @returns {Buffer}
 */
exports.keccak = function (input, bits = 256) {
    input = exports.toBuffer(input);
    if (!bits)
        bits = 256;
    return createKeccakHash(`keccak${bits}`)
        .update(input)
        .digest();
};
/**
 * Returns the AI Network address of a given public key.
 * @param {Buffer} publicKey AIN public key | SEC1 encoded public key
 * @param {boolean} isSEC1 Key is SEC1 encoded
 * @returns {Buffer} lower 160 bits of the hash of `publicKey`
 */
exports.pubToAddress = function (publicKey, isSEC1 = false) {
    publicKey = exports.toBuffer(publicKey);
    if (isSEC1 && publicKey.length !== 64) {
        publicKey = secp256k1.publicKeyConvert(publicKey, false).slice(1);
    }
    assert_1.default(publicKey.length === 64);
    return exports.keccak(publicKey).slice(-20);
};
/**
 * Serialize an object (e.g. tx data) using rlp encoding.
 * @param {string|Buffer|Array|Object} data
 * @param {Array<Field>} _fields
 * @returns {Buffer}
 * @throws if the data is invalid or the number of fields doesn't match
 */
exports.serialize = function (data, _fields) {
    if (!data) {
        throw new Error('invalid data');
    }
    if (!_fields) {
        _fields = TX_FIELDS;
    }
    let input = [];
    if (typeof data === 'string') {
        data = Buffer.from(exports.stripHexPrefix(data), 'hex');
    }
    if (Buffer.isBuffer(data)) {
        data = rlp.decode(data);
    }
    if (Array.isArray(data)) {
        if (data.length > _fields.length) {
            throw new Error('wrong number of fields in data');
        }
        // make sure all the items are buffers
        data.forEach((d, i) => {
            input[i] = exports.toBuffer(d);
        });
    }
    else if (typeof data === 'object') {
        const keys = Object.keys(data);
        for (let i = 0; i < _fields.length; i++) {
            let field = _fields[i];
            if (keys.indexOf(field.name) !== -1) {
                let val = exports.toBuffer(data[field.name]);
                if (val.toString('hex') === '00' && !field.allowZero) {
                    val = Buffer.allocUnsafe(0);
                }
                if (field.allowLess && field.length) {
                    val = unpad(val);
                    assert_1.default(field.length >= val.length, `The field ${field.name} must not have more ${field.length} bytes`);
                }
                else if (!(field.allowZero && val.length === 0) && field.length) {
                    assert_1.default(field.length === val.length, `The field ${field.name} must have byte length of ${field.length}`);
                }
                input[i] = val;
            }
        }
    }
    else {
        throw new Error('invalid data');
    }
    return rlp.encode(input);
};
/**
 * Pads and `message` with leading zeros till it has `length` bytes.
 * Truncates from the beginning if `message` is longer than `length`.
 * @param {Buffer|Array} message
 * @param {number} length the number of bytes the output should be
 * @param {boolean} right whether to start padding form the left or right
 * @return {Buffer|Array}
 */
exports.setLength = function (message, length, right = false) {
    const buf = zeros(length);
    message = exports.toBuffer(message);
    if (right) {
        if (message.length < length) {
            message.copy(buf);
            return buf;
        }
        return message.slice(0, length);
    }
    else {
        if (message.length < length) {
            message.copy(buf, length - message.length);
            return buf;
        }
        return message.slice(-length);
    }
};
/**
 * Removes '0x' from a given `String` is present
 * @param {string} str the string value
 * @return {string}
 */
exports.stripHexPrefix = function (str) {
    return exports.isHexPrefixed(str) ? str.slice(2) : str;
};
/**
 * Attempts to turn a value into a `Buffer`. As input it supports `Buffer`,
 * `String`, `Number`, null/undefined, `BN` and other objects with a
 * `toArray()` method.
 * @param {Buffer|Array|string|number} v
 * @returns {Buffer}
 */
exports.toBuffer = function (v) {
    if (!Buffer.isBuffer(v)) {
        if (Array.isArray(v)) {
            v = Buffer.from(v);
        }
        else if (typeof v === 'string') {
            if (isHexString(v)) {
                v = Buffer.from(padToEven(exports.stripHexPrefix(v)), 'hex');
            }
            else {
                v = Buffer.from(v);
            }
        }
        else if (typeof v === 'number') {
            v = intToBuffer(v);
        }
        else if (v === null || v === undefined) {
            v = Buffer.allocUnsafe(0);
        }
        else if (bn_js_1.default.isBN(v)) {
            v = v.toArrayLike(Buffer);
        }
        else if (v.toArray) {
            // converts a BN to a Buffer
            v = Buffer.from(v.toArray());
        }
        else {
            throw new Error('invalid type');
        }
    }
    return v;
};
/**
 * Returns a checksummed address.
 * @param {string} address
 * @returns {string}
 */
exports.toChecksumAddress = function (address) {
    address = exports.stripHexPrefix(address).toLowerCase();
    const hash = exports.keccak(address).toString('hex');
    let ret = '0x';
    for (let i = 0; i < address.length; i++) {
        if (parseInt(hash[i], 16) >= 8) {
            ret += address[i].toUpperCase();
        }
        else {
            ret += address[i];
        }
    }
    return ret;
};
// Internal functions
/**
 *
 */
function calculateSigRecovery(v, chainId) {
    console.log("==== calculateSigRecovery ====");
    console.log("v:", v, "chainId:", chainId);
    return chainId ? v - (2 * chainId + 35) : v - 27;
}
/**
 * ECDSA public key recovery from signature.
 * @returns Recovered public key
 */
function ecRecoverPub(msgHash, r, s, v, chainId) {
    console.log("==== ecRecoverPub ====");
    const signature = Buffer.concat([exports.setLength(r, 32), exports.setLength(s, 32)], 64);
    console.log("signature:", signature);
    const recovery = calculateSigRecovery(v, chainId);
    console.log("recovery:", recovery);
    // const recovery = v
    if (!isValidSigRecovery(recovery)) {
        throw new Error('Invalid signature v value');
    }
    const senderPubKey = secp256k1.recover(msgHash, signature, recovery);
    console.log("senderPubKey:", senderPubKey);
    return secp256k1.publicKeyConvert(senderPubKey, false);
    //.slice(1)
}
/**
 * Returns the ECDSA signature of a message hash.
 */
function ecSignHash(msgHash, privateKey, chainId) {
    console.log("==== ecSignHash ====");
    const sig = secp256k1.sign(msgHash, privateKey);
    const recovery = sig.recovery;
    console.log("sig:", sig);
    const ret = {
        r: sig.signature.slice(0, 32),
        s: sig.signature.slice(32, 64),
        v: chainId ? recovery + (chainId * 2 + 35) : recovery + 27,
    };
    return ret;
}
/**
 * Convert signature format of the `eth_sign` RPC method to signature parameters
 */
function ecSplitSig(signature) {
    console.log("==== ecSplitSig ====");
    // TODO: Use secp256k1.signatureImport() that parses a DER encoded ECDSA signature.
    const buf = exports.toBuffer(signature);
    console.log("buf:", buf);
    if (buf.length !== 65) {
        throw new Error('Invalid signature length');
    }
    let v = buf[64];
    // support both versions of `eth_sign` responses
    // if (v < 27) {
    //   v += 27
    // }
    return {
        v: v,
        r: buf.slice(0, 32),
        s: buf.slice(32, 64),
    };
}
/**
 * Converts an `Number` to a `Buffer`
 * @param {Number} i
 * @return {Buffer}
 */
function intToBuffer(i) {
    var hex = intToHex(i);
    return new Buffer(padToEven(hex.slice(2)), 'hex');
}
/**
 * Converts a `Number` into a hex `String`
 * @param {Number} i
 * @return {String}
 */
function intToHex(i) {
    var hex = i.toString(16); // eslint-disable-line
    return '0x' + hex;
}
/**
 * Is the string a hex string.
 *
 * @method check if string is hex string of specific length
 * @param {String} value
 * @param {Number} length
 * @returns {Boolean} output the string is a hex string
 */
function isHexString(value, length) {
    if (!value.match(/^0x[0-9A-Fa-f]*$/)) {
        return false;
    }
    if (length && value.length !== 2 + 2 * length) {
        return false;
    }
    return true;
}
/**
 *
 */
function isValidSigRecovery(recovery) {
    return recovery === 0 || recovery === 1;
}
/**
 * Pads a `String` to have an even length
 * @param {String} value
 * @return {String} output
 */
function padToEven(value) {
    if (typeof value !== 'string') {
        throw new Error('[ain-util] padToEven: value must be string, but is currently ' + typeof value);
    }
    return value.length % 2 ? `0${value}` : value;
}
/**
 */
function unpad(a) {
    a = exports.stripHexPrefix(a);
    let first = a[0];
    while (a.length > 0 && first.toString() === '0') {
        a = a.slice(1);
        first = a[0];
    }
    return a;
}
/**
 * Returns a buffer filled with 0s.
 * @param bytes the number of bytes the buffer should be
 */
function zeros(bytes) {
    return Buffer.allocUnsafe(bytes).fill(0);
}
//# sourceMappingURL=index.js.map