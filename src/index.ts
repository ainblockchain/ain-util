import BN from 'bn.js'
import * as rlp from 'rlp'
import { encode as encodeVarInt } from 'varuint-bitcoin'
import assert from 'assert'
const createKeccakHash = require('keccak')
const secp256k1 = require('secp256k1')
const Buffer = require('safe-buffer').Buffer
const SIGNED_MESSAGE_PREFIX = 'AINetwork Signed Message:\n'
const SIGNED_MESSAGE_PREFIX_BYTES = Buffer.from(SIGNED_MESSAGE_PREFIX, 'utf8')
const SIGNED_MESSAGE_PREFIX_LENGTH = encodeVarInt(SIGNED_MESSAGE_PREFIX.length)
const TX_FIELDS = [{
    name: 'nonce',
    length: 32,
    allowLess: true,
    default: Buffer.from([])
  },
  {
    name: 'to',
    allowZero: true,
    length: 20,
    default: Buffer.from([])
  }, {
    name: 'value',
    length: 32,
    allowLess: true,
    default: Buffer.from([])
  }, {
    name: 'data',
    allowZero: true,
    default: Buffer.from([])
  }, {
    name: 'v',
    allowZero: true,
    default: Buffer.from([0x1c])
  }, {
    name: 'r',
    length: 32,
    allowZero: true,
    allowLess: true,
    default: Buffer.from([])
  }, {
    name: 's',
    length: 32,
    allowZero: true,
    allowLess: true,
    default: Buffer.from([])
  }]

export interface ECDSASignature {
  v: number
  r: Buffer
  s: Buffer
}

export interface Field {
  name: string,
  length?: number,
  allowLess?: boolean,
  allowZero?: boolean,
  default: any
}

/**
 * Adds "0x" to a given `string` if it does not already start with "0x".
 * @param {string} str
 * @returns {string}
 */
export const addHexPrefix = function(str: string): string {
  return isHexPrefixed(str) ? str : '0x' + str
}

/**
 * Converts a `Buffer` into a hex `string`.
 * @param {Buffer} buf
 * @returns {string}
 */
export const bufferToHex = function(buf: Buffer): string {
  buf = toBuffer(buf)
  return '0x' + buf.toString('hex')
}

// TODO: decrypt(ciphertext, privateKey)

/**
 * Signs a message with a private key and returns a `string` signature.
 * @param {Buffer|Array|string|number} message
 * @param {Buffer} privateKey
 * @param {number} chainId
 * @returns {string}
 */
export const ecSignMessage = function(
  message: any,
  privateKey: Buffer,
  chainId?: number
): string {
  const hashedMsg = hashMessage(message)
  const signature = ecSignHash(hashedMsg, privateKey, chainId)

  return bufferToHex(Buffer.concat([
    toBuffer(hashedMsg),
    setLength(signature.r, 32),
    setLength(signature.s, 32),
    toBuffer(signature.v)
  ]))
}

/**
 * Checks if the signature is valid.
 * @param {Buffer|Array|string|number} message
 * @param {string} signature signature of the `message`
 * @param {string} publicKey
 * @param {number} chainId
 * @returns {boolean}
 */
export const ecVerifySig = function(
  message: any,
  signature: string,
  publicKey: string,
  chainId?: number
): boolean {
  const sigBuffer = toBuffer(signature)
  const len = sigBuffer.length
  const lenHash = len - 65
  const hashedMsg = sigBuffer.slice(0, lenHash)
  if (!hashedMsg.equals(hashMessage(message))) {
    return false
  }

  const sig = ecSplitSig(sigBuffer.slice(lenHash, len))
  const pub = ecRecoverPub(hashedMsg, sig.r, sig.s, sig.v, chainId)
  if (!secp256k1.verify(hashedMsg, sigBuffer.slice(lenHash, len-1), toBuffer(pub))) {
    return false
  }

  const addr = bufferToHex(pubToAddress(pub.slice(1)))
  if (toChecksumAddress(publicKey) === toChecksumAddress(addr)) {
    return true
  } else {
    return false
  }
}

// TODO: ecSignTransaction(txData, privateKey, chainId?)

// TODO: encrypt(plaintext, publicKey)

/**
 * Returns the bitcoin's varint encoding of keccak-256 hash of `message`,
 * prefixed with the header 'AINetwork Signed Message:\n'.
 * @param {Buffer|Array|string|number} message
 * @returns {Buffer}
 */
export const hashMessage = function(message: any): Buffer {
  const msgBytes = toBuffer(message)
  const msgLenBytes = encodeVarInt(message.length)
	const dataBytes = Buffer.concat(
		[
			SIGNED_MESSAGE_PREFIX_LENGTH,
			SIGNED_MESSAGE_PREFIX_BYTES,
			msgLenBytes,
			msgBytes,
		],
	)

  return keccak(keccak(dataBytes))
}

/**
 * Checks whether the `str` is prefixed with "0x"
 * @param {string} str
 * @return {boolean}
 * @throws if the str input is not a string
 */
export const isHexPrefixed = function(str: string): boolean {
  if (typeof str !== 'string') {
    throw new Error('[ain-util] isHexPrefixed: Input is not a string')
  }

  return str.slice(0, 2) === '0x'
}

/**
 * Checks whether the `privateKey` is a valid private key (follows the rules of
 * the curve secp256k1).
 * @param {Buffer} privateKey
 * @returns {boolean}
 */
export const isValidPrivate = function(privateKey: Buffer): boolean {
  return secp256k1.privateKeyVerify(privateKey)
}

/**
 * Checks where the `publicKey` is a valid public key (follows the rules of the
 * curve secp256k1 and meets the AIN requirements).
 * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
 * @param {boolean} isSEC1 Accept public keys in other formats
 * @returns {boolean}
 */
export const isValidPublic = function(publicKey: Buffer, isSEC1: boolean = false): boolean {
  if (publicKey.length === 64) {
    // Convert to SEC1 for secp256k1
    return secp256k1.publicKeyVerify(Buffer.concat([Buffer.from([4]), publicKey]))
  }

  if (!isSEC1) {
    return false
  }

  return secp256k1.publicKeyVerify(publicKey)
}

/**
 * Creates Keccak hash of the input
 * @param {Buffer|Array|string|number} input
 * @param {number} bits The Keccak width
 * @returns {Buffer}
 */
export const keccak = function(input: any, bits: number = 256): Buffer {
  input = toBuffer(input)
  if (!bits) bits = 256

  return createKeccakHash(`keccak${bits}`)
    .update(input)
    .digest()
}

/**
 * Returns the AI Network address of a given public key.
 * @param {Buffer} publicKey AIN public key | SEC1 encoded public key
 * @param {boolean} isSEC1 Key is SEC1 encoded
 * @returns {Buffer} lower 160 bits of the hash of `publicKey`
 */
export const pubToAddress = function(publicKey: Buffer, isSEC1: boolean = false): Buffer {
  publicKey = toBuffer(publicKey)
  if (isSEC1 && publicKey.length !== 64) {
    publicKey = secp256k1.publicKeyConvert(publicKey, false).slice(1)
  }
  assert(publicKey.length === 64)
  return keccak(publicKey).slice(-20)
}

/**
 * Serialize an object (e.g. tx data) using rlp encoding.
 * @param {string|Buffer|Array|Object} data
 * @param {Array<Field>} _fields
 * @returns {Buffer}
 * @throws if the data is invalid or the number of fields doesn't match
 */
 export const serialize = function(data: any, _fields?: Array<Field>): Buffer {
   if (!data) {
     throw new Error('[ain-util] serialize: Invalid data')
   }
   if (!_fields) {
     _fields = TX_FIELDS
   }

   let input = []

   if (typeof data === 'string') {
    data = Buffer.from(stripHexPrefix(data), 'hex')
  }

  if (Buffer.isBuffer(data)) {
    data = rlp.decode(data)
  }

  if (Array.isArray(data)) {
    if (data.length > _fields.length) {
      throw new Error('[ain-util] serialize: Wrong number of fields in data')
    }

    // make sure all the items are buffers
    data.forEach((d, i) => {
      input[i] = toBuffer(d)
    })
  } else if (typeof data === 'object') {
    const keys = Object.keys(data)
    for(let i = 0; i < _fields.length; i++) {
      let field = _fields[i]
      if (keys.indexOf(field.name) !== -1) {
        let val = toBuffer(data[field.name])
        if (val.toString('hex') === '00' && !field.allowZero) {
          val = Buffer.allocUnsafe(0)
        }

        if (field.allowLess && field.length) {
          val = unpad(val)
          assert(
            field.length >= val.length,
            `The field ${field.name} must not have more ${field.length} bytes`,
          )
        } else if (!(field.allowZero && val.length === 0) && field.length) {
          assert(
            field.length === val.length,
            `The field ${field.name} must have byte length of ${field.length}`,
          )
        }

        input[i] = val
      }
    }
  } else {
    throw new Error('[ain-util] serialize: Invalid data')
  }

   return rlp.encode(input)
 }

/**
 * Pads and `message` with leading zeros till it has `length` bytes.
 * Truncates from the beginning if `message` is longer than `length`.
 * @param {Buffer|Array} message
 * @param {number} length the number of bytes the output should be
 * @param {boolean} right whether to start padding form the left or right
 * @return {Buffer|Array}
 */
export const setLength = function(
  message: any,
  length: number,
  right: boolean = false
): Buffer {
  const buf = zeros(length)
  message = toBuffer(message)
  if (right) {
    if (message.length < length) {
      message.copy(buf)
      return buf
    }
    return message.slice(0, length)
  } else {
    if (message.length < length) {
      message.copy(buf, length - message.length)
      return buf
    }
    return message.slice(-length)
  }
}

/**
 * Removes '0x' from a given `String` is present
 * @param {string} str the string value
 * @return {string}
 */
export const stripHexPrefix = function(str: string): string {
  if (typeof str !== 'string') {
    return str;
  }

  return isHexPrefixed(str) ? str.slice(2) : str
}

/**
 * Attempts to turn a value into a `Buffer`. As input it supports `Buffer`,
 * `String`, `Number`, null/undefined, `BN` and other objects with a
 * `toArray()` method.
 * @param {Buffer|Array|string|number} v
 * @returns {Buffer}
 */
export const toBuffer = function(v: any): Buffer {
  if (!Buffer.isBuffer(v)) {
    if (Array.isArray(v)) {
      v = Buffer.from(v)
    } else if (typeof v === 'string') {
      if (isHexString(v)) {
        v = Buffer.from(padToEven(stripHexPrefix(v)), 'hex')
      } else {
        v = Buffer.from(v)
      }
    } else if (typeof v === 'number') {
      v = intToBuffer(v)
    } else if (v === null || v === undefined) {
      v = Buffer.allocUnsafe(0)
    } else if (BN.isBN(v)) {
      v = v.toArrayLike(Buffer)
    } else if (v.toArray) {
      // converts a BN to a Buffer
      v = Buffer.from(v.toArray())
    } else {
      throw new Error('[ain-util] toBuffer: Invalid type')
    }
  }
  return v
}

/**
 * Returns a checksummed address.
 * @param {string} address
 * @returns {string}
 */
export const toChecksumAddress = function(address: string): string {
  address = stripHexPrefix(address).toLowerCase()
  const hash = keccak(address).toString('hex')
  let ret = '0x'

  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase()
    } else {
      ret += address[i]
    }
  }

  return ret
}



// Internal functions



/**
 *
 */
function calculateSigRecovery(v: number, chainId?: number): number {
  return chainId ? v - (2 * chainId + 35) : v - 27
}

/**
 * ECDSA public key recovery from signature.
 * @returns Recovered public key
 */
function ecRecoverPub(
  msgHash: Buffer,
  r: Buffer,
  s: Buffer,
  v: number,
  chainId?: number,
): Buffer {
  const signature = Buffer.concat([setLength(r, 32), setLength(s, 32)], 64)
  const recovery = calculateSigRecovery(v, chainId)
  if (!isValidSigRecovery(recovery)) {
    throw new Error('[ain-util] ecRecoverPub: Invalid signature v value')
  }
  const senderPubKey = secp256k1.recover(msgHash, signature, recovery)
  return secp256k1.publicKeyConvert(senderPubKey, false)
}

/**
 * Returns the ECDSA signature of a message hash.
 */
function ecSignHash(
  msgHash: Buffer,
  privateKey: Buffer,
  chainId?: number,
): ECDSASignature {
  const sig = secp256k1.sign(msgHash, privateKey)
  const recovery: number = sig.recovery

  const ret = {
    r: sig.signature.slice(0, 32),
    s: sig.signature.slice(32, 64),
    v: chainId ? recovery + (chainId * 2 + 35) : recovery + 27
  }

  return ret
}

/**
 * Convert signature format of the `eth_sign` RPC method to signature parameters
 */
function ecSplitSig(signature: Buffer): ECDSASignature {
  const buf: Buffer = toBuffer(signature)
  if (buf.length !== 65) {
    throw new Error('[ain-util] ecSplitSig: Invalid signature length')
  }

  return {
    v: buf[64],
    r: buf.slice(0, 32),
    s: buf.slice(32, 64)
  }
}

/**
 * Converts an `Number` to a `Buffer`
 * @param {Number} i
 * @return {Buffer}
 */
function intToBuffer(i: number): Buffer {
  var hex = intToHex(i)

  return Buffer.from(padToEven(hex.slice(2)), 'hex')
}

/**
 * Converts a `Number` into a hex `String`
 * @param {Number} i
 * @return {String}
 */
function intToHex(i: number): string {
  var hex = i.toString(16) // eslint-disable-line

  return '0x' + hex
}

/**
 * Is the string a hex string.
 *
 * @method check if string is hex string of specific length
 * @param {String} value
 * @param {Number} length
 * @returns {Boolean} output the string is a hex string
 */
function isHexString(value: string, length?: number): boolean {
  if (!value.match(/^0x[0-9A-Fa-f]*$/)) {
    return false
  }

  if (length && value.length !== 2 + 2 * length) {
    return false
  }

  return true
}

/**
 *
 */
function isValidSigRecovery(recovery: number): boolean {
  return recovery === 0 || recovery === 1
}

/**
 * Pads a `String` to have an even length
 * @param {String} value
 * @return {String} output
 */
function padToEven(value: string): string {
  if (typeof value !== 'string') {
    throw new Error('[ain-util] padToEven: Value must be string, but is currently ' + typeof value);
  }

  return value.length % 2 ? `0${value}` : value
}

/**
 */
function unpad(a: any) {
  a = stripHexPrefix(a)
  let first = a[0]
  while (a.length > 0 && first.toString() === '0') {
    a = a.slice(1)
    first = a[0]
  }
  return a
}

/**
 * Returns a buffer filled with 0s.
 * @param bytes the number of bytes the buffer should be
 */
function zeros(bytes: number): Buffer {
  return Buffer.allocUnsafe(bytes).fill(0)
}
