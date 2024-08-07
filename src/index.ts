import BN from 'bn.js';
import * as rlp from 'rlp';
import { encode as encodeVarInt } from 'varuint-bitcoin';
import assert from 'assert';
const createKeccakHash = require('keccak');
const secp256k1 = require('secp256k1');
const HDkey = require('hdkey');
import { mnemonicToSeedSync, validateMnemonic } from 'bip39';
import { encrypt, decrypt } from 'eccrypto';
const stringify = require('fast-json-stable-stringify');
const Buffer = require('safe-buffer').Buffer;
const scrypt = require('scryptsy');
const pbkdf2Sync = require('pbkdf2');
const randomBytes = require('randombytes');
const { createCipheriv, createDecipheriv } = require('browserify-cipher');
const uuid = require('uuid');
// NOTE(platfowner): In AI Network, we decided to use both Ethereum Network's
//                   derivation path ("m/44'/60'/0'/0/") and
//                   its own ("m/44'/412'/0'/0/").
const AIN_HD_DERIVATION_PATH = "m/44'/412'/0'/0/";
const ETH_HD_DERIVATION_PATH = "m/44'/60'/0'/0/";
const SIGNED_MESSAGE_PREFIX = 'AINetwork Signed Message:\n'
const SIGNED_MESSAGE_PREFIX_BYTES = Buffer.from(SIGNED_MESSAGE_PREFIX, 'utf8')
const SIGNED_MESSAGE_PREFIX_LENGTH = encodeVarInt(SIGNED_MESSAGE_PREFIX.length)
const TX_FIELDS = [{
    name: 'nonce',
    length: 32,
    allowLess: true,
    default: Buffer.from([])
  }, {
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
  r: Buffer
  s: Buffer
  v: number
}

export interface Field {
  name: string
  length?: number
  allowLess?: boolean
  allowZero?: boolean
  default: any
}

export interface Encrypted {
  iv: string
  ephemPublicKey: string
  ciphertext: string
  mac: string
}

export interface TransactionBody {
  operation: any
  nonce: number
  timestamp: number
  parent_tx_hash?: string
}

export interface Account {
  address: string;
  private_key: string;
  public_key: string;
}

export interface KdfParams {
  dklen: number,
  salt: string,
  prf?: string,
  c?: number,
  n?: number,
  r?: number,
  p?: number
}

export interface V3KeystoreOptions {
  salt?: string,
  iv?: Buffer,
  kdf?: string,
  dklen?: number,
  c?: number,
  n?: number,
  r?: number,
  p?: number,
  prf?: string,
  cipher?: string,
  uuid?: Buffer
}

export interface V3Keystore {
  version: 3,
  id: string,
  address: string,
  crypto: {
    ciphertext: string,
    cipherparams: {
      iv: string
    },
    cipher: string,
    kdf: string,
    kdfparams: KdfParams,
    mac: string
  }
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
 * ECDSA public key recovery from signature.
 * @returns Recovered public key
 */
export const ecRecoverPub = function(
  msgHash: Buffer,
  r: Buffer,
  s: Buffer,
  v: number,
  chainId?: number
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
 * Converts signature format of the `eth_sign` RPC method to signature parameters.
 * @param {Buffer} signature
 * @returns {ECDSASignature}
 */
export const ecSplitSig = function(signature: Buffer): ECDSASignature {
  const buf: Buffer = toBuffer(signature)
  if (buf.length !== 65) {
    throw new Error('[ain-util] ecSplitSig: Invalid signature length')
  }

  return {
    r: buf.slice(0, 32),
    s: buf.slice(32, 64),
    v: buf[64]
  }
}

/**
 * Checks if the signature is valid.
 * @param {Buffer|Array|string|number} data
 * @param {string} signature signature of the `data`
 * @param {string} address
 * @param {number} chainId
 * @returns {boolean}
 */
export const ecVerifySig = function(
  data: any,
  signature: string,
  address: string,
  chainId?: number
): boolean {
  const sigBuffer = toBuffer(signature)
  const len = sigBuffer.length
  const lenHash = len - 65
  const hashedData = sigBuffer.slice(0, lenHash)
  if (typeof data === 'object' && isTransactionBody(data)) {
    if (!hashedData.equals(hashTransaction(data))) return false
  } else {
    if (!hashedData.equals(hashMessage(data))) return false
  }

  const sig = ecSplitSig(sigBuffer.slice(lenHash, len))
  const pub = ecRecoverPub(hashedData, sig.r, sig.s, sig.v, chainId)
  if (!secp256k1.verify(hashedData, sigBuffer.slice(lenHash, len-1), toBuffer(pub))) {
    return false
  }

  const addr = bufferToHex(pubToAddress(pub.slice(1)))
  return areSameAddresses(address, addr)
}

/**
 * Signs a transaction body with a private key and returns a `string` signature.
 * @param {TransactionBody} txData
 * @param {Buffer} privateKey
 * @param {number} chainId
 * @returns {string}
 */
export const ecSignTransaction = function(
  txData: TransactionBody,
  privateKey: Buffer,
  chainId?: number
): string {
  const hashedTx = hashTransaction(txData)
  const signature = ecSignHash(hashedTx, privateKey, chainId)

  return bufferToHex(Buffer.concat([
    toBuffer(hashedTx),
    setLength(signature.r, 32),
    setLength(signature.s, 32),
    toBuffer(signature.v)
  ]))
}

/**
 * Generates keccak hash using a transaction body.
 * @param {TransactionBody|string} transaction
 * @returns {Buffer}
 */
export const hashTransaction = function(transaction: TransactionBody | string): Buffer {
  const tx = typeof transaction === 'string' ? transaction : stringify(transaction)
  return keccak(keccak(tx))
}

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
 * Checks whether the `str` is prefixed with "0x".
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
 * Checks whether the `publicKey` is a valid public key (follows the rules of the
 * curve secp256k1 and meets the AIN requirements).
 * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
 * @param {boolean} isSEC1 Accept public keys in other formats
 * @returns {boolean}
 */
export const isValidPublic = function(
  publicKey: Buffer,
  isSEC1: boolean = false
): boolean {
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
 * Checks if the address is valid.
 * @param {string} address
 * @returns {boolean}
 */
export const isValidAddress = function(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address)
}

/**
 * Checks if the two addresses are the same.
 * @param {string} address1
 * @param {string} address2
 * @returns {boolean}
 */
 export const areSameAddresses = function(address1: string, address2: string): boolean {
   return toChecksumAddress(address1) === toChecksumAddress(address2);
 }

/**
 * Creates Keccak hash of the input.
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

// TODO(platfowner): Consider replacing privateTo prefixes with privateKeyTo.
/**
 * Returns the public key of a given private key.
 * @param {Buffer} privateKey A private key must be 256 bits wide
 * @return {Buffer}
 */
export const privateToPublic = function(privateKey: Buffer): Buffer {
  privateKey = toBuffer(privateKey);
  // skip the type flag and use the X, Y points
  return secp256k1.publicKeyCreate(privateKey, false).slice(1);
}

/**
 * Returns the AI Network address of a given public key.
 * @param {Buffer} publicKey AIN public key | SEC1 encoded public key
 * @param {boolean} isSEC1 Key is SEC1 encoded
 * @returns {Buffer} lower 160 bits of the hash of `publicKey`
 */
export const pubToAddress = function(
  publicKey: Buffer,
  isSEC1: boolean = false
): Buffer {
  publicKey = toBuffer(publicKey)
  if (isSEC1 && publicKey.length !== 64) {
    publicKey = secp256k1.publicKeyConvert(publicKey, false).slice(1)
  }
  assert(publicKey.length === 64)
  return keccak(publicKey).slice(-20)
}

export const privateToAddress = function(privateKey: Buffer): string {
  return toChecksumAddress(bufferToHex(pubToAddress(privateToPublic(privateKey))))
}

/**
 * Returns an account with the given private key.
 * @param {Buffer} privateKey
 * @return {Account}
 */
export const privateToAccount = function(privateKey: Buffer): Account {
  return {
    address: privateToAddress(privateKey),
    private_key: privateKey.toString('hex'),
    public_key: privateToPublic(privateKey).toString('hex')
  }
}

/**
 * Returns a private key with the given seed.
 * @param {Buffer} seed
 * @param {number} index of the account
 * @param {string} chain to use the derivation path of
 * @return {Buffer}
 */
export const seedToPrivatekey = function(seed: Buffer, index: number = 0, chain: string = 'AIN'): Buffer {
  if (index < 0) {
    throw new Error('[ain-util] seedToPrivatekey: index should be greater than 0');
  }

  const hdkey = HDkey.fromMasterSeed(seed);
  const prefix = chain === 'ETH' ? ETH_HD_DERIVATION_PATH : AIN_HD_DERIVATION_PATH;
  const path = prefix + index;
  const wallet = hdkey.derive(path);

  return wallet.privateKey;
}

/**
 * Returns an account with the given seed.
 * @param {Buffer} seed
 * @param {number} index of the account
 * @param {string} chain to use the derivation path of
 * @return {Account}
 */
export const seedToAccount = function(seed: Buffer, index: number = 0, chain: string = 'AIN'): Account {
  return privateToAccount(seedToPrivatekey(seed, index, chain));
}

/**
 * Returns a randomly generated mnemonic.
 * @return {string}
 */
export { generateMnemonic } from 'bip39';

/**
 * Returns a private key with the given mnemonic.
 * @param {string} mnemonic
 * @param {number} index of the account
 * @param {string} chain to use the derivation path of
 * @return {Buffer}
 */
export const mnemonicToPrivatekey = function(mnemonic: string, index: number = 0, chain: string = 'AIN'): Buffer {
  if (index < 0) {
    throw new Error('[ain-util] mnemonicToPrivatekey: index should be greater than 0');
  }

  if (!validateMnemonic(mnemonic)) {
    throw new Error('[ain-util] mnemonicToPrivatekey: Invalid mnemonic');
  }

  const seed = mnemonicToSeedSync(mnemonic);

  return seedToPrivatekey(seed, index, chain);
}

/**
 * Returns an account with the given mnemonic.
 * @param {string} mnemonic
 * @param {number} index of the account
 * @param {string} chain to use the derivation path of
 * @return {Account}
 */
export const mnemonicToAccount = function(mnemonic: string, index: number = 0, chain: string = 'AIN'): Account {
  return privateToAccount(mnemonicToPrivatekey(mnemonic, index, chain));
}

// TODO: deprecate this method (serialize)
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

   let input: Buffer[] = []

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
 * Removes '0x' from a given `String` is present.
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
      v = numToBuffer(v)
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
  if (!isValidAddress(address)) {
    throw new Error('[ain-util] toChecksumAddress: Invalid address')
  }
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

/**
 * Encrypts message with publicKey.
 * @param {string} publicKey
 * @param {string} message
 * @returns {Encrypted}
 */
export const encryptWithPublicKey = function(
  publicKey: string,
  message: string
): Promise<Encrypted> {
  // ensure its an uncompressed publicKey
  publicKey = decompress(publicKey)
  // re-add the compression-flag
  const pubString = '04' + publicKey

  return encrypt(Buffer.from(pubString, 'hex'), Buffer.from(message))
    .then(encryptedBuffers => {
      const encrypted = {
          iv: encryptedBuffers.iv.toString('hex'),
          ephemPublicKey: encryptedBuffers.ephemPublicKey.toString('hex'),
          ciphertext: encryptedBuffers.ciphertext.toString('hex'),
          mac: encryptedBuffers.mac.toString('hex')
        }
      return encrypted
    })
}

/**
 * Decrypts encrypted data with privateKey.
 * @param {string} privateKey
 * @param {string} encrypted
 * @returns {string}
 */
export const decryptWithPrivateKey = function(
  privateKey: string,
  encrypted: Encrypted | string
): Promise<string> {
  const parsed = parseEncryption(encrypted)
  // remove trailing '0x' from privateKey
  const twoStripped = removeTrailing0x(privateKey)
  const encryptedBuffer = {
      iv: Buffer.from(parsed.iv, 'hex'),
      ephemPublicKey: Buffer.from(parsed.ephemPublicKey, 'hex'),
      ciphertext: Buffer.from(parsed.ciphertext, 'hex'),
      mac: Buffer.from(parsed.mac, 'hex')
  }

  return decrypt(Buffer.from(twoStripped, 'hex'), encryptedBuffer)
    .then(decryptedBuffer => decryptedBuffer.toString())
}

/**
 * Creates an account with a given entropy.
 * @param {string} entropy
 * @return {Account}
 */
export const createAccount = function(entropy?: string): Account {
  const innerHex = keccak(concatHexPrefixed(randomBytes(32), !!entropy ? Buffer.from(entropy) : randomBytes(32)));
  const middleHex = concatHexPrefixed(concatHexPrefixed(randomBytes(32), innerHex), randomBytes(32));
  const privateKey = keccak(middleHex);
  return privateToAccount(privateKey);
}

/**
 * Converts an account into a V3 Keystore and encrypts it with a password.
 * @param {Buffer} privateKey
 * @param {string} password
 * @param {V3KeystoreOptions} options
 * @return {V3Keystore}
 */
export const privateToV3Keystore = function (
  privateKey: Buffer,
  password: string,
  options: V3KeystoreOptions = {}
): V3Keystore {
  const salt = options.salt || randomBytes(32);
  const iv = options.iv || randomBytes(16);
  let derivedKey: Buffer;
  const kdf = options.kdf || 'scrypt';
  const kdfparams: KdfParams = { dklen: options.dklen || 32, salt: salt.toString('hex') };
  if (kdf === 'pbkdf2') {
    kdfparams.c = options.c || 262144;
    kdfparams.prf = 'hmac-sha256';
    derivedKey = pbkdf2Sync(
        Buffer.from(password),
        Buffer.from(kdfparams.salt, 'hex'),
        kdfparams.c,
        kdfparams.dklen,
        'sha256'
      );
  } else if (kdf === 'scrypt') {
    kdfparams.n = options.n || 262144; // 2048 4096 8192 16384
    kdfparams.r = options.r || 8;
    kdfparams.p = options.p || 1;
    derivedKey = scrypt(
        Buffer.from(password),
        Buffer.from(kdfparams.salt, 'hex'),
        kdfparams.n,
        kdfparams.r,
        kdfparams.p,
        kdfparams.dklen,
      );
  } else {
    throw new Error('[ain-util] privateToV3Keystore: Unsupported kdf');
  }
  const cipher = createCipheriv(options.cipher || 'aes-128-ctr', derivedKey.slice(0, 16), iv);
  if (!cipher) {
    throw new Error('[ain-util] privateToV3Keystore: Unsupported cipher');
  }
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(privateKey, 'hex')),
    cipher.final()
  ]);
  const mac = keccak(Buffer.concat([derivedKey.slice(16, 32), ciphertext]))
      .toString('hex').replace('0x', '');
  const address = privateToAddress(privateKey);
  return {
    version: 3,
    id: uuid.v4({random: options.uuid || randomBytes(16)}),
    address: address.toLowerCase().replace('0x', ''),
    crypto: {
      ciphertext: ciphertext.toString('hex'),
      cipherparams: {
        iv: iv.toString('hex')
      },
      cipher: options.cipher || 'aes-128-ctr',
      kdf,
      kdfparams,
      mac
    }
  };
}

/**
 * Returns a private key from a V3 Keystore.
 * @param {V3Keystore | string} v3Keystore
 * @param {string} password
 * @return {Buffer}
 */
export const v3KeystoreToPrivate = function(
  v3Keystore: V3Keystore | string,
  password: string
): Buffer {
  let json: V3Keystore = (typeof v3Keystore === 'string') ?
      JSON.parse(v3Keystore.toLowerCase()) : v3Keystore;
  if (json.version !== 3) {
      throw new Error('[ain-util] v3KeystoreToPrivate: Not a valid V3 wallet');
  }
  let derivedKey: Buffer;
  let kdfparams: KdfParams;
  if (json.crypto.kdf === 'scrypt') {
    kdfparams = json.crypto.kdfparams;
    derivedKey = scrypt(
        Buffer.from(password),
        Buffer.from(kdfparams.salt, 'hex'),
        kdfparams.n,
        kdfparams.r,
        kdfparams.p,
        kdfparams.dklen
      );
  } else if (json.crypto.kdf === 'pbkdf2') {
    kdfparams = json.crypto.kdfparams;
    if (kdfparams.prf !== 'hmac-sha256') {
      throw new Error('[ain-util] v3KeystoreToPrivate: Unsupported parameters to PBKDF2');
    }
    derivedKey = pbkdf2Sync(
        Buffer.from(password),
        Buffer.from(kdfparams.salt, 'hex'),
        kdfparams.c,
        kdfparams.dklen,
        'sha256'
      );
  } else {
    throw new Error('[ain-util] v3KeystoreToPrivate: Unsupported key derivation scheme');
  }
  const ciphertext = Buffer.from(json.crypto.ciphertext, 'hex');
  const mac = keccak(Buffer.concat([derivedKey.slice(16, 32), ciphertext]))
      .toString('hex').replace('0x', '');
  if (mac !== json.crypto.mac) {
    throw new Error('[ain-util] v3KeystoreToPrivate: Key derivation failed - possibly wrong password');
  }
  const decipher = createDecipheriv(
      json.crypto.cipher,
      derivedKey.slice(0, 16),
      Buffer.from(json.crypto.cipherparams.iv, 'hex')
    );
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function encode(key: string): string {
  return key.replace(/[\/\.\$\*#\{\}\[\]!]/g, (match) => {
    return `!${match.charCodeAt(0).toString(16).toUpperCase()}`;
  });
}

export function decode(key: string): string {
  return key.replace(/!([0-9a-f]{2})/gi, (match, code) => {
    return String.fromCharCode(parseInt(code, 16));
  });
}


// Internal functions


function concatHexPrefixed(a: Buffer, b: Buffer): Buffer {
  return Buffer.concat([a, b.slice(0, 2).equals(Buffer.from('0x')) ? b.slice(2) : b]);
}

function parseEncryption(encrypted: Encrypted | string): Encrypted {
  if (typeof encrypted !== 'string') return encrypted
  const buf = Buffer.from(encrypted, 'hex')
  const parsed = {
    iv: buf.toString('hex', 0, 16),
    ephemPublicKey: buf.toString('hex', 16, 49),
    mac: buf.toString('hex', 49, 81),
    ciphertext: buf.toString('hex', 81, buf.length)
  }
  // decompress publicKey
  parsed.ephemPublicKey = '04' + decompress(parsed.ephemPublicKey)
  return parsed
}

function decompress(startsWith02Or03: string): string {
  // if already decompressed an not has trailing 04
  const testBuffer = Buffer.from(startsWith02Or03, 'hex')
  if (testBuffer.length === 64) startsWith02Or03 = '04' + startsWith02Or03
  let decompressed = secp256k1.publicKeyConvert(
      Buffer.from(startsWith02Or03, 'hex'), false).toString('hex')
  // remove trailing 04
  decompressed = decompressed.substring(2)
  return decompressed
}

function removeTrailing0x(str: string): string {
  if (str.startsWith('0x')) return str.substring(2)
  else return str
}

/**
 *
 */
function calculateSigRecovery(v: number, chainId?: number): number {
  return chainId ? v - (2 * chainId + 35) : v - 27
}

/**
 * Returns the ECDSA signature of a message hash.
 */
function ecSignHash(
  msgHash: Buffer,
  privateKey: Buffer,
  chainId?: number
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

function isTransactionBody(obj: object | string): obj is TransactionBody {
  let _obj: object;
  if (typeof obj === 'string') {
    _obj = JSON.parse(obj)
  } else {
    _obj = obj;
  }

  return 'nonce' in _obj && 'timestamp' in _obj && 'operation' in _obj
}

/**
 * Converts a float `Number` to a `Buffer`
 * @param {Number} i
 * @return {Buffer}
 */
function floatToBuffer(i: number): Buffer {
  return Buffer.from(new Uint8Array(new Float64Array([i]).buffer,0,8), 'hex');
}

/**
 * Converts an integer `Number` to a `Buffer`
 * @param {Number} i
 * @return {Buffer}
 */
function intToBuffer(i: number): Buffer {
  var hex = intToHex(i);
  return Buffer.from(padToEven(hex.slice(2)), 'hex');
}

/**
 * Converts a `Number` to a `Buffer`
 * @param {Number} i
 * @return {Buffer}
 */
function numToBuffer(i: number): Buffer {
  return Number.isInteger(i) ? intToBuffer(i) : floatToBuffer(i);
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
