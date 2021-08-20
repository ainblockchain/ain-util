# ain-util


A collection of utility functions for AI Network (AIN).
The methods and tests have been modified from [ethereumjs-util](https://github.com/ethereumjs/ethereumjs-util) and [ethjs-util](https://github.com/ethjs/ethjs-util).

## Installation
```
npm install @ainblockchain/ain-util
```

## Examples
```
const ainUtil = require('@ainblockchain/ain-util');

const message = { foo: 'bar' };
const privateKey = YOUR_OWN_PRIVATE_KEY;

// Alice generates signature using private key.
const signature = ainUtil.ecSignMessage(JSON.stringify(message), Buffer.from(privateKey, 'hex'));

// Bob verifies the message
const hash = ainUtil.hashMessage(JSON.stringify(message));
const sigBuffer = ainUtil.toBuffer(signature);
const len = sigBuffer.length;
const lenHash = len - 65;
const { r, s, v } = ainUtil.ecSplitSig(sigBuffer.slice(lenHash, len));
const publicKey = ainUtil.ecRecoverPub(Buffer.from(hash, 'hex'), r, s, v);
const address = ainUtil.toChecksumAddress(ainUtil.bufferToHex(ainUtil.pubToAddress(publicKey, publicKey.length === 65)));
const isVerified = ainUtil.ecVerifySig(JSON.stringify(message), signature, address);
// console.log(isVerified);
// will return
// ADDRESS
// true
```

## API

### addHexPrefix(str: string) -> string
Adds "0x" to a given `string` if it does not already start with "0x".

### bufferToHex(buf: Buffer) -> string
Converts a `Buffer` into a hex `string`.

### ecSignMessage(message: any, privateKey: Buffer, chainId?: number) -> string
Signs a message with a private key and returns a `string` signature.

### ecRecoverPub(msgHash: Buffer, r: Buffer, s: Buffer, v: number, chainId?: number) -> Buffer
ECDSA public key recovery from signature.

### ecSplitSig(signature: Buffer) -> ECDSASignature
Converts signature format of the `eth_sign` RPC method to signature parameters.

### ecVerifySig(data: any, signature: string, address: string, chainId?: number) -> boolean
Checks if the signature is valid.

### ecSignTransaction(txData: TransactionBody, privateKey: Buffer, chainId?: number) -> string


### hashTransaction(transaction: TransactionBody | string) -> Buffer


### hashMessage(message: any) -> Buffer
Returns the bitcoin's varint encoding of keccak-256 hash of `message`,
prefixed with the header 'AINetwork Signed Message:\n'.

### isHexPrefixed(str: string) -> boolean
Checks whether the `str` is prefixed with "0x".

### isValidPrivate(privateKey: Buffer) -> boolean
Checks whether the `privateKey` is a valid private key (follows the rules of the curve secp256k1).

### isValidPublic(publicKey: Buffer, isSEC1: boolean = false) -> boolean
Checks whether the `publicKey` is a valid public key (follows the rules of the
curve secp256k1 and meets the AIN requirements).

### isValidAddress(address: string) -> boolean
Checks if the address is valid.

### areSameAddresses(address1: string, address2: string) -> boolean
Checks if the two addresses are the same.

### keccak(input: any, bits: number = 256) -> Buffer
Creates Keccak hash of the input.

### privateToPublic(privateKey: Buffer) -> Buffer
Returns the public key of a given private key.

### pubToAddress(publicKey: Buffer, isSEC1: boolean = false) -> Buffer
Returns the AI Network address of a given public key.

### privateToAccount(privateKey: Buffer) -> Account
Returns an Account with the given private key.

### serialize(data: any, _fields?: Array<Field>) -> Buffer (will deprecated)
Serializes an object (e.g. tx data) using rlp encoding.

### setLength(message: any, length: number, right: boolean = false) -> Buffer
Pads and `message` with leading zeros till it has `length` bytes.
Truncates from the beginning if `message` is longer than `length`.

### stripHexPrefix(str: string) -> string
Removes '0x' from a given `String` is present.

### toBuffer(v: any) -> Buffer
Attempts to turn a value into a `Buffer`. As input it supports `Buffer`,
`String`, `Number`, null/undefined, `BN` and other objects with a `toArray()` method.

### toChecksumAddress(address: string) -> string
Returns a checksummed address.

### encryptWithPublicKey(publicKey: string, message: string) -> Promise<Encrypted>
Encrypts message with publicKey.

### decryptWithPrivateKey(privateKey: string, encrypted: Encrypted | string) -> Promise<string>
Decrypts encrypted data with privateKey.

### createAccount(entropy?: string) -> Account
Creates an account with a given entropy.

### privateToV3Keystore(privateKey: Buffer, password: string, options: V3KeystoreOptions = {}) -> V3Keystore
Converts an account into a V3 Keystore and encrypts it with a password.

### v3KeystoreToPrivate(v3Keystore: V3Keystore | string, password: string) -> Buffer
Returns a private key from a V3 Keystore.

### encode(key: string) -> string


### decode(key: string) -> string


---

## LICENSE

MPL-2.0
