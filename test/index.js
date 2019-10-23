const assert = require('assert')
const utils = require('../dist/index.js')
const BN = require('bn.js')
const {
  address,
  pk,
  sk,
  echash,
  ecprivkey,
  chainId,
  checksumAddresses,
  message,
  correct_signature,
  tx,
  tx_scrambled,
  tx_different
} = require('./test_data.js')

describe('keccak', function () {
  it('should produce a keccak hash', function () {
    const msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    const r = '82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28'
    const hash = utils.keccak(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('keccak without hexprefix', function () {
  it('should produce a hash', function () {
    const msg = '3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    const r = '22ae1937ff93ec72c4d46ff3e854661e3363440acd6f6e4adf8f1a8978382251'
    const hash = utils.keccak(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('pad', function () {
  it('should left pad a Buffer', function () {
    const buf = Buffer.from([9, 9])
    const padded = utils.setLength(buf, 3)
    assert.equal(padded.toString('hex'), '000909')
  })
  it('should left truncate a Buffer', function () {
    const buf = Buffer.from([9, 0, 9])
    const padded = utils.setLength(buf, 2)
    assert.equal(padded.toString('hex'), '0009')
  })
})

describe('bufferToHex', function () {
  it('should convert a buffer to hex', function () {
    const buf = Buffer.from('5b9ac8', 'hex')
    const hex = utils.bufferToHex(buf)
    assert.equal(hex, '0x5b9ac8')
  })
  it('empty buffer', function () {
    const buf = Buffer.alloc(0)
    const hex = utils.bufferToHex(buf)
    assert.strictEqual(hex, '0x')
  })
})

describe('isValidPrivate', function () {
  const SECP256K1_N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)
  it('should fail on short input', function () {
    const tmp = '0011223344'
    assert.equal(utils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on too big input', function () {
    const tmp = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    assert.equal(utils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on invalid curve (zero)', function () {
    const tmp = '0000000000000000000000000000000000000000000000000000000000000000'
    assert.equal(utils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on invalid curve (== N)', function () {
    const tmp = SECP256K1_N.toString(16)
    assert.equal(utils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on invalid curve (>= N)', function () {
    const tmp = SECP256K1_N.addn(1).toString(16)
    assert.equal(utils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should work otherwise (< N)', function () {
    const tmp = SECP256K1_N.subn(1).toString(16)
    assert.equal(utils.isValidPrivate(Buffer.from(tmp, 'hex')), true)
  })
})

describe('isValidPublic', function () {
  it('should fail on too short input', function () {
    const pubKey = Buffer.from('3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744', 'hex')
    assert.equal(utils.isValidPublic(pubKey), false)
  })
  it('should fail on too big input', function () {
    const pubKey = Buffer.from('3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d00', 'hex')
    assert.equal(utils.isValidPublic(pubKey), false)
  })
  it('should fail on SEC1 key', function () {
    const pubKey = Buffer.from('043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d', 'hex')
    assert.equal(utils.isValidPublic(pubKey), false)
  })
  it('shouldn\'t fail on SEC1 key with sanitize enabled', function () {
    const pubKey = Buffer.from('043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d', 'hex')
    assert.equal(utils.isValidPublic(pubKey, true), true)
  })
  it('should fail with an invalid SEC1 public key', function () {
    const pubKey = Buffer.from('023a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d', 'hex')
    assert.equal(utils.isValidPublic(pubKey, true), false)
  })
  it('should work with compressed keys with sanitize enabled', function () {
    const pubKey = Buffer.from('033a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a', 'hex')
    assert.equal(utils.isValidPublic(pubKey, true), true)
  })
  it('should work with sanitize enabled', function () {
    const pubKey = Buffer.from('043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d', 'hex')
    assert.equal(utils.isValidPublic(pubKey, true), true)
  })
  it('should work otherwise', function () {
    const pubKey = Buffer.from('3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d', 'hex')
    assert.equal(utils.isValidPublic(pubKey), true)
  })
})

describe('isValidAddress', function() {
  it('should validate addresses correctly', function() {
    assert.equal(utils.isValidAddress(address), true)
    assert.equal(utils.isValidAddress(address.substring(1, address.length)), false)
  })

  it('should validate non-checksummed addresses', function() {
    assert.equal(utils.isValidAddress('0x' + address.substring(2, address.length).toUpperCase()), true)
    assert.equal(utils.isValidAddress(address.toLowerCase()), true)
  })
})

describe('areSameAddresses', function() {
  it('should correctly compare two addresses', function() {
    assert.equal(utils.areSameAddresses(address, '0x' + address.substring(2, address.length).toUpperCase()), true)
    assert.equal(utils.areSameAddresses(address, address.toLowerCase()), true)
  })
})

describe('pubToAddress', function () {
  it('should produce an address given a public key', function () {
    const pubKey = Buffer.from('3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d', 'hex')
    const address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    const r = utils.pubToAddress(pubKey)
    assert.equal(r.toString('hex'), address)
  })
  it('should produce an address given a SEC1 public key', function () {
    const pubKey = Buffer.from('043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d', 'hex')
    const address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    const r = utils.pubToAddress(pubKey, true)
    assert.equal(r.toString('hex'), address)
  })
  it('shouldn\'t produce an address given an invalid SEC1 public key', function () {
    const pubKey = Buffer.from('023a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d', 'hex')
    assert.throws(function () {
      utils.pubToAddress(pubKey, true)
    })
  })
  it('shouldn\'t produce an address given an invalid public key', function () {
    const pubKey = Buffer.from('3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744', 'hex')
    assert.throws(function () {
      utils.pubToAddress(pubKey)
    })
  })
})

describe('pubToAddress 0x', function () {
  it('should produce an address given a public key', function () {
    const pubKey = '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    const address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    const r = utils.pubToAddress(pubKey)
    assert.equal(r.toString('hex'), address)
  })
})

describe('hex prefix', function () {
  const string = 'd658a4b8247c14868f3c512fa5cbb6e458e4a989'
  it('should add', function () {
    assert.equal(utils.addHexPrefix(string), '0x' + string)
  })
  it('should return on non-string input', function () {
    assert.throws(function() {
      utils.addHexPrefix(1)
    })
  })
})

describe('privateToPublic', function() {
  it('should get the corresponding public key', function() {
    assert.deepEqual(utils.privateToPublic(sk), pk)
  })
})

describe('toBuffer', function () {
  it('should work', function () {
    // Buffer
    assert.deepEqual(utils.toBuffer(Buffer.allocUnsafe(0)), Buffer.allocUnsafe(0))
    // Array
    assert.deepEqual(utils.toBuffer([]), Buffer.allocUnsafe(0))
    // String
    assert.deepEqual(utils.toBuffer('11'), Buffer.from([49, 49]))
    assert.deepEqual(utils.toBuffer('0x11'), Buffer.from([17]))
    assert.deepEqual(utils.toBuffer('1234').toString('hex'), '31323334')
    assert.deepEqual(utils.toBuffer('0x1234').toString('hex'), '1234')
    // Number
    assert.deepEqual(utils.toBuffer(1), Buffer.from([1]))
    // null
    assert.deepEqual(utils.toBuffer(null), Buffer.allocUnsafe(0))
    // undefined
    assert.deepEqual(utils.toBuffer(), Buffer.allocUnsafe(0))
    // 'toBN'
    assert.deepEqual(utils.toBuffer(new BN(1)), Buffer.from([1]))
    // 'toArray'
    assert.deepEqual(utils.toBuffer({ toArray: function () { return [ 1 ] } }), Buffer.from([1]))
  })
  it('should fail', function () {
    assert.throws(function () {
      utils.toBuffer({ test: 1 })
    })
  })
})

describe('hashTransaction', function() {
  it('should produce a deterministic hash', function() {
    const tx_hash = utils.hashTransaction(tx)
    const scrambled_hash = utils.hashTransaction(tx_scrambled)
    const different_hash = utils.hashTransaction(tx_different)
    assert.deepEqual(tx_hash, scrambled_hash)
    assert.notDeepEqual(tx_hash, different_hash)
  })
})

describe('hashMessage', function () {
  it('should produce a deterministic hash', function () {
    const h = utils.hashMessage(Buffer.from('Hello world'))
    assert.deepEqual(h, Buffer.from('14894951ffca216088cba18b434a31fe88cd706886c5f64e0582711d57757ed6', 'hex'))
  })
})

describe('toChecksumAddress', function () {
  it('should work', function () {
    for (let i = 0; i < checksumAddresses.length; i++) {
      let tmp = checksumAddresses[i]
      assert.equal(utils.toChecksumAddress(tmp.toLowerCase()), tmp)
    }
  })
})

describe('ecSignTransaction', function() {
  it('should return a signature for a transaction for AI Network', function() {
    const signature = utils.ecSignTransaction(tx, sk)
    assert.equal(utils.ecVerifySig(tx, signature, address), true)
  })
})

describe('ecSignMessage', function() {
  it('should return a signature for a message', function() {
    const signature = utils.ecSignMessage(message, sk)
    assert.equal(utils.ecVerifySig(message, signature, address), true)
  })
})

describe('ecVerifySig', function() {
  it('should return true for a correct signature', function() {
    const verified = utils.ecVerifySig(message, correct_signature, address)
    assert.equal(verified, true)
  })

  it('should return false for a corrupt signature', function() {
    let corrupt_signature = '0x2'+correct_signature.substring(3,correct_signature.length)
    const verified = utils.ecVerifySig(message, corrupt_signature, address)
    assert.equal(verified, false)
  })

  it('should return false for an incorrect public key', function() {
    const verified = utils.ecVerifySig(message, correct_signature, '0x1D982a9bb0A224618Ac369Ff0a6B8B1c51E5c472')
    assert.equal(verified, false)
  })

  it('should return false for a different message', function() {
    const verified = utils.ecVerifySig('Hello World', correct_signature, address)
    assert.equal(verified, false)
  })
})

describe('encryption', function() {
  it('should encrypt and decrypt correctly', async function() {
    const message = 'abcdefg'
    const encrypted = await utils.encryptWithPublicKey(pk.toString('hex'), message)
    const decrypted = await utils.decryptWithPrivateKey(sk.toString('hex'), encrypted)
    assert.equal(message, decrypted)
  })
})

describe('createAccount', function() {
  it('should create a new account', async function() {
    const account = utils.createAccount()
    const publicKey = utils.privateToPublic(Buffer.from(account.private_key, 'hex')).toString('hex')
    assert.equal(account.public_key, publicKey)
  });
})
