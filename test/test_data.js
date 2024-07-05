/**
 * The data in this file is for running test ONLY. Do NOT use it for production.
 */
const address = '0xCAcD898dBaEdBD9037aCd25b82417587E972838d';
const pk = Buffer.from('cf0ba8241cd1452c282c4dfa33d48e43ca34e60f5da9a2422293aa34ac14b018991d0cbc42089e4dcf3b3cc2907d51f06baed00cad7f855182572c77cbfad2b3', 'hex');
const sk = Buffer.from('cef602325bc0882591e5768e94cd94a326947e8ee5d3b02fb29d1b89a9334d99', 'hex');
const mnemonic = 'lab diesel rule gas student bulb menu option play habit ski result';
// NOTE(platfowner): In AI Network, we decided to use Ethereum Network's
//                   derivation path ("m/44'/60'/0'/0/") instead of
//                   its own ("m/44'/412'/0'/0/").
// const mnemonicPrivateKey = Buffer.from('1fa9d5e22aa39d264c7c939f99b47696cf534bead88e4ca81da767b1ed122fa8', 'hex');
// const mnemonicPublicKey = Buffer.from('6ab3e3c1d727fe72e06a6243a05ee6b1607c162a1696629ac9f19b0c1661d586554cadb17ea9d1ae246f60735f9d0e399c61139d7afef72de28809edb695990e', 'hex');
// const mnemonicAddress = '0xe402A6296233F2DfefE35cbC3203802965B4E4d7';
const mnemonicPrivateKey = Buffer.from('6819573717d78a332c67460c9f6d4ed8cc72457620646ba365673177a7aa34dd', 'hex');
const mnemonicPublicKey = Buffer.from('98cea6be654001ec6c47cd13dd7e193fc82b69954a2726949cbcc724088081657b51b12b2bfbd6055c060a86d4b6e189faa44a0e43157503f78e929f01cd7742', 'hex');
const mnemonicAddress = '0xCb6D24618842a9dE0a1f73Ab55DEB301D811ad13';
const checksumAddresses = [
  '0x21fE266480080535b0CCe687669e5DBe13f42559',
  '0x32F9c01ab1247C9366C8A22B6929eB0A905dBBd1',
  '0x5C102a82543448d75FEe35EdA1Fff7cD24D9D02F'
]
const message = 'Hello world'
const correct_signature = '0x14894951ffca216088cba18b434a31fe88cd706886c5f64e0582711d57757ed6f2ecce39370e9ef5da08db891b88d6966245c5f52ce4144661c0015e9a8e97c467bb0a872d0f298f8ab948b882e7c0cbb8070f1067e8b42e34ada2314ae9df221c'
const tx = {
  operation: {
    ref: '/afan',
    value: 'HAHA',
    type: 'SET_VALUE'
  },
  nonce: 10,
  timestamp: 123,
  parent_tx_hash: ''
}
const tx_scrambled = {
  timestamp: 123,
  operation: {
    value: 'HAHA',
    ref: '/afan',
    type: 'SET_VALUE'
  },
  nonce: 10,
  parent_tx_hash: ''
}
const tx_different = {
  operation: {
    ref: '/afan',
    value: 'HAHA',
    type: 'SET_VALUE'
  },
  nonce: 10,
  timestamp: 1234,
  parent_tx_hash: ''
}

module.exports = {
  address,
  pk,
  sk,
  mnemonic,
  mnemonicPrivateKey,
  mnemonicPublicKey,
  mnemonicAddress,
  checksumAddresses,
  message,
  correct_signature,
  tx,
  tx_scrambled,
  tx_different
}
