const Buffer = require('safe-buffer').Buffer

export interface ECDSASignature {
  v: number
  r: Buffer
  s: Buffer
}

export const hashMessage = (message: any): Buffer => {
  console.log("This function is not implemented yet.")
  return new Buffer("")
}

export const ecSignMessage = (
  message: any,
  privateKey: Buffer,
  chainId?: number
): Buffer => {
  console.log("This function is not implemented yet.")
  return new Buffer("")
}

export const ecSplitSig = (signature: Buffer): ECDSASignature => {
  console.log("This function is not implemented yet.")
  return { v: 0, r: new Buffer(""), s: new Buffer("") }
}

export const ecVerifySig = (
  signature: Buffer,
  message: any,
  publicKey: string,
  chainId?: number
): boolean => {
  console.log("This function is not implemented yet.")
  return false
}
