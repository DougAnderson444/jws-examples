import sodium from 'sodium-universal'
import base64url from 'base64url'
import canonicalize from 'canonicalize'

const keyPair = {
  publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
  secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
}
sodium.crypto_sign_keypair(keyPair.publicKey, keyPair.secretKey)
console.log({ keyPair })

// const hexToUintArray = hex => {
//   const a = []
//   for (let i = 0, len = hex.length; i < len; i += 2) {
//     a.push(parseInt(hex.substr(i, 2), 16))
//   }
//   return new Uint8Array(a)
// }

// const hexToArrayBuf = hex => {
//   return hexToUintArray(hex).buffer
// }

// const arrayBufToBase64UrlEncode = buf => {
//   let binary = ''
//   const bytes = new Uint8Array(buf)
//   for (let i = 0; i < bytes.byteLength; i++) {
//     binary += String.fromCharCode(bytes[i])
//   }
//   let b64
//   if (isNodejs()) b64 = Buffer.from(binary, 'binary').toString('base64')
//   else {
//     b64 = window.btoa(binary) // creates a Base64-encoded ASCII string from a binary string
//       .replace(/\//g, '_')
//       .replace(/=/g, '')
//       .replace(/\+/g, '-')
//   }
//   return b64
// }

export const privateKeyJwkFromEd25519PrivateKeyHex = (Ed25519privateKeyHex) => {
  const jwk = {
    crv: 'Ed25519',
    d: base64url.encode(Ed25519privateKeyHex.slice(0, 32)),
    x: base64url.encode(Ed25519privateKeyHex.slice(32, 64)),
    kty: 'OKP'
  }
  const kid = getKid(jwk)
  return {
    ...jwk,
    kid
  }
}

export const getKid = (jwk) => {
  const copy = { ...jwk }
  delete copy.d
  delete copy.kid
  delete copy.alg
  const digest = Buffer.alloc(sodium.crypto_generichash_BYTES)
  const uint8array = new TextEncoder('utf-16').encode(canonicalize(copy))
  sodium.crypto_generichash(digest, uint8array) // blake2b-256
  return base64url.encode(Buffer.from(digest))
}

console.log(privateKeyJwkFromEd25519PrivateKeyHex(keyPair.secretKey))
