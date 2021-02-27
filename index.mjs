// The SignJWT class is a utility for creating Compact JWS formatted JWT strings.

// Option 1: Use webcrypto
import { generate } from './generate.mjs'
import { generateKeyPair } from '@stablelib/ed25519'
import { generateJwk } from './convert.mjs'

import SignJWT from 'jose/jwt/sign'
import parseJwk from 'jose/jwk/parse'
import CompactSign from 'jose/jws/compact/sign'
import GeneralSign from 'jose/jws/general/sign'
import compactVerify from 'jose/jws/compact/verify'

async function main () {
  // const keyPair = await generate()
  // console.log({ keyPair })

  // or convert raw to JWK
  const keyPair = await generateJwk()
  console.log('JWK keypair\n', { keyPair })

  /*
    for panva/jose use 'alg' could be:
      ES256 (curve P-256),
      EdDSA (curve Ed25519), or
      ES256K (curve secp256k1)
  */
  const alg = 'EdDSA'

  // Private Key JWK
  // const jwk = {
  //   alg: 'ES256',
  //   crv: 'P-256',
  //   kty: 'EC',
  //   d: 'VhsfgSRKcvHCGpLyygMbO_YpXc7bVKwi12KQTE4yOR4',
  //   x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
  //   y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo'
  // }

  const ecPrivateKey = await parseJwk({ ...keyPair.privateKeyJwk, alg }) // Returns: Promise<KeyLike>

  // Create JWT
  // const jwt = await new SignJWT({ 'urn:example:claim': true })
  //   .setProtectedHeader({ alg: 'ES256' })
  //   .setIssuedAt()
  //   .setIssuer('urn:example:issuer')
  //   .setAudience('urn:example:audience')
  //   .setExpirationTime('2h')
  //   .sign(ecPrivateKey)

  // console.log({ jwt })

  // Compact JWS Signature
  const encoder = new TextEncoder()

  const textObj = { test: 'It’s a dangerous business, Frodo, going out your door.' }

  console.log(textObj instanceof Object)
  console.log(JSON.stringify(textObj) instanceof Object)

  const jwsCompact = await new CompactSign(encoder.encode(JSON.stringify(textObj)))
    .setProtectedHeader({ alg })
    .sign(ecPrivateKey)

  console.log({ jwsCompact })

  const decoder = new TextDecoder()

  // Compact verify
  const publicKey = await parseJwk({ ...keyPair.publicKeyJwk, alg })
  const { payload, protectedHeader } = await compactVerify(jwsCompact, publicKey)

  console.log(protectedHeader)
  console.log(decoder.decode(payload))
  console.log(decoder.decode(payload).text)

  // general Sign
  const sign = new GeneralSign(encoder.encode('It’s a dangerous business, Frodo, going out your door.'))

  sign
    .addSignature(ecPrivateKey)
    .setProtectedHeader({ alg })

  const jwsGeneral = await sign.sign()

  console.log('\nGeneral JWS: \n', JSON.stringify(jwsGeneral, null, 2))
}
main()
