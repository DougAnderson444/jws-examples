// The SignJWT class is a utility for creating Compact JWS formatted JWT strings.

// Option 1: Use webcrypto
import { generate } from './generate.mjs'

import SignJWT from 'jose/jwt/sign'
import parseJwk from 'jose/jwk/parse'
import CompactSign from 'jose/jws/compact/sign'
import GeneralSign from 'jose/jws/general/sign'
import compactVerify from 'jose/jws/compact/verify'

async function main () {
  const keyPair = await generate()

  console.log({ keyPair })

  // Private Key JWK
  // const jwk = {
  //   alg: 'ES256',
  //   crv: 'P-256',
  //   kty: 'EC',
  //   d: 'VhsfgSRKcvHCGpLyygMbO_YpXc7bVKwi12KQTE4yOR4',
  //   x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
  //   y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo'
  // }

  const ecPrivateKey = await parseJwk({ ...keyPair.privateKeyJwk, alg: 'ES256' }) // Returns: Promise<KeyLike>

  console.log({ ecPrivateKey })

  // Create JWT
  const jwt = await new SignJWT({ 'urn:example:claim': true })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt()
    .setIssuer('urn:example:issuer')
    .setAudience('urn:example:audience')
    .setExpirationTime('2h')
    .sign(ecPrivateKey)

  console.log({ jwt })

  // Compact JWS Signature
  const encoder = new TextEncoder()
  const jwsCompact = await new CompactSign(encoder.encode('It’s a dangerous business, Frodo, going out your door.'))
    .setProtectedHeader({ alg: 'ES256' })
    .sign(ecPrivateKey)

  console.log({ jwsCompact })

  const decoder = new TextDecoder()

  // Compact verify
  const publicKey = await parseJwk({ ...keyPair.publicKeyJwk, alg: 'ES256' })
  const { payload, protectedHeader } = await compactVerify(jwsCompact, publicKey)

  console.log(protectedHeader)
  console.log(decoder.decode(payload))

  // general Sign
  const sign = new GeneralSign(encoder.encode('It’s a dangerous business, Frodo, going out your door.'))

  sign
    .addSignature(ecPrivateKey)
    .setProtectedHeader({ alg: 'ES256' })

  const jwsGeneral = await sign.sign()

  console.log('\nGeneral JWS: \n', JSON.stringify(jwsGeneral, null, 2))
}
main()
