import crypto from './crypto.mjs'

export const generateKeyPair = async (options = { kty: 'EC', crvOrSize: 'P-256' }) => {
  const kp = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: options.crvOrSize
    },
    true,
    ['sign', 'verify']
  )
  return kp
}

export const generate = async (options = { kty: 'EC', crvOrSize: 'P-256' }) => {
  const kp = await generateKeyPair(options)

  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey)

  return {
    publicKeyJwk: {
      // alg:
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y
    },
    privateKeyJwk: {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
      d: jwk.d
    }
  }
}
