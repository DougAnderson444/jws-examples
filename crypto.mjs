import Crypto from 'crypto'

export function isNodejs () {
  return (
    typeof process === 'object' &&
    typeof process.versions === 'object' &&
    typeof process.versions.node !== 'undefined' &&
    typeof window !== undefined
  )
}

let crypto

if (isNodejs()) {
  crypto = Crypto
} else {
  crypto = window.crypto
}

export default crypto
