const libsignal = require('libsignal')
const crypto = require('crypto')

// libloki.crypto

const IV_LENGTH = 16

function makeSymkey(privkeyBin, pubkeyHex) {
  // convert toPubkey to Buffer
  const pubKeyBin = Buffer.from(pubkeyHex, 'hex')
  return libsignal.curve.calculateAgreement(
    pubKeyBin,
    privkeyBin
  )
}

function fallbackEncrypt(privkey, toPubkey, text) {
  const symmetricKey = makeSymkey(privkey, toPubkey)
  //console.log('fallbackEncrypt symmetricKey', symmetricKey)
  const iv = crypto.randomBytes(IV_LENGTH)
  // get an arraybuffer from tet
  const payloadData = Buffer.from(text)
  const ciphertext = libsignal.crypto.encrypt(
    symmetricKey,
    payloadData,
    iv
  )
  const ivAndCiphertext = new Uint8Array(
    iv.byteLength + ciphertext.byteLength
  )
  ivAndCiphertext.set(new Uint8Array(iv))
  ivAndCiphertext.set(new Uint8Array(ciphertext), iv.byteLength)
  //console.log('ivAndCiphertext', ivAndCiphertext)

  // returns a uint8array
  return ivAndCiphertext
}

function fallbackDecrypt(privkey, fromPubkey, ivAndCiphertext) {
  const symmetricKey = makeSymkey(privkey, fromPubkey)

  const iv = ivAndCiphertext.slice(0, IV_LENGTH)
  const ciphertext = ivAndCiphertext.slice(IV_LENGTH)
  return libsignal.crypto.decrypt(symmetricKey, ciphertext, iv)
}

module.exports = {
  fallbackEncrypt,
  fallbackDecrypt
}
