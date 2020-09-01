const crypto    = require('crypto')
const libsignal = require('libsignal')
const bb        = require('bytebuffer')

/*
bufferFrom64
bufferTo64
bufferFromHex
bufferToHex
*/

const IV_LENGTH = 16
const NONCE_LENGTH = 12
const TAG_LENGTH = 16

async function DHEncrypt(symmetricKey, plainText) {
  const iv = crypto.randomBytes(IV_LENGTH)
  // DH
  const ciphertext = await libsignal.crypto.encrypt(
    symmetricKey,
    plainText,
    iv
  )
  const ivAndCiphertext = new Uint8Array(
    iv.byteLength + ciphertext.byteLength
  )
  ivAndCiphertext.set(new Uint8Array(iv))
  ivAndCiphertext.set(new Uint8Array(ciphertext), iv.byteLength)
  return ivAndCiphertext
}

async function DHDecrypt(symmetricKey, ivAndCiphertext) {
  const iv = ivAndCiphertext.slice(0, IV_LENGTH)
  const ciphertext = ivAndCiphertext.slice(IV_LENGTH)
  // DH
  return libsignal.crypto.decrypt(symmetricKey, ciphertext, iv)
}

// used for proxy requests
const DHEncrypt64 = async(symmetricKey, plainText) => {
  const ivAndCiphertext = await DHEncrypt(symmetricKey, plainText)
  return bb.wrap(ivAndCiphertext).toString('base64')
}

// used for tokens
const DHDecrypt64 = async(symmetricKey, cipherText64) => {
  // base64 decode
  const ivAndCiphertext = Buffer.from(
    bb.wrap(cipherText64, 'base64').toArrayBuffer()
  )
  return DHDecrypt(symmetricKey, ivAndCiphertext)
}

function makeSymmetricKey(privKeyBuf, pubKeyBuf) {
  if (pubKeyBuf.byteLength === 32) {
    pubKeyBuf = Buffer.concat([Buffer.from('05', 'hex'), pubKeyBuf])
  }
  // is this a promise?
  const symmetricKey = libsignal.curve.calculateAgreement(
    pubKeyBuf,
    privKeyBuf
  )
  //console.log('symmetricKey', symmetricKey)
  return symmetricKey
}

// pubKey & privKey needs to be a buffer
function makeOnionSymKey(privKeyBuf, pubKeyBuf) {
  if (pubKeyBuf.byteLength === 32) {
    pubKeyBuf = Buffer.concat([Buffer.from('05', 'hex'), pubKeyBuf])
  }
  // symKey
  const keyAgreement = libsignal.curve.calculateAgreement(
    pubKeyBuf,
    privKeyBuf
  )
  //console_wrapper.log('makeOnionSymKey agreement', keyAgreement.toString('hex'))

  // hash the key agreement
  const hashedSymmetricKeyBuf = crypto.createHmac('sha256', 'LOKI').update(keyAgreement).digest()

  return hashedSymmetricKeyBuf
}

function encryptGCM(symmetricKey, plaintextEnc) {
  // not on the node side
  const nonce = crypto.randomBytes(NONCE_LENGTH) // Buffer (object)

  const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, nonce)
  const ciphertext = Buffer.concat([cipher.update(plaintextEnc), cipher.final()])
  const tag = cipher.getAuthTag()

  const finalBuf = Buffer.concat([nonce, ciphertext, tag])
  return finalBuf
}

// used for avatar download
function decryptGCM(symmetricKey, ivCiphertextAndTag) {
  const nonce      = ivCiphertextAndTag.slice(0, NONCE_LENGTH)
  const ciphertext = ivCiphertextAndTag.slice(NONCE_LENGTH, ivCiphertextAndTag.byteLength - TAG_LENGTH)
  const tag        = ivCiphertextAndTag.slice(ivCiphertextAndTag.byteLength - TAG_LENGTH)

  const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, nonce)
  decipher.setAuthTag(tag)
  //return decipher.update(ciphertext, 'binary', 'utf8') + decipher.final();
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

async function encryptCBC(keysBuf, plaintextEnc) {
  const aesKey = keysBuf.slice(0, 32)
  const macKey = keysBuf.slice(32, 64)

  // not on the node side
  const iv = crypto.randomBytes(IV_LENGTH) // Buffer (object)
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintextEnc), cipher.final()])
  const ivAndCiphertext = Buffer.concat([iv, ciphertext])
  // generate mac
  const macBuf = crypto.createHmac('sha256', macKey).update(ivAndCiphertext).digest()
  const finalBuf = Buffer.concat([ivAndCiphertext, macBuf])
  return finalBuf
}

// for attachments
function decryptCBC(keysBuf, ivCiphertextAndMac, remoteDigest) {
  const aesKey = keysBuf.slice(0, 32)
  const iv         = ivCiphertextAndMac.slice(0, IV_LENGTH)
  const ciphertext = ivCiphertextAndMac.slice(IV_LENGTH, ivCiphertextAndMac.byteLength - 32)
  // FIXME: implement mac and digest checking
  // const mac        = ivCiphertextAndMac.slice(ivCiphertextAndMac.byteLength - 32);
  if (remoteDigest) {
    // digest checking will need a digest passed in to compare...
    // or we need to export ivCiphertextAndMac
    const localDigest = crypto.createHash('sha256').update(ivCiphertextAndMac).digest()
    if (Buffer.compare(localDigest, remoteDigest)) {
      // mismatch, what do?
    }
  }
  const decipher   = crypto.createDecipheriv('aes-256-cbc', aesKey, iv)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

// FIXME: bring in the multidevice support functions
// or maybe put them into a separate libraries

// reply_to if 0 not, is also required in adnMessage
async function getSigData(sigVer, privKey, noteValue, adnMessage) {
  let sigString = ''
  sigString += adnMessage.text.trim()
  sigString += noteValue.timestamp
  if (noteValue.quote) {
    sigString += noteValue.quote.id
    sigString += noteValue.quote.author
    sigString += noteValue.quote.text.trim()
    if (adnMessage.reply_to) {
      sigString += adnMessage.reply_to
    }
  }
  /*
  sigString += [...attachmentAnnotations, ...previewAnnotations]
    .map(data => data.id || data.image.id)
    .sort()
    .join();
  */
  sigString += sigVer
  const sigData = Buffer.from(bb.wrap(sigString, 'utf8').toArrayBuffer())
  // symKey
  //const sig = await libsignal.curve.calculateSignature(privKey, sigData)
  const sig = makeSymmetricKey(privKey, sigData)
  return sig.toString('hex')
}

module.exports = {
  DHEncrypt,
  DHDecrypt,
  DHEncrypt64,
  DHDecrypt64,
  // what needs this?
  makeSymmetricKey,
  makeOnionSymKey,
  encryptGCM,
  decryptGCM,
  encryptCBC,
  decryptCBC,
  getSigData
}
