const crypto    = require('crypto')
const libsignal = require('libsignal')
const bb        = require('bytebuffer')
const _sodium   = require('libsodium-wrappers-sumo') // maybe put in session-client?
const binary    = require('./lib.binary.js')

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
const DHEncrypt64 = async (symmetricKey, plainText) => {
  const ivAndCiphertext = await DHEncrypt(symmetricKey, plainText)
  return bb.wrap(ivAndCiphertext).toString('base64')
}

// used for tokens
const DHDecrypt64 = async (symmetricKey, cipherText64) => {
  // base64 decode
  const ivAndCiphertext = Buffer.from(
    bb.wrap(cipherText64, 'base64').toArrayBuffer()
  )
  return DHDecrypt(symmetricKey, ivAndCiphertext)
}

function generateEphemeralKeyPair() {
  // generate a x25519 keypair
  const keys = libsignal.curve.generateKeyPair()
  // Signal protocol prepends with "0x05"
  keys.pubKey = keys.pubKey.slice(1)
  return keys
}

function makeSymmetricKey(privKeyBuf, pubKeyBuf) {
  if (pubKeyBuf.byteLength === 32) {
    pubKeyBuf = Buffer.concat([Buffer.from('05', 'hex'), pubKeyBuf])
  }
  // is this a promise? no (needs .async. for promise)
  const symmetricKey = libsignal.curve.calculateAgreement(
    pubKeyBuf,
    privKeyBuf
  )
  //console.log('symmetricKey', symmetricKey)
  return symmetricKey
}

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

// for attachments
async function encryptCBC(keysBuf, plaintextEnc) {
  if (plaintextEnc === undefined) {
    console.trace('lib.loki_crypo::encryptCBC - passed undefined plaintextEnc')
    return
  }
  const aesKey = keysBuf.slice(0, 32)
  const macKey = keysBuf.slice(32, 64)

  // not on the node side
  const iv = crypto.randomBytes(IV_LENGTH) // Buffer (object)
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv) // Cipheriv object
  const ciphertext = Buffer.concat([cipher.update(plaintextEnc), cipher.final()])
  const ivAndCiphertext = Buffer.concat([iv, ciphertext])
  // generate mac
  const macBuf = crypto.createHmac('sha256', macKey).update(ivAndCiphertext).digest()
  const finalBuf = Buffer.concat([ivAndCiphertext, macBuf])
  return finalBuf
}

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
// marking async, because we likely will need some IO in the future
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
  const sig = await libsignal.curve.calculateSignature(privKey, sigData)
  // const sig = makeSymmetricKey(privKey, sigData)
  return sig.toString('hex')
}

function verifySigDataV2(pubKeyBuf, messageBuf, sigBuf) {
  return libsignal.curve.verifySignature(pubKeyBuf, messageBuf, sigBuf)
}

function getSigDataV2(privKey, messageBuf) {
  return libsignal.curve.calculateSignature(
    privKey,
    messageBuf
  ).toString('base64')
}

const sha512Multipart = async parts => {
  await _sodium.ready
  const sodium = _sodium
  return sodium.crypto_hash_sha512(binary.concatUInt8Array(...parts))
}

/**
 *
 * @param messageParts concatenated byte array
 * @param ourKeyPair our devices keypair
 * @param ka blinded secret key for this open group
 * @param kA blinded pubkey for this open group
 * @returns blinded signature
 */
async function blindedED25519Signature(messageParts, ourKeyPair, ka, kA) {
  //const sodium = await getSodiumRenderer();
  await _sodium.ready
  const sodium = _sodium

  //console.log('ourKeyPair', ourKeyPair)
  const sEncode = ourKeyPair.privateKey.slice(0, 32) // only half

  const shaFullLength = sodium.crypto_hash_sha512(sEncode)

  const Hrh = shaFullLength.slice(32)

  const r = sodium.crypto_core_ed25519_scalar_reduce(await sha512Multipart([Hrh, kA, messageParts]))

  const sigR = sodium.crypto_scalarmult_ed25519_base_noclamp(r)

  const HRAM = sodium.crypto_core_ed25519_scalar_reduce(await sha512Multipart([sigR, kA, messageParts]))

  const sigS = sodium.crypto_core_ed25519_scalar_add(
    r,
    sodium.crypto_core_ed25519_scalar_mul(HRAM, ka)
  )

  const fullSig = binary.concatUInt8Array(sigR, sigS)
  return fullSig
}

async function getSogsSignature(blinded, ka, kA, signingKeys, toSign) {
  await _sodium.ready
  const sodium = _sodium
  //console.log('blinded', blinded, 'ka', ka, 'kA', kA)
  if (blinded && ka && kA) {
    //console.log('signing sogs with blinded ED25519 sig')
    return blindedED25519Signature(toSign, signingKeys, ka, kA)
  }
  //console.log('signingKeys', signingKeys)
  //const edKeyPrivBytes = edKey.ed25519KeyPair.privateKey
  // signingKeys.privateKey is in Uint8Array
  //console.log('signing sogs with unblinded personal ED25519 sig')
  return sodium.crypto_sign_detached(toSign, signingKeys.privateKey)
}

// only need signingKeys.privateKey (ed priv key here)
const getBlindingValues = async (serverPK, signingKeys) => {
  await _sodium.ready
  const sodium = _sodium
  const k = sodium.crypto_core_ed25519_scalar_reduce(sodium.crypto_generichash(64, serverPK))
  //console.log('signingKeys', signingKeys)

  let signingKey = sodium.crypto_sign_ed25519_sk_to_curve25519(signingKeys.privateKey)

  if (signingKey.length > 32) {
    console.warn('length of signing key is too long, cutting to 32: oldlength', signingKey.length)
    signingKey = signingKey.slice(0, 32)
  }

  const ka = sodium.crypto_core_ed25519_scalar_mul(k, signingKey) // recast for reasons
  const kA = sodium.crypto_scalarmult_ed25519_base_noclamp(ka)

  return {
    a: signingKey,
    secretKey: ka,
    publicKey: kA,
  }
}

async function getSigDataBlinded(serverPubKeyHex, signingKeys, messageBuf) {
  const srvU8A = binary.hexStringToUint8Array(serverPubKeyHex)
  const blindKp = await getBlindingValues(srvU8A, signingKeys)
  // blindKp has a, secretKey, publicKey
  const ka = blindKp.secretKey
  const kA = blindKp.publicKey
  //console.log('signing with', ka, kA, 'and', signingKeys)

  const sigB64 = await getSogsSignature(true, ka, kA, signingKeys, messageBuf)
  //console.log('sig', sigBuf)

  if (0) {
    await _sodium.ready
    const sodium = _sodium
    console.log('mid', sigB64)
    const sigBuf = Buffer.from(sigB64, 'base64')

    const blindedVerifySig = sodium.crypto_sign_verify_detached(
      sigBuf,
      messageBuf,
      kA // this this right?
    )
    console.log('blindedVerifySig', blindedVerifySig)
  }

  return binary.fromUInt8ArrayToBase64(sigB64)
}

async function verifySigDataV3(serverPubKeyHex, pubKeyBuf, messageBuf, sigB64) {
  //const srvU8A = binary.hexStringToUint8Array(serverPubKeyHex)
  const sigBuf = Buffer.from(sigB64, 'base64')
  //console.log('sigBufLength', sigBuf.byteLength)
  //console.log('blind type?', pubKeyBuf[0], 0x15)
  if (pubKeyBuf[0] === 0x15) {
    //console.log('verifying blinded message')
    // blinded
    await _sodium.ready
    const sodium = _sodium
    // kA
    const pubkeyWithoutPrefixBuf = pubKeyBuf.slice(1) // Buffer
    //console.log('pubkeyWithoutPrefix', typeof(pubkeyWithoutPrefix), pubkeyWithoutPrefix)

    const blindedVerifySig = sodium.crypto_sign_verify_detached(
      sigBuf,
      messageBuf,
      pubkeyWithoutPrefixBuf
    )
    //console.log('blindedVerifySig', blindedVerifySig)

    return blindedVerifySig
  }
  // standard curve verify
  return libsignal.curve.verifySignature(pubKeyBuf, messageBuf, sigBuf)
}

// Calculate a shared secret for a message from A to B:
//
// BLAKE2b(a kB || kA || kB)
//
// The receiver can calulate the same value via:
//
// BLAKE2b(b kA || kA || kB)
function sharedBlindedEncryptionKey(fromBlindedPublicKey, otherBlindedPublicKey,
  secretKey, sodium, toBlindedPublicKey) {
  // Calculate k*a.  To get 'a' (the Ed25519 private key scalar) we call the sodium function to
  // convert to an *x* secret key, which seems wrong--but isn't because converted keys use the
  // same secret scalar secret (and so this is just the most convenient way to get 'a' out of
  // a sodium Ed25519 secret key)
  //const aBytes = generatePrivateKeyScalar(secretKey, sodium)
  const aBytes = sodium.crypto_sign_ed25519_sk_to_curve25519(secretKey)
  const combinedKeyBytes = sodium.crypto_scalarmult_ed25519_noclamp(aBytes, otherBlindedPublicKey)
  return sodium.crypto_generichash(32,
    binary.concatUInt8Array(combinedKeyBytes, fromBlindedPublicKey, toBlindedPublicKey)
  )
}

function generateBlindingFactor(serverPubKeyHex, sodium) {
  const serverUI8 = binary.hexStringToUint8Array(serverPubKeyHex)
  const serverPkHash = sodium.crypto_generichash(64, serverUI8)
  if (!serverPkHash.length) {
    throw new Error('generateBlindingFactor: crypto_generichash failed')
  }

  // Reduce the server public key into an ed25519 scalar (`k`)
  const k = sodium.crypto_core_ed25519_scalar_reduce(serverPkHash)
  return k
}

// https://github.com/oxen-io/session-desktop/blob/0794edeb69aac582187da35771dc29ae3e68279c/ts/session/crypto/BufferPadding.ts#L13
/**
 * Unpad the buffer from its padding.
 * An error is thrown if there is no padding.
 * A padded buffer is
 *  * whatever at start
 *  * ends with 0x80 and any number of 0x00 until the end
 */
function removeMessagePadding(paddedData) {
  const paddedPlaintext = new Uint8Array(paddedData)
  // window?.log?.info('Removing message padding...');
  for (let i = paddedPlaintext.length - 1; i >= 0; i -= 1) {
    if (paddedPlaintext[i] === 0x80) {
      const plaintext = new Uint8Array(i)
      plaintext.set(paddedPlaintext.subarray(0, i))
      return plaintext.buffer
    } else if (paddedPlaintext[i] !== 0x00) {
      console.debug('got a message without padding... Letting it through for now')
      return paddedPlaintext
    }
  }

  throw new Error('Invalid padding')
}

async function decryptWithSessionBlindingProtocol(
  data, isOutgoing, otherBlindedPublicKey, serverPubKeyHex, userEd25519KeyPair) {
  await _sodium.ready
  const sodium = _sodium

  const NPUBBYTES = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  if (data.length <= NPUBBYTES) {
    console.warn(`data is too short. should be at least ${sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES} but is ${data.length}`)
    return false
  }
  //console.log('serverPubKeyHex', serverPubKeyHex)
  //console.log('userEd25519KeyPair', userEd25519KeyPair)
  const srvU8A = binary.hexStringToUint8Array(serverPubKeyHex)
  const blindKp = await getBlindingValues(srvU8A, userEd25519KeyPair)
  if (!blindKp) {
    console.warn('decryptWithSessionBlindingProtocol - getBlindingValues failure')
    return false
  }
  const otherPkBuf = Buffer.from(otherBlindedPublicKey, 'hex')
  const otherPkWithoutPrefixBuf = otherPkBuf.slice(1) // Buffer
  const kA = isOutgoing ? blindKp.publicKey : otherPkWithoutPrefixBuf

  // probably needs a try
  const decKey = sharedBlindedEncryptionKey(kA, otherPkWithoutPrefixBuf,
    userEd25519KeyPair.privateKey, sodium,
    isOutgoing ? otherPkBuf : blindKp.publicKey,
  )
  if (!decKey) {
    console.warn('decryptWithSessionBlindingProtocol - sharedBlindedEncryptionKey failure')
    return false
  }
  const version = data[0]
  const NPUBBYTESLoc = data.length - NPUBBYTES
  const ciphertext = data.slice(1, NPUBBYTESLoc)
  const nonce = data.slice(NPUBBYTESLoc)

  if (version !== 0) {
    console.warn('decryptWithSessionBlindingProtocol - Unknown version', version)
    return false
  }
  // We can decrypt this! We have the technology!
  const innerBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    null,
    nonce,
    decKey
  )
  if (!innerBytes) {
    console.warn('decryptWithSessionBlindingProtocol - decryption failed')
    return false
  }
  const numBytesPubkey = 32
  // Ensure the length is correct
  if (innerBytes.length <= numBytesPubkey) {
    console.warn('decryptWithSessionBlindingProtocol - decryption failed, result too small')
    return false
  }

  // Split up: the last 32 bytes are the sender's *unblinded* ed25519 key
  const senderEdpkLoc = innerBytes.length - numBytesPubkey
  const plainText = innerBytes.slice(0, senderEdpkLoc)
  const senderEdpk = innerBytes.slice(senderEdpkLoc)

  // Verify that the inner sender_edpk (A) yields the same outer kA we got with the message
  const blindingFactor = generateBlindingFactor(serverPubKeyHex, sodium)
  //const sharedSecret = combineKeys(blindingFactor, senderEdpk, sodium);
  const sharedSecret = sodium.crypto_scalarmult_ed25519_noclamp(blindingFactor, senderEdpk)

  // case insensitive compare
  // kA is a buffer
  // sharedSecret is uint8
  const sharedSecretBuf = Buffer.from(sharedSecret.buffer, sharedSecret.byteOffset, sharedSecret.byteLength)
  //console.log('decryptWithSessionBlindingProtocol - kA', kA, '==', sharedSecretBuf)
  if (Buffer.compare(kA, sharedSecretBuf) !== 0) {
    console.warn('decryptWithSessionBlindingProtocol - kA', kA, '!=', sharedSecret)
    return false
  }

  // Get the sender's X25519 public key
  //const senderSessionIdBytes = toX25519(senderEdpk, sodium)
  const senderSessionIdBytes = sodium.crypto_sign_ed25519_pk_to_curve25519(senderEdpk)
  // Uint8Array
  //console.log('senderSessionIdBytes', senderSessionIdBytes)
  const senderPKBuf = Buffer.from(senderSessionIdBytes.buffer, senderSessionIdBytes.byteOffset, senderSessionIdBytes.byteLength)
  const plainTextBuf = Buffer.from(plainText.buffer, plainText.byteOffset, plainText.byteLength)
  return {
    plainTextBuf,
    senderUnblinded: '05' + senderPKBuf.toString('hex')
    //senderUnblinded: `${KeyPrefixType.standard}${to_hex(senderSessionIdBytes)}`
  }
}

module.exports = {
  DHEncrypt,
  DHDecrypt,
  DHEncrypt64,
  DHDecrypt64,
  generateEphemeralKeyPair,
  // what needs this?
  makeSymmetricKey,
  makeOnionSymKey,
  encryptGCM,
  decryptGCM,
  encryptCBC,
  decryptCBC,
  getSigData,
  getSigDataV2,
  getSigDataBlinded,
  verifySigDataV2,
  getBlindingValues,
  getSogsSignature,
  verifySigDataV3,
  decryptWithSessionBlindingProtocol,
  removeMessagePadding,
}
