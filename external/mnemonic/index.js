const crypto   = require('crypto')
const mnemonic = require('./mnemonic.js')
//const curve    = require('curve25519-n')
const _sodium = require('libsodium-wrappers')

const SEEDSIZE = 16 // gives 12 seed words

// always return a promise
async function wordsToKeyPair(words) {
  const f3 = words.substr(0, 3)
  if (f3 === 'V2:') {
    return wordsToKeyPairV2(words.substr(3))
  } else
  if (f3 === 'V3:') {
    return wordsToKeyPairV3(words.substr(3))
  }
  return wordsToKeyPairV3(words)
}

// words is a space separate string
function wordsToKeyPairV2(words) {
  console.warn('Using deprecation version 2 format')
  // converting seed words to pubkey
  const seedHex32 = mnemonic.mn_decode(words)
  // double it
  const seedHex64 = seedHex32.concat(seedHex32).substring(0, 64)

  //const priv1 = curve.makeSecretKey(Buffer.from(seedHex64, 'hex'))
  const publicBuffer = Buffer.concat([Buffer.from('05', 'hex'), curve.derivePublicKey(priv1)])

  return {
    privKey: priv1,
    pubKey: publicBuffer
  }
}

async function wordsToKeyPairV3(words) {
  // converting seed words to pubkey
  const seedHex32 = mnemonic.mn_decode(words) // string
  // prefix with 32 0s
  const seedHex64 = seedHex32.concat(['0'.repeat(32), seedHex32]).substring(0, 64) // string

  await _sodium.ready
  const sodium = _sodium
  try {
    // convert seed to ed keypair
    const ed25519KeyPair = sodium.crypto_sign_seed_keypair(
      Buffer.from(seedHex64, 'hex') // convert hex str into buffer
    )
    // ed to curve pubkey
    const x25519PublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(
      ed25519KeyPair.publicKey
    )
    // prepend 05 (version)
    const origPub = new Uint8Array(x25519PublicKey)
    const prependedX25519PublicKey = new Uint8Array(33)
    prependedX25519PublicKey.set(origPub, 1)
    prependedX25519PublicKey[0] = 5

    // ed to curve private
    const x25519SecretKey = sodium.crypto_sign_ed25519_sk_to_curve25519(
      ed25519KeyPair.privateKey
    )

    return {
      // is this safe in node?
      privKey: Buffer.from(x25519SecretKey.buffer),
      pubKey: Buffer.from(prependedX25519PublicKey.buffer),
      ed25519KeyPair,
    }
  } catch (err) {
    return {
      err: err
    }
  }
}

// new random one...
async function newKeypair() {
  const seedBuf = crypto.randomBytes(SEEDSIZE)
  const words = await mnemonic.mn_encode(seedBuf.toString('hex'))
  const keypair = await wordsToKeyPairV3(words)
  if (keypair.err) {
    console.error('mnemonic::::index::newKeypair - err', keypair.err)
    return false
  }
  return {
    keypair: keypair,
    words: words
  }
}

module.exports = {
  newKeypair,
  wordsToKeyPair,
}
