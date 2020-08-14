const crypto   = require('crypto')
const mnemonic = require('./mnemonic.js')
const curve    = require('curve25519-n')

const fromHexString = hexString =>
  new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const SEEDSIZE = 16 // gives 12 seed words

// words is a space separate string
function wordsToKeyPair(words) {
  // converting seed words to pubkey
  const seedHex32 = mnemonic.mn_decode(words)
  // double it
  const seedHex64 = seedHex32.concat(seedHex32).substring(0, 64)

  const priv1 = curve.makeSecretKey(Buffer.from(seedHex64, 'hex'));
  const publicBuffer = Buffer.concat([Buffer.from('05', 'hex'), curve.derivePublicKey(priv1)])

  return {
    privKey: priv1,
    pubKey: publicBuffer
  }
}

async function newKeypair() {
  const seedBuf = crypto.randomBytes(SEEDSIZE)
  const words = await mnemonic.mn_encode(seedBuf.toString('hex'))
  const keypair = wordsToKeyPair(words)
  return {
    keypair: keypair,
    words: words
  }
}

module.exports = {
  newKeypair,
  wordsToKeyPair,
}
