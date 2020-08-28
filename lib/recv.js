const libsignal = require('libsignal')
const crypto = require('crypto')
const signalcrypto = require('../port/signal-crypto.js')
const protobuf = require('./protobuf.js')
const fallbackUtils = require('../port/fallback.js')

const CIPHERTEXT_VERSION = 1
const UNIDENTIFIED_DELIVERY_PREFIX = 'UnidentifiedDelivery'

// for debugging...
function buf2hex(buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('')
}

async function _calculateEphemeralKeys(ephemeralPublic, ephemeralPrivate, salt) {
  const ephemeralSecret = libsignal.curve.calculateAgreement(
    ephemeralPublic,
    ephemeralPrivate
  )
  // will this work...

  // salt expects 32 bytes, and we're giving it like 86 here...
  //const newSalt = salt.slice(54)
  /*
  const newSalt = salt.slice(0, 32)
  //console.log('newSalt', newSalt.byteLength)
  console.log('newSalt', newSalt) // is correct
  console.log('ephemeralSecret', ephemeralSecret) // is correct
  const ephemeralDerivedParts = await libsignal.crypto.deriveSecrets(
    ephemeralSecret,
    newSalt,
    Buffer.alloc(0)
  );
  console.log('ephemeralDerivedParts', ephemeralDerivedParts)
  */

  // last needs to be an arrayBuffer
  const ephemeralDerivedParts = await signalcrypto.HKDF(ephemeralSecret, salt, new ArrayBuffer())
  /*
  console.log('ephemeralDerivedParts2.chainK', buf2hex(ephemeralDerivedParts2[0]))
  console.log('ephemeralDerivedParts2.cipher', buf2hex(ephemeralDerivedParts2[1]))
  console.log('ephemeralDerivedParts2.macKey', buf2hex(ephemeralDerivedParts2[2]))
  */

  // keep it as buffers...
  return {
    chainKey: Buffer.from(ephemeralDerivedParts[0]),
    cipherKey: Buffer.from(ephemeralDerivedParts[1]),
    macKey: Buffer.from(ephemeralDerivedParts[2])
  }
}

async function _decryptWithSecretKeys(cipherKey, macKey, ciphertext) {
  if (ciphertext.byteLength < 10) {
    throw new Error('Ciphertext not long enough for MAC!')
  }

  const ciphertextWoMac = ciphertext.slice(0, ciphertext.byteLength - 10)
  const theirMac = ciphertext.slice(ciphertext.byteLength - 10) // last 10 bytes

  const digest = crypto.createHmac('sha256', macKey).update(ciphertextWoMac).digest()
  const ourMac = digest.slice(0, 10)

  if (Buffer.compare(ourMac, theirMac)) {
    throw new Error('Bad mac!')
    //console.log('nBad mac!')
  }

  return signalcrypto.decryptAesCtr(cipherKey, ciphertextWoMac, Buffer.alloc(16, 0))
}

// would be used for encrypt too
// FIXME: move out
async function _calculateStaticKeys(staticPublic, staticPrivate, salt) {
  //console.log('staticPublic', typeof(staticPublic), staticPublic)
  //console.log('staticPrivate', typeof(staticPrivate), staticPrivate)
  const staticSecret = libsignal.curve.calculateAgreement(
    staticPublic,
    staticPrivate
  )
  const staticDerivedParts = await signalcrypto.HKDF(
    staticSecret,
    salt,
    new ArrayBuffer()
  )

  // private StaticKeys(byte[] cipherKey, byte[] macKey)
  return {
    cipherKey: Buffer.from(staticDerivedParts[1]),
    macKey: Buffer.from(staticDerivedParts[2])
  }
}

function unpad(paddedData) {
  const paddedPlaintext = new Uint8Array(paddedData)

  for (let i = paddedPlaintext.length - 1; i >= 0; i -= 1) {
    if (paddedPlaintext[i] === 0x80) {
      const plaintext = new Uint8Array(i)
      plaintext.set(paddedPlaintext.subarray(0, i))
      return plaintext.buffer
    } else if (paddedPlaintext[i] !== 0x00) {
      throw new Error('Invalid padding')
    }
  }

  throw new Error('Invalid padding')
}

async function handleUnidentifiedMessageType(env, ourKeypair) {
  // get version
  const version = (env.content[0] & 0xff) >> 4

  // check version
  if (version > CIPHERTEXT_VERSION) {
    throw new Error(`Unknown version: ${this.version}`)
  }

  // decode remainder
  const wrapper = protobuf.UnidentifiedSenderMessage.decode(env.content.slice(1))

  // doDecrypt in recv/contentMessage.ts
  const ephemeralSalt = Buffer.concat([
    Buffer.from(UNIDENTIFIED_DELIVERY_PREFIX), // 20 bytes
    ourKeypair.pubKey, // 33 bytes? buffer
    wrapper.ephemeralPublic // 33 bytes? buffer
  ]) // 86 bytes

  // all libsignal.crypto.deriveSecrets
  const ephemeralKeys = await _calculateEphemeralKeys(
    wrapper.ephemeralPublic,
    ourKeypair.privKey,
    ephemeralSalt
  )
  // get staticKeyBytes
  const staticKeyBytes = await _decryptWithSecretKeys(
    ephemeralKeys.cipherKey,
    ephemeralKeys.macKey,
    wrapper.encryptedStatic
  )
  // make staticSalt form ephermalKeys and encryptedStatic
  const staticSalt = Buffer.concat([
    ephemeralKeys.chainKey,
    wrapper.encryptedStatic
  ])
  // get staticKeys
  const staticKeys = await _calculateStaticKeys(
    Buffer.from(staticKeyBytes),
    ourKeypair.privKey,
    staticSalt
  )
  // get messageBytes
  const messageBytes = await _decryptWithSecretKeys(
    staticKeys.cipherKey,
    staticKeys.macKey,
    wrapper.encryptedMessage
  )
  const message = protobuf.UnidentifiedSenderMessage.Message.decode(
    Buffer.from(messageBytes)
  )
  if (!message.type || !message.senderCertificate || !message.content) {
    throw new Error('Missing fields')
  }

  let type
  // FIXME: convert to map
  // map protobuf to env type
  switch (message.type) {
    case 1: // prekey
      type = 3
      break
    case 2: // message
      type = 1
      break
    case 3: // friend request
      type = 101
      break
    default:
      throw new Error(`Unknown type: ${message.type}`)
  }
  //senderCertificate: senderCert, <= but not used
  //senderCertificate: message.senderCertificate,
  //content: message.content,
  //serialized: messageBytes

  //console.log('content', content)
  if (type === 101) {
    // loki friend request / PreKeyBundleMessage
    // decryptPreKeyWhisperMessage => doDecrypt => decrypt()
    const padded = fallbackUtils.fallbackDecrypt(
      ourKeypair.privKey, message.senderCertificate.sender, message.content
    )
    const plaintext = unpad(padded)
    // innerHandleContentMessage

    const content = protobuf.Content.decode(new Uint8Array(plaintext))
    //console.log('content', content)

    /*
    if (content.preKeyBundleMessage) {
      // holy shit contnet.dataMessage.body has content
      console.log('got preKeyBundleMessage', content.preKeyBundleMessage)
      // handleSessionRequestMessage in recv/sessionHandling
      //const preKeyMsg = protobuf.PreKeyBundleMessage.decode(plaintext)
      //console.log('preKeyMsg', preKeyMsg)
      */
    // store these keys for this convo
    /*
PreKeyBundleMessage {
  identityKey: Uint8Array(33) [
      5, 210,  51, 198, 200, 218, 237,  99,
    164, 141, 252, 135,  42, 102,   2,  81,
     47, 213, 161, 143, 199, 100, 166, 215,
     90,   8, 185, 178,  94, 117,  98, 133,
     26
  ],
  deviceId: 1,
  preKeyId: 122,
  signedKeyId: 10,
  preKey: Uint8Array(33) [
      5, 119, 26, 197, 201,  35, 127, 164,
     35, 118, 54, 100, 238, 247, 222, 182,
    191,  39,  0, 229, 199, 198, 192,  89,
    148,  40, 83, 148,  91,   2,  78,  91,
     14
  ],
  signedKey: Uint8Array(33) [
      5, 237, 214,  52, 248, 168, 187, 230,
     77,   8, 114,  14,  40,  65,  37,  14,
    238, 142,  30, 160, 193, 219,  90, 198,
    199, 100, 144, 218,  28, 107, 155, 233,
     47
  ],
  signature: Uint8Array(64) [
     89, 191, 253,  96,  10, 253,  46,   5, 197, 188, 247,
    129, 254, 220, 150,  82, 246, 233,  41, 208, 230,  28,
    115, 121, 116, 103,  85, 134,  16,  84,  98, 200,   6,
    242, 133, 253, 113,  83,  10,  25,  30, 234,  49, 255,
      8,  82, 249,   1, 200, 211,  39,  10,   2,  73, 100,
    121, 146, 226,  20,  42, 224, 210, 155,   9
  ]
      */
    /*
      // generate keys to send back...
    }
    if (content.dataMessage) {
      //console.log('got message', content.dataMessage)

      // iOS sends a blank body message...
      if (content.dataMessage.body || content.dataMessage.attachments) {
        //return {...content.dataMessage, source: message.senderCertificate.sender}
      } else {
        console.warn('spurious iOS message?', content)
      }
    }
    */
    return { ...content, source: message.senderCertificate.sender }
  } else {
    console.warn('unhandled innerContent type', type, 'message type', message.type)
  }
}

const decodeMessageMap = {
  // UNIDENTIFIED_SENDER
  6: handleUnidentifiedMessageType
}

function handleMessage(msg, ourKeypair) {
  // encode message as base64 and then uint8array
  const buf = Buffer.from(msg.data, 'base64')

  // handle ws/wsr
  const wsMessage = protobuf.WebSocketMessage.decode(buf)
  // now turn message.request.body into an envelope
  /*
message WebSocketMessage {
type: 1,
request:
WebSocketRequestMessage {
headers: [],
verb: 'PUT',
path: '/api/v1/message',
body:
<Buffer 08 06 12 00 28 a8 cf ee db bb 2e 38 00 42 fb 03 11 0a 21 05 c1 2f 19 01 ef 8e 62 8f 8e f3 58 25 42 47 de cc 5d 43 e3 a1 70 dd 22 1e f7 c7 68 63 c9 d5 ... >,
id: Long { low: -347036081, high: 1342692244, unsigned: true } } }
*/
  //console.log('message', message)
  if (wsMessage.type !== 1 || !wsMessage.request) {
    console.warn('unhandled websocket message', wsMessage)
    return
  }
  // recv/contentMessage.ts - handle envelope contnet
  const env = protobuf.Envelope.decode(wsMessage.request.body)
  /*
Envelope {
type: 6,
timestamp: Long { low: -1066270830, high: 371, unsigned: true },
sourceDevice: 1,
content:
<Buffer 11 0a 21 05 1c 97 2a 1b d8 d7 35 38 01 4f 90 eb 66 18 9d 96 36 b6 da d5 ac a6 21 ab 8f 02 ce 46 8c 7f d0 29 12 2b 2e 71 4c a5 14 50 2a 10 1a fe 2b f3 ... > }
*/
  if (decodeMessageMap[env.type]) {
    return decodeMessageMap[env.type](env, ourKeypair)
  } else {
    console.warn('unhandled envelope type', env.type)
  }
}

async function checkBox(pubKey, swarmUrl, ourKeypair, inLasthash, lib) {
  //console.log('snodes', snodeData.snodes)
  const messageData = await lib.jsonrpc(swarmUrl, 'retrieve', {
    pubKey: pubKey, lastHash: inLasthash
  })
  if (!messageData) {
    console.error('recv::checkBox - no messageData')
    return
  }
  if (!messageData.messages) {
    // Service node is not ready: not in any swarm; not done syncing;
    console.log('(missing messages) messageData', messageData)
  }
  if (messageData.messages && messageData.messages.length) {
    // console.log('messageData', messageData.messages[0].data)
  } else {
    //console.log('no messages')
  }
  let outLasthash = inLasthash
  let newMsgs = []
  // just make sure it's an array
  if (messageData.messages && messageData.messages.length) {
    newMsgs = await Promise.all(messageData.messages.map(async msg => {
      /*
       { data:
              'CAESrgQKA1BVVBIPL2FwaS92MS9tZXNzYWdlGosECAYSACioz+7buy44AEL7AxEKIQXBLxkB745ij47zWCVCR97MXUPjoXDdIh73x2hjydWUQxIrIcl/2e/kdA0xfFj9hyDLkv9yHxdPSmsKxBpZOPyX0nDuHyHdnICArMjNixqnAx0UKnuvmKiPvUh5To22BbpgZ6L4GJwLjL2t/KtX4ufQZ955wzCseM9r+1E0/1cWf6uqax1nQbcAkPiqrMTzoQ+9r02HA5DrYRdI5azyQjB7uOHYcEmBmXj3mW93gA53jD6ohkxdFDEd0Jimo69geQug/iksB5/eLUbcT1lQjWYbsu0U22lvqv6vSTUEzBJcP46fcrLoBt1nb2KkZv5okGETQISc2RLBd1hIctitclhReXWvc/sKtXaU49sCCdR6EjzoKLQojIy0+yPjBDyK7n+Io/gnPPBU4t78QxuWxAQuRvb1x+xU/NLHEosNa9ArnCbzlDwXyyYRhFv6d4W3Q4fXy/Bbsu6rj3S/vomgtQPdt9Xu6vwn/eoWeKsB9PV7ON19AYRhOeDdhM5lMcg8SvyT/dKSNlInadEeiuTRxpDJGQ3yC1CkMwo8BEpnr64XMQ14UvZOC2/JLBMFTHQIbRcu96RJdseUb9edtW7uyxEEu/fve9NZWAPb3tX0m288ZzpoIH5PgXLRzhN0Z68CyoeCEuO7RU7B6TKqW8H7DBZgnbIv/ECFeyDPzMLazvL2g1A=',
             expiration: 1596747510107,
             hash:
              '0002fd94c689db923cba606efa53e1ecb8541bc2afa51793a2f7d5c4c6cda4937a3aa532096e15d1ba9109ee5553cda4985bdb0427bf2934b399c8b198cd72ab'
      */
      //console.log('msg', msg)
      //if (msg.expiration === 1596767387535) return
      outLasthash = msg.hash
      return handleMessage(msg, ourKeypair)
    }))
  }
  return {
    lastHash: outLasthash,
    messages: newMsgs.filter(msg => !!msg)
  }
}

module.exports = {
  checkBox
}
