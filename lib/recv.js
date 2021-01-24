const protobuf = require('./protobuf.js')
const _sodium = require('libsodium-wrappers') // maybe put in session-client?

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
  await _sodium.ready
  const sodium = _sodium

  // decode session protocol

  // 1. decrypt message
  const stripedPK = ourKeypair.pubKey.subarray(1)
  let plaintext, senderX25519PublicKey
  try {
    // sometimes get an incorrect keypair here...
    const plaintextWithMetadata = sodium.crypto_box_seal_open(
      new Uint8Array(env.content),
      stripedPK, // strip 05
      ourKeypair.privKey
    )
    // integrity check
    const minSize = sodium.crypto_sign_BYTES +  sodium.crypto_sign_PUBLICKEYBYTES
    if (plaintextWithMetadata.byteLength <= minSize) {
      console.error('decryption failed', plaintextWithMetadata.byteLength, 'is less than', minSize)
      return false
    }

    // 2. get message parts
    const metadataPos = plaintextWithMetadata.byteLength - minSize
    plaintext = plaintextWithMetadata.subarray(0, metadataPos)
    const signPos = plaintextWithMetadata.byteLength - sodium.crypto_sign_BYTES
    const senderED25519PublicKey = plaintextWithMetadata.subarray(metadataPos, signPos)
    const signature = plaintextWithMetadata.subarray(signPos)

    // 3. verify sig
    const isValid = sodium.crypto_sign_verify_detached(
      signature,
      Buffer.concat([plaintext, senderED25519PublicKey, stripedPK]),
      senderED25519PublicKey
    )
    if (!isValid) {
      console.error('decryption failed - bad signature')
      return false
    }

    // 4. get senders pubkey
    senderX25519PublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(
      senderED25519PublicKey
    ) // Uint8Array
    if (!senderX25519PublicKey) {
      console.error('decryption failed - curve conversion')
      return false
    }
  } catch(e) {
    console.log('recv failure', e)
    return
  }

  // might need to unpad plaintext
  const unpaddedPlaintext = unpad(plaintext)

  const content = protobuf.Content.decode(new Uint8Array(unpaddedPlaintext))
  return { ...content, source: `05${Buffer.from(senderX25519PublicKey).toString('hex')}` }
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

async function checkBox(pubKey, ourKeypair, inLasthash, lib, debug) {
  if (inLasthash === null) {
    console.trace('recv::checkBox - inLasthash can not be null')
    inLasthash = undefined
  }
  //console.log('snodes', snodeData.snodes)
  const url = await lib.getSwarmsnodeUrl(pubKey)
  if (debug) console.log('jsonrpc start', url, pubKey, inLasthash)
  const messageData = await lib.pubKeyAsk(url, 'retrieve', pubKey, {
    lastHash: inLasthash
  })
  if (debug) console.log('jsonrpc end')
  if (!messageData) {
    //console.error('recv::checkBox - no messageData')
    return
  }
  if (!messageData.messages) {
    // Service node is not ready: not in any swarm; not done syncing;
    console.log('(missing messages) messageData', messageData)
  }
  let outLasthash = inLasthash
  let newMsgs = []
  // just make sure it's an array
  if (messageData.messages && messageData.messages.length) {
    // console.log('got', messageData.messages.length, 'msgs for', pubKey)
    newMsgs = await Promise.all(messageData.messages.map(async msg => {
      /*
       { data:
              'CAESrgQKA1BVVBIPL2FwaS92MS9tZXNzYWdlGosECAYSACioz+7buy44AEL7AxEKIQXBLxkB745ij47zWCVCR97MXUPjoXDdIh73x2hjydWUQxIrIcl/2e/kdA0xfFj9hyDLkv9yHxdPSmsKxBpZOPyX0nDuHyHdnICArMjNixqnAx0UKnuvmKiPvUh5To22BbpgZ6L4GJwLjL2t/KtX4ufQZ955wzCseM9r+1E0/1cWf6uqax1nQbcAkPiqrMTzoQ+9r02HA5DrYRdI5azyQjB7uOHYcEmBmXj3mW93gA53jD6ohkxdFDEd0Jimo69geQug/iksB5/eLUbcT1lQjWYbsu0U22lvqv6vSTUEzBJcP46fcrLoBt1nb2KkZv5okGETQISc2RLBd1hIctitclhReXWvc/sKtXaU49sCCdR6EjzoKLQojIy0+yPjBDyK7n+Io/gnPPBU4t78QxuWxAQuRvb1x+xU/NLHEosNa9ArnCbzlDwXyyYRhFv6d4W3Q4fXy/Bbsu6rj3S/vomgtQPdt9Xu6vwn/eoWeKsB9PV7ON19AYRhOeDdhM5lMcg8SvyT/dKSNlInadEeiuTRxpDJGQ3yC1CkMwo8BEpnr64XMQ14UvZOC2/JLBMFTHQIbRcu96RJdseUb9edtW7uyxEEu/fve9NZWAPb3tX0m288ZzpoIH5PgXLRzhN0Z68CyoeCEuO7RU7B6TKqW8H7DBZgnbIv/ECFeyDPzMLazvL2g1A=',
             expiration: 1596747510107,
             hash:
              '0002fd94c689db923cba606efa53e1ecb8541bc2afa51793a2f7d5c4c6cda4937a3aa532096e15d1ba9109ee5553cda4985bdb0427bf2934b399c8b198cd72ab'
      */
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
