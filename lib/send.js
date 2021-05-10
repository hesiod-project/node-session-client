const protobuf = require('./protobuf.js')
const _sodium = require('libsodium-wrappers') // maybe put in session-client?

async function send(toPubkey, sourceKeypair, body, lib, options = {}) {
  await _sodium.ready
  const sodium = _sodium
  if (!sourceKeypair.ed25519KeyPair) {
    console.error('sourceKeypair does not have an ed25519 to send messages with')
    return
  }

  // Constants.TTL_DEFAULT.REGULAR_MESSAGE
  const ttl = 2 * 86400 * 1000 // in ms
  const timestamp = Date.now()

  const swarmUrl = await lib.getSwarmsnodeUrl(toPubkey)

  // we need to cipher something...
  // device is pubkey... (cast?)
  // pt buf and encryption(fb) comes from message...
  // put cipherText into content...

  // MessageSender.ts
  //console.log('sending to', toPubkey)
  const destinationBuf = Buffer.from(toPubkey, 'hex').subarray(1)

  const plaintext = protobuf.encodeContentMessage(body, timestamp, options)
  const verificationData = Buffer.concat([
    plaintext,
    sourceKeypair.ed25519KeyPair.publicKey,
    destinationBuf
  ])
  let signature
  try {
    signature = sodium.crypto_sign_detached(
      verificationData,
      sourceKeypair.ed25519KeyPair.privateKey
    )
  } catch (e) {
    console.error('send failed', e)
    return
  }
  const plaintextWithMetadata = Buffer.concat([
    plaintext,
    sourceKeypair.ed25519KeyPair.publicKey,
    signature
  ])
  const content = sodium.crypto_box_seal(
    plaintextWithMetadata,
    destinationBuf
  )
  if (!content) {
    console.error('send failed, could not encrypt')
    return
  }

  /*
  const content = fallbackUtils.fallbackEncrypt(
    sourceKeypair.privKey, toPubkey, protobuf.padPlainTextBuffer(contentBuf)
  )
  */
  // build an envelope
  const rawEnv = {
    // FALLBACK_MESSAGE
    //type: 101,
    // UNIDENTIFIED
    type: 6,
    source: sourceKeypair.pubKey.toString('hex'),
    sourceDevice: 1,
    timestamp: timestamp,
    // looking for a uint8array
    content: content
  }
  //console.log('env', rawEnv)
  const errMsg2 = protobuf.Envelope.verify(rawEnv)
  if (errMsg2) console.error('rawEnv verification', errMsg2)
  const envWrapper = protobuf.Envelope.create(rawEnv)
  const envBuf = protobuf.Envelope.encode(envWrapper).finish()

  //console.log('test env', envBuf)

  // MessageSender.ts
  const rawWsr = {
    id: 0,
    body: envBuf,
    verb: 'PUT',
    path: '/api/v1/message'
  }
  const errMsg3 = protobuf.WebSocketRequestMessage.verify(rawWsr)
  if (errMsg3) console.error('rawWsr verification', errMsg3)
  const wsrWrapper = protobuf.WebSocketRequestMessage.create(rawWsr)

  const rawWs = {
    // SignalService.WebSocketMessage.Type.REQUEST
    type: 1,
    request: wsrWrapper
  }
  const errMsg4 = protobuf.WebSocketMessage.verify(rawWs)
  if (errMsg4) console.error('rawWs verification', errMsg4)
  const wsWrapper = protobuf.WebSocketMessage.create(rawWs)
  const wsBuf = protobuf.WebSocketMessage.encode(wsWrapper).finish()

  // convert data to base64...
  const data64 = wsBuf.toString('base64')

  // loki_message.js
  const storeParams = {
    ttl: ttl.toString(),
    timestamp: timestamp.toString(),
    data: data64
  }
  const storeData = await lib.pubKeyAsk(swarmUrl, 'store', toPubkey, storeParams)
  // object, { difficulty: 1 }
  if (storeData.difficulty !== 1) {
    console.log('storeData', storeData)
    return false
  }
  return true
}

module.exports = {
  send
}
