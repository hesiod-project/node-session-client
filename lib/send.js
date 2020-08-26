const pow = require('../external/libloki/proof-of-work.js')
const protobuf = require('./protobuf.js')
const fallbackUtils = require('../port/fallback.js')

function getPaddedMessageLength(originalLength) {
  const messageLengthWithTerminator = originalLength + 1
  let messagePartCount = Math.floor(messageLengthWithTerminator / 160)

  if (messageLengthWithTerminator % 160 !== 0) {
    messagePartCount += 1
  }

  return messagePartCount * 160
}

function padPlainTextBuffer(messageBuffer) {
  const plaintext = new Uint8Array(
    getPaddedMessageLength(messageBuffer.byteLength + 1) - 1
  )
  plaintext.set(new Uint8Array(messageBuffer))
  plaintext[messageBuffer.byteLength] = 0x80

  return plaintext
}

async function send(toPubkey, sourceKeypair, body, lib, options = {}) {
  // Constants.TTL_DEFAULT.REGULAR_MESSAGE
  const ttl = 2 * 86400 * 1000 // in ms
  const timestamp = Date.now()
  const difficulty = 1

  const swarmUrl = await lib.getSwarmsnodeUrl(toPubkey)

  const rawDM = {
    body: body,
    timestamp: timestamp
  }
  if (options.attachments) {
    console.log('setting attachments', options.attachments.length)
    rawDM.attachments = options.attachments
  }
  if (options && (options.displayName || options.avatar)) {
    const profile = {}
    if (options.displayName) {
      profile.displayName = options.displayName
    }
    if (options.avatar) {
      // this is the avatarPointer, a URL on the file server...
      profile.avatar   = options.avatar.url

      const b = options.avatar.profileKeyBuf
      const pk8 = new Uint8Array(b.buffer, b.byteOffset, b.byteLength)

      rawDM.profileKey = pk8
    }
    rawDM.profile = protobuf.LokiProfile.create(profile)
  }
  const errMsg5 = protobuf.DataMessage.verify(rawDM)
  if (errMsg5) console.error('rawDM verification', errMsg5)
  const dmWrapper = protobuf.DataMessage.create(rawDM)
  //console.log('dmWrapper', dmWrapper)

  const rawContent = {
    dataMessage: dmWrapper
  }
  // console.log('rawContent', rawContent)
  const errMsg = protobuf.Content.verify(rawContent)
  if (errMsg) console.error('rawContent verification', errMsg)
  const contentWrapper = protobuf.Content.create(rawContent)
  //console.log('contentWrapper', contentWrapper)

  // what happens here...
  // should be an uint8array
  const contentBuf = protobuf.Content.encode(contentWrapper).finish()
  //console.log('contentBuf', contentBuf)

  // we need to cipher something...
  // device is pubkey... (cast?)
  // pt buf and encryption(fb) comes from message...
  // put cipherText into content...

  // MessageSender.ts
  //console.log('sending to', toPubkey)
  const content = fallbackUtils.fallbackEncrypt(
    sourceKeypair.privKey, toPubkey, padPlainTextBuffer(contentBuf)
  )
  const rawEnv = {
    // FALLBACK_MESSAGE
    type: 101,
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
  //pow.calcPoW(timestamp, ttl, toPubkey, data64, difficulty)
  const nonce = await pow.calcPoW(timestamp, ttl, toPubkey, data64, difficulty)
  //console.log('nonce', nonce, 'data64', data64)

  // loki_message
  const storeParams = {
    pubKey: toPubkey,
    ttl: ttl.toString(),
    nonce: nonce,
    timestamp: timestamp.toString(),
    data: data64
  }
  //console.log('storeParams', storeParams)
  const storeData = await lib.jsonrpc(swarmUrl, 'store', storeParams)
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
