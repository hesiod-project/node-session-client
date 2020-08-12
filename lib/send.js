const pow = require('../external/libloki/proof-of-work.js')
const protobuf = require('protobufjs')

const fallbackUtils = require('../port/fallback.js')

let WebSocketMessage, WebSocketRequestMessage
let Envelope, Content, DataMessage

protobuf.load('external/protos/SubProtocol.proto', function(err, protoRoot) {
  if (err) console.error('proto err', err)
  WebSocketMessage = protoRoot.lookupType('WebSocketMessage')
  WebSocketRequestMessage = protoRoot.lookupType('WebSocketRequestMessage')
})
protobuf.load('external/protos/SignalService.proto', async function(err, signalRoot) {
  if (err) console.error('proto err', err)
  Envelope = signalRoot.lookupType('Envelope')
  Content = signalRoot.lookupType('Content')
  DataMessage = signalRoot.lookupType('DataMessage')
})

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

async function send(toPubkey, sourceKeypair, body, lib) {
  // Constants.TTL_DEFAULT.REGULAR_MESSAGE
  const ttl = 2 * 86400 * 1000 // in ms
  const timestamp = Date.now()
  const difficulty = 1

  const swarmUrl = await lib.getSwarmsnodeUrl(toPubkey)

  const rawDM = {
    body: body,
    timestamp: timestamp
  }
  const errMsg5 = DataMessage.verify(rawDM)
  if (errMsg5) console.error('rawDM verification', errMsg5)
  const dmWrapper = DataMessage.create(rawDM)

  const rawContent = {
    dataMessage: dmWrapper
  }
  // console.log('rawContent', rawContent)
  const errMsg = Content.verify(rawContent)
  if (errMsg) console.error('rawContent verification', errMsg)
  const contentWrapper = Content.create(rawContent)
  //console.log('contentWrapper', contentWrapper)

  // what happens here...
  // should be an uint8array
  const contentBuf = Content.encode(contentWrapper).finish()
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
  const errMsg2 = Envelope.verify(rawEnv)
  if (errMsg2) console.error('rawEnv verification', errMsg2)
  const envWrapper = Envelope.create(rawEnv)
  const envBuf = Envelope.encode(envWrapper).finish()

  //console.log('test env', envBuf)

  // MessageSender.ts
  const rawWsr = {
    id: 0,
    body: envBuf,
    verb: 'PUT',
    path: '/api/v1/message'
  }
  const errMsg3 = WebSocketRequestMessage.verify(rawWsr)
  if (errMsg3) console.error('rawWsr verification', errMsg3)
  const wsrWrapper = WebSocketRequestMessage.create(rawWsr)

  const rawWs = {
    // SignalService.WebSocketMessage.Type.REQUEST
    type: 1,
    request: wsrWrapper
  }
  const errMsg4 = WebSocketMessage.verify(rawWs)
  if (errMsg4) console.error('rawWs verification', errMsg4)
  const wsWrapper = WebSocketMessage.create(rawWs)
  const wsBuf = WebSocketMessage.encode(wsWrapper).finish()

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
