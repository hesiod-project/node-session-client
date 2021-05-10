const protobuf = require('protobufjs')
const path   = require('path')
const crypto = require('crypto')

const protoPath = path.join(__dirname, '../external/protos/')

protobuf.load(protoPath + 'SubProtocol.proto', function(err, protoRoot) {
  if (err) console.error('proto err', err)
  module.exports.WebSocketMessage = protoRoot.lookupType('WebSocketMessage')
  module.exports.WebSocketRequestMessage = protoRoot.lookupType('WebSocketRequestMessage')
})
protobuf.load(protoPath + 'SignalService.proto', function(err, signalRoot) {
  if (err) console.error('proto err', err)
  module.exports.Envelope = signalRoot.lookupType('Envelope')
  module.exports.Content = signalRoot.lookupType('Content')
  module.exports.DataMessage = signalRoot.lookupType('DataMessage')
  module.exports.AttachmentPointer = signalRoot.lookupType('AttachmentPointer')
  module.exports.LokiProfile = signalRoot.lookupType('LokiProfile')
  module.exports.GroupInvitation = signalRoot.lookupType('GroupInvitation')
  //module.exports.PreKeyBundleMessage = signalRoot.lookupType('PreKeyBundleMessage')
})
// I don't think this is used any more
/*
protobuf.load(protoPath + 'UnidentifiedDelivery.proto', function(err, uniddelRoot) {
  if (err) console.error('proto err', err)
  module.exports.UnidentifiedSenderMessage = uniddelRoot.lookupType('UnidentifiedSenderMessage')
  module.exports.SenderCertificate = uniddelRoot.lookupType('SenderCertificate')
})
*/

function unpad(paddedData) {
  //console.log('unpad', paddedData)
  const paddedPlaintext = new Uint8Array(paddedData)
  //console.log('unpad last char is', paddedPlaintext[paddedPlaintext.length - 1])
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

function encodeContentMessage(text, ts, options) {
  const rawDM = {
    body: text,
    timestamp: ts,
  }
  if (options.attachments) {
    console.log('protobuf::encodeContentMessage - setting attachments', options.attachments.length)
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
      // convert buffer into Uint8Array
      const pk8 = new Uint8Array(b.buffer, b.byteOffset, b.byteLength)

      rawDM.profileKey = pk8
    }
    rawDM.profile = profile
  }
  if (options.groupInvitation) {
    // yea we don't need to create a protobuf for these sub-structures
    rawDM.groupInvitation = options.groupInvitation
  }
  if (options.flags) {
    rawDM.flags = options.flags
  }
  if (options.nullMessage) {
    const buffer = crypto.randomBytes(1) // random int between 1 and 512
    const paddingLength = (new Uint8Array(buffer)[0] & 0x1ff) + 1
    console.log('protobuf::encodeContentMessage - paddingLength', paddingLength)
    rawDM.nullMessage = {
      padding: crypto.randomBytes(paddingLength)
    }
    // may need to tweak TTL for push notes on the recving end
    // Constants.TTL_DEFAULT.SESSION_ESTABLISHED
    // ttl = (2 * 86400) - (1 * 3600)

    // also maybe encrypted different...
  }
  if (rawDM.body === undefined) rawDM.body = ''
  const errMsg5 = module.exports.DataMessage.verify(rawDM)
  if (errMsg5) console.error('protobuf::encodeContentMessage - rawDM verification', errMsg5)
  const dmWrapper = module.exports.DataMessage.create(rawDM)
  const rawContent = {
    dataMessage: dmWrapper
  }
  const errMsg = module.exports.Content.verify(rawContent)
  if (errMsg) console.error('protobuf::encodeContentMessage - rawContent verification', errMsg)
  const contentWrapper = module.exports.Content.create(rawContent)
  const contentBuf = module.exports.Content.encode(contentWrapper).finish()
  // padPlainTextBuffer returns Uint8Array
  return padPlainTextBuffer(contentBuf)
  //console.log('plaintextBuf', plaintextBuf, 'plaintextBuf', plaintextBuf.toString())
}

// plaintext is output from sodium
// maybe uint8_array
// seems to like node Buffer tho
function decodeContentMessage(plaintext, id) {
  // might need to unpad plaintext
  let unpaddedPlaintext
  try {
    unpaddedPlaintext = unpad(plaintext)
  } catch (e) {
    console.log('protobuf::decodeContentMessage - unpadding failure', id, e)
    return
  }

  let content
  try {
    content = module.exports.Content.decode(new Uint8Array(unpaddedPlaintext))
  } catch (e) {
    console.log('protobuf::decodeContentMessage - content decode failure', e)
    return
  }
  return content
}

module.exports = {
  padPlainTextBuffer,
  encodeContentMessage,
  decodeContentMessage,
}
