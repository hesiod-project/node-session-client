const protobuf = require('protobufjs')
const path = require('path')

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
  module.exports.PreKeyBundleMessage = signalRoot.lookupType('PreKeyBundleMessage')
})
protobuf.load(protoPath + 'UnidentifiedDelivery.proto', function(err, uniddelRoot) {
  if (err) console.error('proto err', err)
  module.exports.UnidentifiedSenderMessage = uniddelRoot.lookupType('UnidentifiedSenderMessage')
  module.exports.SenderCertificate = uniddelRoot.lookupType('SenderCertificate')
})

module.exports = {
}
