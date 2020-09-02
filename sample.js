const fs = require('fs')
const SessionClient = require('./session-client.js')

const client = new SessionClient()
// load place in inbox if available
if (fs.existsSync('lastHash.txt')) {
  client.lastHash = fs.readFileSync('lastHash.txt').toString()
}
client.loadIdentity({
  seed: fs.existsSync('seed.txt') && fs.readFileSync('seed.txt').toString(),
  displayName: 'Sample Session Client',
  //avatarFile: 'avatar.png',
}).then(async() => {
  console.log(client.identityOutput)

  // persist place in inbox incase we restart
  client.on('updateLastHash', hash => {
    fs.writeFileSync('lastHash.txt', hash)
  })

  // handle incoming messages
  client.on('messages', msgs => {
    msgs.forEach(async msg => {
      //console.log('msg', msg)
      // Attachment processing example
      /*
      if (msg.attachments.length) {
        const attachments = await client.getAttachments(msg)
        //console.log('attachment', attachments[0])
        fs.writeFileSync('imagetest.png', attachments[0])
      }
      */
      // Open group invitation example
      /*
      if (msg.groupInvitation) {
        console.log('got invite to channel', msg.groupInvitation.channelId)
      }
      */
    })
  })
  client.open()

  const toPubkey = '05d233c6c8daed63a48dfc872a6602512fd5a18fc764a6d75a08b9b25e7562851a'

  // LNS example
  //
  //const lnsUtils = require('./lib/lns.js')
  //const pubkey = await lnsUtils.getNameFast('root')
  //console.log('sid for root', pubkey)

  // Send message example
  //
  // need an image
  //const attachment = await client.makeAttachment(fs.readFileSync('/Users/user2/Pictures/1587699732-0s.png'))
  client.send(toPubkey, 'Hello', {
    // attachments: [attachment]
  })

  // Open group invite example
  // only works on desktop
  //client.sendOpenGroupInvite(toPubkey, 'Bob\'s server', 'chat-dev.lokinet.org', 2)
})
