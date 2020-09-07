const fs = require('fs') // for loading state
// may need to adjust path until npm version is available
const SessionClient = require('./session-client.js')

// create an instance
// You'll want an instance per SessionID you want to receive messages for
const client = new SessionClient()

// load place in inbox if available
if (fs.existsSync('lastHash.txt')) {
  client.lastHash = fs.readFileSync('lastHash.txt').toString()
}

// load an SessionID into client and set some options
client.loadIdentity({
  // load recovery phrase if available
  seed: fs.existsSync('seed.txt') && fs.readFileSync('seed.txt').toString(),
  displayName: 'Sample Session Client',
  // path to local file
  //avatarFile: 'avatar.png',
}).then(async () => {
  // output recovery phrase if making an identity
  console.log(client.identityOutput)

  // persist place in inbox incase we restart
  client.on('updateLastHash', hash => {
    fs.writeFileSync('lastHash.txt', hash)
  })

  await client.joinOpenGroup('session.lokisn.com')

  // handle incoming messages
  client.on('messages', msgs => {
    msgs.forEach(async msg => {

      console.log()
      console.log(`New message, ${msg.openGroup ? `In group: ${msg.openGroup}` : 'Private'}:`)
      console.log(`From: ${msg.profile.displayName} (${msg.source})`)
      console.log(msg.body)

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
  // the await here allows send to reuse the cache it builds
  await client.open()

  // TODO: replace with your SessionID
  const SessionID = '05d233c6c8daed63a48dfc872a6602512fd5a18fc764a6d75a08b9b25e7562851a'
  // LNS example
  //
  //const lnsUtils = require('./lib/lns.js')
  //const pubkey = await lnsUtils.getNameFast('root')
  //console.log('sid for root', pubkey)

  // Send message example
  //
  // need an image
  //const attachment = await client.makeImageAttachment(fs.readFileSync('/Users/user2/Pictures/1587699732-0s.png'))
  client.send(SessionID, 'Hello', {
    // attachments: [attachment]
  })

  // Open group invite example
  // only works on desktop
  //client.sendOpenGroupInvite(toPubkey, 'Bob\'s server', 'chat-dev.lokinet.org', 2)
})
