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

  const openGroupV2URL = 'http://open2.hesiod.network/build_a_bot?public_key=58dc124cc38e4d03449037e9a4a86a2e5c2a648938eb824a5cdf3b6a80fab07d'
  const ogv2Handle = await client.joinOpenGroupV2(openGroupV2URL)

  // handle incoming messages
  client.on('messages', msgs => {
    msgs.forEach(async msg => {
      if (msg.room) {
        console.log(`New message, In group: ${msg.id} in ${msg.room}`)
      } else {
        console.log('New message, Private')
      }
      console.log(`From: ${msg.profile && msg.profile.displayName} (${msg.source})`)
      console.log(msg.body)

      // Download their avatar
      // change 0 to 1 if you want to download avatars from users that you receive
      if (0 && msg.profile && msg.profile.profilePicture) {
        const avatarBuf = await client.decodeAvatar(msg.profile.profilePicture, msg.profileKey)
        // write it to disk
        fs.writeFileSync(msg.source + '.avatar', avatarBuf)
      }

      // Attachment processing example
      // change 0 to 1 if you want to download (the first) attachment sent to you
      if (0) {
        if (msg.attachments.length) {
          const attachments = await client.getAttachments(msg)
          //console.log('attachment', attachments[0])
          if (attachments[0]) { // if no errors
            fs.writeFileSync(msg.source + '.attachment', attachments[0])
          }
        }
      }
      /*
      // Open group invitation example
      if (msg.groupInvitation) {
        console.log('got invite to channel', msg.groupInvitation.channelId)
      }
      */
    })
  })
  // the await here allows send to reuse the cache it builds
  await client.open()

  // TODO: replace with your SessionID
  const SessionID = ''

  // LNS example
  //
  //const lnsUtils = require('./lib/lns.js')
  //const pubkey = await lnsUtils.getNameFast('root')
  //console.log('sid for root', pubkey)

  // Send message example
  //
  // need an image
  //const attachment = await client.makeImageAttachment(fs.readFileSync('/Users/user2/Pictures/1587699732-0s.png'))
  //
  // change 0 to 1 if you want to send a message to SessionID
  if (0) {
    client.send(SessionID, 'Hello', {
      // attachments: [attachment]
    }).then(() => {
      console.debug('Sent "Hello" to', SessionID)
    })
  }
  // Open group invite example
  // change 0 to 1 if you want to send an open group invite to SessionID
  if (0) {
    client.sendOpenGroupInvite(SessionID, 'Bob\'s server', '')
  }

  // change 0 to 1 if you want to send a message to an open group
  if (0 && ogv2Handle) {
    const messageId = await client.sendOpenGroupV2Message(ogv2Handle, 'Hello World SOGSv2 from node-session-client')
    // change 0 to 1 if you want to delete that message you sent to an open group
    if (0) {
      await client.deleteOpenGroupV2Message(ogv2Handle, messageId)
    }
  }
})
