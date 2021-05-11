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

  //const openGroupName = 'session.lokisn.com'
  //const openGroupName = 'feedback.getsession.org'
  const openGroupV2URL = 'http://open2.hesiod.network/build_a_bot?public_key=58dc124cc38e4d03449037e9a4a86a2e5c2a648938eb824a5cdf3b6a80fab07d'

  //const ogOpened = await client.joinOpenGroup(openGroupName)
  const ogv2Handle = await client.joinOpenGroupV2(openGroupV2URL)

  // handle incoming messages
  client.on('messages', msgs => {
    msgs.forEach(async msg => {
      /*
      if (msg.openGroup) {
        console.log(`New message, In group: ${msg.openGroup}`)
      } else */
      if (msg.room) {
        console.log(`New message, In group V2: ${msg.id} in ${msg.room}`)
      } else {
        console.log('New message, Private')
      }
      console.log(`From: ${msg.profile && msg.profile.displayName} (${msg.source})`)
      console.log(msg.body)

      // Attachment processing example
      if (0) {
        if (msg.attachments.length) {
          const attachments = await client.getAttachments(msg)
          //console.log('attachment', attachments[0])
          fs.writeFileSync('imagetest.png', attachments[0])
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
  if (0) {
    client.send(SessionID, 'Hello', {
      // attachments: [attachment]
    }).then(() => {
      console.debug('Sent "Hello" to', SessionID)
    })
  }

  /*
  if (ogOpened) {
    const messageId = await client.sendOpenGroupMessage(openGroupName, 'Sample Open Group Message 1')
    await client.deleteOpenGroupMessage(openGroupName, [messageId])
  }
  */

  if (0 && ogv2Handle) {
    const messageId = await client.sendOpenGroupV2Message(ogv2Handle, 'Hello World SOGSv2 from node-session-client')
    await client.deleteOpenGroupV2Message(ogv2Handle, messageId)
  }

  // Open group invite example
  // only works on desktop
  //client.sendOpenGroupInvite(toPubkey, 'Bob\'s server', openGroupName, 2)
})
