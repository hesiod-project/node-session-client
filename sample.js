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
  const openGroupName = 'feedback.getsession.org'

  const ogOpened = await client.joinOpenGroup(openGroupName)

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
  const SessionID = '05ce7f197b3e4fa80331397ebb68fb5d66e47f92594ab76bb67233105b78ced238' // ipadtop

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
  }).then(() => {
    console.debug('Sent "Hello" to', SessionID)
  })

  if (ogOpened) {
    //await client.deleteOpenGroupMessage(openGroupName, [28, 27, 26])
  }

  //await client.sendOpenGroupMessage(openGroupName, 'Sample Open Group Message 1')

  // Open group invite example
  // only works on desktop
  //client.sendOpenGroupInvite(toPubkey, 'Bob\'s server', openGroupName, 2)
})
