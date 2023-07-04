# node-session-client
Implementation of Session protocol in node

Supports
- Session protocol support (Direct messaging)
- Recovery Phrase (13 words)
- Support for communicating with the Loki 10.x network
- File server v2
- Avatars
- Attachments
- Open groups v3
  - receiving blinded public/open messages
  - sending blinded public/open messages
  - delete blinded public/open messages
  - receiving blinded DMs (inbox)
  - display names

Working on:
- LNS
- bugs / error codes
- closed group support
- relying on less 3rd party NPMs (for security reasons)
- pure web version

## installing nodejs

### CentOS NodeJS installation:

`curl -sL https://rpm.nodesource.com/setup_18.x | sudo bash -`

### Ubuntu/Debian NodeJS installation:

`curl -sL https://deb.nodesource.com/setup_18.x | sudo bash -`

then

`sudo apt-get install -y nodejs`

## clone repo

You can clone the repo many ways. I will include how to do this from the command line:

This makes a local copy of the repo via https

`git clone https://github.com/hesiod-project/node-session-client`

Be sure to be inside of the project repo for the next steps

`cd node-session-client`

## install dependencies

from inside the project root directory

`npm i`

## Example Usage

1. set up library instance, be sure to adjust path in require if not in the project root.

```js
const SessionClient = require('./session-client.js')

// You'll want an instance per SessionID you want to receive messages for
const client = new SessionClient()
```

2. Set up identity and send a message

To generate a new identity and save it to disk as `seed.txt`. please change `YOUR_SESSON_ID_GOES_HERE` to your Session ID

```js
const fs = require('fs')
client.loadIdentity({
  seed: fs.existsSync('seed.txt') && fs.readFileSync('seed.txt').toString(),
  displayName: 'Sample Session Client',
}).then(async () => {
  // output recovery phrase if making an identity
  console.log(client.identityOutput)
  
  const SessionID = "YOUR_SESSON_ID_GOES_HERE"
  client.send(SessionID, 'Hello').then(() => {
     console.debug('Sent "Hello" to', SessionID)
  })
})
```

## Detailed Example

[Example](sample.js)

## Documentation

[Auto-generated Detailed Documentation](https://hesiod-project.github.io/node-session-client/)


# Support our work

Development depends on your support
LT2mP2DrmGD82gFnH16ty8ZtP6f33czpA6XgQdnuTVeT5bNGyy3vnaUezzKq1rEYyq3cvb2GBZ5LjCC6uqDyKnbvFki9aAX

QR Code:
![oxen://LT2mP2DrmGD82gFnH16ty8ZtP6f33czpA6XgQdnuTVeT5bNGyy3vnaUezzKq1rEYyq3cvb2GBZ5LjCC6uqDyKnbvFki9aAX](LT2mP2DrmGD82gFnH16ty8ZtP6f33czpA6XgQdnuTVeT5bNGyy3vnaUezzKq1rEYyq3cvb2GBZ5LjCC6uqDyKnbvFki9aAX.png)
