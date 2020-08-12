const SessionClient = require('./session-client.js')

const client = new SessionClient()

client.open()
client.on('messages', msgs => {
  console.log('newMessages', msgs)
})
const toPubkey = '05d233c6c8daed63a48dfc872a6602512fd5a18fc764a6d75a08b9b25e7562851a'
client.send(toPubkey, 'Hello')
