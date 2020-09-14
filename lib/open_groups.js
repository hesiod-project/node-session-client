const lib = require('./lib.js')
// eslint-disable-next-line camelcase
const loki_crypto = require('./lib.loki_crypto.js')

async function getToken(openGroupURL, privKey, pubkeyHex) {
  const openGroupUrl = `https://${openGroupURL}`
  const chalUrl = `${openGroupUrl}/loki/v1/get_challenge?pubKey=${pubkeyHex}`
  const data = await lib.jsonAsk(chalUrl)
  if (!data.cipherText64 || !data.serverPubKey64) {
    console.error('open_groups::getToken - data', typeof (data), data)
    return
  }
  // decode server public key
  const serverPubKeyBuff = Buffer.from(data.serverPubKey64, 'base64')
  // make sym key
  const symmetricKey = await loki_crypto.makeSymmetricKey(privKey, serverPubKeyBuff)
  // decrypt
  const tokenBuf = await loki_crypto.DHDecrypt64(symmetricKey, data.cipherText64)
  const token = tokenBuf.toString() // fix up type
  // set up submit to activate token
  const subUrl = `${openGroupUrl}/loki/v1/submit_challenge`
  let activateRes
  try {
    activateRes = await lib.textAsk(subUrl, {
      method: 'POST',
      body: JSON.stringify({
        token: token,
        pubKey: pubkeyHex
      }),
      headers: {
        'Content-Type': 'application/json'
      }
    })
  } catch (e) {
    console.error('open_groups::getToken - submit_challenge err', e)
  }
  if (activateRes !== '') {
    console.error('Failed to get token for', openGroupUrl, pubkeyHex)
  }
  return token
}

class SessionOpenGroupChannel {
  constructor(openGroupURL, options = {}) {
    this.channelId = options.channelId || 1
    this.serverUrl = openGroupURL
    this.lastId = 0
    this.timer = null
    this.pollRate = options.pollRate || 1000
    this.keypair = options.keypair || false
    this.token = options.token || ''
    this.pollServer = false
  }

  async subscribe() {
    console.log('Subscribing to Open Group', this.serverUrl)
    try {
      const subscriptionResult = await lib.jsonAsk(`https://${this.serverUrl}/channels/${this.channelId}/subscribe`,
        {
          method: 'post',
          headers: {
            Authorization: `Bearer ${this.token}`,
            'Content-type': 'application/json',
            Accept: 'application/json',
            'Accept-Charset': 'utf-8'
          }
        })
      if (subscriptionResult.meta && subscriptionResult.meta.code && subscriptionResult.meta.code === 200) {
        return subscriptionResult
      } else {
        console.error('open_groups::subscribe - Wrong response received', subscriptionResult)
      }
    } catch (e) {
      console.error('open_groups::subscribe - Subscribe error', e)
    }
    return null
  }

  async getMessages() {
    try {
      const messageListResult = await lib.jsonAsk(`https://${this.serverUrl}/channels/${this.channelId}/messages?since_id=${this.lastId}`,
        {
          method: 'get',
          headers: {
            Authorization: `Bearer ${this.token}`,
            'Content-type': 'application/json',
            Accept: 'application/json',
            'Accept-Charset': 'utf-8'
          }
        })
      if (messageListResult.meta && messageListResult.meta.code && messageListResult.meta.code === 200 && messageListResult.data) {
        if (messageListResult.data.length) {
          this.lastId = messageListResult.data[0].id
        }
        return messageListResult.data
      } else {
        console.error('open_groups::getMessages - Wrong response received', messageListResult)
      }
    } catch (e) {
      console.error('open_groups::getMessages - Getting messages error', e)
    }
    return null
  }

  async send(text, options = {}) {
    try {
      const sigVer = 1
      const mockAdnMessage = { text }
      const timestamp = new Date().getTime()
      const annotations = [
        {
          type: 'network.loki.messenger.publicChat',
          value: {
            timestamp,
            // sig: '6b07d9f8c7bb4c5e28a43b4dd2aa4889405361e709258a0420ba55c8aa6784c1b3059787a7adeec85bbce66832fa61efa7398a55ee9f45aa396a9c05f9edb105',
            //sigver: sigVer
          }

        }
      ]
      if (options && options.avatar) {
        // inject avatar is we have it...
        // probably should do it differently...
        annotations[0].value.avatar = options.avatar
      }

      const sig = await loki_crypto.getSigData(
        sigVer,
        this.keypair.privKey,
        annotations[0].value,
        mockAdnMessage
      )

      annotations[0].value.sig = sig
      annotations[0].value.sigver = sigVer

      const payload = {
        text,
        annotations
      }
      const messageSendResult = await lib.jsonAsk(`https://${this.serverUrl}/channels/${this.channelId}/messages`,
        {
          method: 'POST',
          body: JSON.stringify(payload),
          headers: {
            Authorization: `Bearer ${this.token}`,
            'Content-type': 'application/json',
            Accept: 'application/json',
            'Accept-Charset': 'utf-8'
          }
        })
      //console.log(messageSendResult)
      if (messageSendResult.meta && messageSendResult.meta.code && messageSendResult.meta.code === 200 && messageSendResult.data) {
        return messageSendResult.data
      } else {
        console.error('open_groups::send - Wrong response received', messageSendResult)
      }
    } catch (e) {
      console.error('open_groups::send - Sending messages error', e)
    }
    return null
  }

  async messageDelete(messageIds = []) {
    try {
      const messageDeleteResult = await lib.jsonAsk(`https://${this.serverUrl}/loki/v1/moderation/messages?ids=${encodeURIComponent(messageIds)}`,
        {
          method: 'DELETE',
          headers: {
            Authorization: `Bearer ${this.token}`,
            'Content-type': 'application/json',
            Accept: 'application/json',
            'Accept-Charset': 'utf-8'
          }
        })
      if (messageDeleteResult.meta && messageDeleteResult.meta.code && messageDeleteResult.meta.code === 200 && messageDeleteResult.data) {
        return messageDeleteResult.data
      } else {
        console.error('open_groups::delete - Wrong response received', messageDeleteResult)
      }
    } catch (e) {
      console.error('open_groups::delete - Getting messages error', e)
    }
    return null
  }
}

module.exports = {
  getToken,
  SessionOpenGroupChannel
}
