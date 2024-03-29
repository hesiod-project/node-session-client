const lib = require('./lib.js')
// eslint-disable-next-line camelcase
const loki_crypto = require('./lib.loki_crypto.js')
const protobuf = require('./protobuf.js')

async function getToken(baseUrl, room, serverPubKeyHex, privKey, pubkeyHex) {
  const result = await lib.lsrpc(baseUrl, 'public_key=' + pubkeyHex, serverPubKeyHex,
    'auth_token_challenge', 'GET', '', { Room: room })
  //console.log('result', result)
  if (!result || !result.challenge || !result.challenge.ciphertext || !result.challenge.ephemeral_public_key) {
    console.error('open_group_v2::getToken - result', typeof (result), result)
    return
  }
  // decode everything into buffer format
  const ephermalPubBuf = Buffer.from(result.challenge.ephemeral_public_key, 'base64')
  const cipherTextBuf = Buffer.from(result.challenge.ciphertext, 'base64')

  const symmetricKey = loki_crypto.makeOnionSymKey(privKey, ephermalPubBuf)
  const tokenBuf = loki_crypto.decryptGCM(symmetricKey, cipherTextBuf)

  const tokenHex = tokenBuf.toString('hex') // fix up type

  const pkJSON = JSON.stringify({ public_key: pubkeyHex })
  try {
    const activateRes = await lib.lsrpc(baseUrl, '', serverPubKeyHex,
      'claim_auth_token', 'POST', pkJSON, { Room: room, Authorization: tokenHex })
    //
    if (activateRes.status_code !== 200) {
      console.error('open_group_v2::getToken - claim_auth_token failure', activateRes)
      return
    }
    //console.log('activated', tokenHex)
    return tokenHex
  } catch (e) {
    console.error('open_group_v2::getToken - exception', e)
  }
}

// for multiple keypairs, servers and rooms
class SessionOpenGroupV2Manager {
  constructor(options = {}) {
    this.servers = {}
  }

  joinServer(baseURL, serverPubkeyHex, options) {
    if (this.servers[baseURL]) {
      console.log('SessionOpenGroupV2Manager::joinServer - already joined', baseURL)
      return
    }
    this.servers[baseURL] = new SessionOpenGroupV2Server(baseURL, serverPubkeyHex, {...this.options, options })
  }

  leaveServer(baseURL) {
    // this no server function for leaving?
    //this.rooms[room].stop()
    // leave all the rooms? not needed atm
    delete this.servers[baseURL]
  }

  joinServerRoom(baseURL, serverPubkeyHex, keypair, room, options) {
    if (this.servers[baseURL] === undefined) {
      this.joinServer(baseURL, serverPubkeyHex, options)
    }
    return this.servers[baseURL].joinRoom(keypair, room, options)
  }

  async getMessages() {
    const messages = await Promise.all(Object.values(this.servers).map(server => {
      return server.getMessages()
    }))
    return [].concat(...messages)
  }
}

class SessionOpenGroupV2Server {
  constructor(baseURL, serverPubkeyHex, manager, options = {}) {
    this.serverURL = baseURL
    this.serverPubkeyHex = serverPubkeyHex

    this.pollServer = false
    this.rooms = {}
  }

  _getKey(keypair, room) {
    return keypair.publicKeyHex + '_' + room
  }

  async joinRoom(keypair, room, options = {}) {
    const key = this._getKey(keypair, room)
    if (this.rooms[key]) {
      console.log('SessionOpenGroupV2Server::joinRoom', keypair.publicKeyHex, 'already joined', room)
      return
    }
    this.rooms[key] = new SessionOpenGroupV2Room(this, keypair, room, options)
    await this.rooms[key].subscribe()
    return this.rooms[key].token ? this.rooms[key] : false
  }

  async leaveRoom(keypair, room) {
    const key = this._getKey(keypair, room)
    // this no server function for leaving?
    await this.rooms[room].unsubscribe()
    delete this.rooms[key]
  }

  async getMessages() {
    try {
      const requests = []
      const tokenLookup = {}
      for (const id in this.rooms) {
        const room = this.rooms[id]
        await room.ensureToken()
        if (!room.token) {
          console.warn('SessionOpenGroupV2Server::getMessages - ', room.room, 'no token (yet?) to poll with')
          continue
        }
        tokenLookup[room.token] = room
        requests.push({
          room_id: room.room,
          auth_token: room.token,
          from_message_server_id: room.lastId,
          from_deletion_server_id: 0,
        })
      }
      // , 'using', this.token
      //console.log('getting from lastId', room.lastId)
      //console.log('requests', requests)
      const result = await lib.lsrpc(this.serverURL, '', this.serverPubkeyHex,
        'compact_poll', 'POST', JSON.stringify({ requests }), {})
      //console.log('result', result)
      if (result.status_code !== 200) {
        console.error('SessionOpenGroupV2Server::getMessages - non-200 response', result)
        return null
      }
      /*
      if (result.status_code === 401) {
        this.token = false
        console.log('refreshing token')
        this.token = getToken(this.serverUrl, this.room, this.serverPubkeyHex, this.keypair.privKey, this.keypair.pubKey.toString('hex'))
        return null
      }
      */
      if (!result || !result.results || !result.results.length) {
        console.warn('SessionOpenGroupV2Server::getMessages - ', this.room, 'no result', result)
        return null
      }

      const msgs = []
      for (const id in requests) {
        const request = requests[id]
        const room = tokenLookup[request.auth_token]
        let last = room.lastId
        // if this is always sorted asc, can just grab the last message id
        for (const i in result.results[id].messages) {
          // server_id, public_key, timestamp, data, signature
          const serverMsg = result.results[id].messages[i]
          const humanId = serverMsg.server_id + ' from ' + serverMsg.public_key + ' in ' + room.room + ' on ' + this.serverURL
          // get content
          const contentBuf = Buffer.from(serverMsg.data, 'base64')
          const content = protobuf.decodeContentMessage(contentBuf, humanId)
          // check sig
          let verified = false
          try {
            verified = loki_crypto.verifySigDataV2(
              Buffer.from(serverMsg.public_key, 'hex'),
              contentBuf,
              Buffer.from(serverMsg.signature, 'base64')
            )
          } catch (e) {
            console.warn('SessionOpenGroupV2Server::getMessages - Could not verify signature on', humanId)
          }

          // make sure message is decoded
          // discard messages on first poll
          // and not a message we send
          const notUs = room.keypair.publicKeyHex !== serverMsg.public_key
          if (content && room.lastId && notUs) {
            //console.log('data', data)
            const message = {
              // identity
              serverURL: this.serverURL,
              room: room.room,
              id: serverMsg.server_id,
              source: serverMsg.public_key,
              roomHandle: room,
              // message
              destination: room.keypair.publicKeyHex,
              // unique to the intended message
              timestamp: serverMsg.timestamp,
              // specific to the transport
              existedBy: serverMsg.timestamp,
              // access to quotes/attachments/etc
              content,
              verified,
            }
            // if dataMessage, unpack it a bit
            if (content.dataMessage) {
              // unique to the intended message
              if (content.dataMessage.timestamp) message.timestamp = content.dataMessage.timestamp
              message.body = content.dataMessage.body
              if (content.dataMessage.profile) {
                message.profile = {
                  displayName: content.dataMessage.profile.displayName,
                  avatar: {
                    url: content.dataMessage.profile.profilePicture,
                    key: content.dataMessage.profile.profileKey,
                  }
                }
              }
              // FIXME: quote, attachments?
            }
            msgs.push(message)
          }
          last = Math.max(last, serverMsg.server_id)
        }
        room.lastId = last
      }
      return msgs
    } catch (e) {
      console.error('SessionOpenGroupV2Server::getMessages - Getting messages error', e)
    }
    return null
  }
}

class SessionOpenGroupV2Room {
  constructor(server, keypair, room, options = {}) {
    this.server = server
    this.keypair = keypair
    this.room   = room

    this.lastId = options.lastId || 0
    this.token = options.token || ''
  }

  async ensureToken() {
    if (!this.token) {
      this.token = await getToken(this.server.serverURL, this.room, this.server.serverPubkeyHex, this.keypair.privKey, this.keypair.publicKeyHex)
    }
  }

  async subscribe() {
    // this adds us to the count
    await this.ensureToken()
    if (!this.token) {
      console.log('SessionOpenGroupV2Room::subscribe - Can not subscribe no token')
      return
    }
    const lastMessageRes = await lib.lsrpc(this.server.serverURL, 'limit=1', this.server.serverPubkeyHex,
      'messages', 'GET', '', { Room: this.room, Authorization: this.token })
    if (!lastMessageRes || !lastMessageRes.messages || !lastMessageRes.messages.length) {
      console.error('SessionOpenGroupV2Server::subscribe - no room messages', lastMessageRes)
      return
    }
    if (lastMessageRes.status_code !== 200) {
      console.error('SessionOpenGroupV2Server::subscribe - non-200 response', lastMessageRes)
      return
    }
    this.lastId = lastMessageRes.messages[0].server_id
    //console.log('setting', this.room + '@' + this.server.serverURL, 'last message to', this.lastId)
  }

  async unsubscribe() {
    // DELETE token
  }

  async send(text, options = {}) {
    try {
      // we need to pad text
      const ts = Date.now()

      // padPlainTextBuffer returns uint8 array
      const plaintextBuf = Buffer.from(protobuf.encodeContentMessage(text, ts, options))
      const message = {
        // sender
        public_key: this.keypair.publicKeyHex,
        timestamp: ts,
        data: plaintextBuf.toString('base64'), // base64 encode plaintextBuf
        signature: loki_crypto.getSigDataV2(this.keypair.privKey, plaintextBuf), //base64
      }
      const result = await lib.lsrpc(this.server.serverURL, '', this.server.serverPubkeyHex,
        'messages', 'POST', JSON.stringify(message), { Room: this.room, Authorization: this.token })
      // result.message: server_id, public_key, timestamp, data, signature
      if (!result || !result.message || !result.message.server_id) {
        console.error('SessionOpenGroupV2Room::send - bad result?', result)
        return false
      }
      return result.message.server_id
    } catch (e) {
      console.error('SessionOpenGroupV2Room::send - Sending messages error', e)
    }
    return null
  }

  async messageDelete(messageId) {
    try {
      const messageDeleteResult = await lib.lsrpc(this.server.serverURL, '', this.server.serverPubkeyHex,
        'messages/' + messageId, 'DELETE', '', { Authorization: this.token, Room: this.room})
      console.log('messageDeleteResult', messageDeleteResult)
      if (messageDeleteResult.status_code !== 200) {
        console.error('SessionOpenGroupV2Room::delete - Wrong response received', messageDeleteResult)
        return false
      }
      return true
    } catch (e) {
      console.error('SessionOpenGroupV2Room::delete - Getting messages error', e)
    }
    return null
  }
}

module.exports = {
  SessionOpenGroupV2Manager: new SessionOpenGroupV2Manager(),
}
