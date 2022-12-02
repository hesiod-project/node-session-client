const lib = require('./lib.js')
// eslint-disable-next-line camelcase
const loki_crypto = require('./lib.loki_crypto.js')
const protobuf = require('./protobuf.js')
//const _sodium = require('libsodium-wrappers')
const _sodium = require('libsodium-wrappers-sumo') // maybe put in session-client?
//const crypto = require('crypto')
const binary = require('./lib.binary.js')

// OnionSending in https://github.com/oxen-io/session-desktop/blob/0794edeb69aac582187da35771dc29ae3e68279c/ts/session/onions/onionSend.ts#L36
// NOTE some endpoints require decoded strings
const endpointExceptions = ['/reaction'];
const endpointRequiresDecoding = url => {
  // tslint:disable-next-line: prefer-for-of
  for (let i = 0; i < endpointExceptions.length; i++) {
    if (url.includes(endpointExceptions[i])) {
      return decodeURIComponent(url);
    }
  }
  return url;
};

async function getOurOGHeaders(serverPubKeyHex, endpoint, method, blinded, body, keypair) {
  await _sodium.ready
  const sodium = _sodium
  const signingKeys = keypair.ed25519KeyPair

  //const timestamp = Math.floor(getNowWithNetworkOffset() / 1000);
  const timestamp = Math.floor(Date.now() / 1000)
  //const nonce = new Uint8Array(16)
  const nonce = await sodium.randombytes_buf(16)
  const srvU8A = binary.hexStringToUint8Array(serverPubKeyHex)

  let pubkey, ka, kA
  // https://github.com/oxen-io/session-desktop/blob/0794edeb69aac582187da35771dc29ae3e68279c/ts/session/types/PubKey.ts#L5
  if (blinded) {
    const blindingValues = await loki_crypto.getBlindingValues(srvU8A, signingKeys)
    ka = blindingValues.secretKey
    kA = blindingValues.publicKey
    //console.log('kA', kA) // uint8(32)
    //pubkey = `15${toHex(kA)}`;
    const hexStr = Buffer.from(kA).toString('hex')
    //console.log('hexStr', hexStr)
    pubkey = '15' + hexStr
  } else {
    //pubkey = `00${toHex(signingKeys.pubKeyBytes)}`;
    //console.log('signingKeys', signingKeys)
    const hexStr = Buffer.from(signingKeys.publicKey).toString('hex')
    pubkey = '00' + hexStr
  }
  // requires front /
  //console.log('endpoint', endpoint)
  const rawPath = endpointRequiresDecoding(endpoint) // this gets a string of the path with potentially emojis in it
  const encodedPath = new Uint8Array(binary.encode(rawPath, 'utf8')) // this gets the binary content of that utf8 string

  //const srvPubKeyBuf = Buffer.from(serverPubKeyHex, 16)
  //console.log('srvPubKeyBuf', srvPubKeyBuf)

  // SERVER_PUBKEY 32 || NONCE 16 || TIMESTAMP 10ish || METHOD 3-6 || PATH +|| HASHED_BODY *
  /*
  //const srvU8A = new ArrayBuffer(srvPubKeyBuf.length)
  const srvU8A = new Uint8Array(srvPubKeyBuf.length)
  for (let i = 0; i < srvPubKeyBuf.length; ++i) {
    srvU8A[i] = srvPubKeyBuf[i]
  }
  */
  //console.debug('serverPubKeyHex', serverPubKeyHex, 'timestamp', timestamp, 'method', method, 'path', endpoint, 'body', body)
  const tsU8a = binary.stringToUint8Array(timestamp.toString())
  const methU8a = binary.stringToUint8Array(method)
  if (0) {
    console.log('srvU8A', srvU8A)
    console.log('nonce', nonce)
    console.log('tsBuf', tsU8a)
    console.log('methU8a', methU8a)
    console.log('encodedPath', encodedPath)
  }

  let toSign = binary.concatUInt8Array(
    srvU8A,
    nonce,
    tsU8a,
    methU8a,
    encodedPath
  )

  if (body) {
    // body hash to signature
    toSign = binary.concatUInt8Array(toSign, sodium.crypto_generichash(64, body))
  }

  const signature = await loki_crypto.getSogsSignature(blinded, ka, kA, signingKeys, toSign)

  return {
    'X-SOGS-Pubkey': pubkey, // user pubkey
    'X-SOGS-Timestamp': '' + timestamp,
    'X-SOGS-Nonce': binary.fromUInt8ArrayToBase64(nonce),
    'X-SOGS-Signature': binary.fromUInt8ArrayToBase64(signature),
  };
}

// if endpoint don't start with /, we're considered legacy
async function sogs_rpcv4(method, endpoint, querystring, body, baseUrl, serverPubKeyHex, keypair, blinded) {
  let headers = await getOurOGHeaders(serverPubKeyHex, endpoint, method, blinded, body, keypair)
  // might need json headers...
  // FIXME: we can detect if body is an object...
  //console.log('method', method, 'ep', endpoint, 'body', body)
  if (method === 'POST' && (endpoint === '/batch' || endpoint.match(/message$/))) {
    //console.log('adding json content-type')
    headers = {...headers, 'Content-Type': 'application/json' }
    //console.log('headers', headers)
  }
  // https://github.com/oxen-io/session-desktop/blob/0794edeb69aac582187da35771dc29ae3e68279c/ts/session/onions/onionSend.ts#L272
  const result = await lib.lsrpcv4(baseUrl, querystring, serverPubKeyHex,
    endpoint, method, body, headers)
  //console.log('result', result)
  return result
}

async function sogs_rpcv3(method, endpoint, querystring, body, baseUrl, serverPubKeyHex, keypair, blinded) {
  const headers = await getOurOGHeaders(serverPubKeyHex, endpoint, method, blinded, body, keypair)
  //console.log('headers', headers)
  // https://github.com/oxen-io/session-desktop/blob/0794edeb69aac582187da35771dc29ae3e68279c/ts/session/onions/onionSend.ts#L272
  const result = await lib.lsrpc(baseUrl, querystring, serverPubKeyHex,
    endpoint, method, body, headers)
  //console.log('result', result)
  return result
}

// for multiple keypairs, servers and rooms
class SessionOpenGroupV3Manager {
  constructor(options = {}) {
    this.servers = {}
  }

  updateProfile(keypair, displayName, profileInfo) {
    for(const url in this.servers) {
      this.servers[url].updateProfile(keypair, displayName, profileInfo)
    }
  }

  joinServer(baseURL, serverPubkeyHex, options) {
    if (this.servers[baseURL]) {
      console.log('SessionOpenGroupV3Manager::joinServer - already joined', baseURL)
      return
    }
    this.servers[baseURL] = new SessionOpenGroupV3Server(baseURL, serverPubkeyHex, {...this.options, options })
    this.servers[baseURL].subscribe()
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

class SessionOpenGroupV3Server {
  constructor(baseURL, serverPubkeyHex, manager, options = {}) {
    this.serverURL = baseURL
    this.serverPubkeyHex = serverPubkeyHex

    this.pollServer = false
    this.rooms = {}

    this.caps = []
    this.blinded = null
    this.useV3 = options.useV3 || false
    this.capsReady = new Promise(resolve => {
      this.capsResolve = resolve
    })
    this.lastInboxId = undefined
    this.lastOutboxId = undefined
  }

  _getKey(keypair, room) {
    return keypair.publicKeyHex + '_' + room
  }

  updateProfile(keypair, displayName, profileInfo) {
    // search rooms for rooms with this keypair
    for(const kp_name in this.rooms) {
      const parts = kp_name.split('_', 2)
      const pkHex = parts[0]
      if (pkHex === keypair.publicKeyHex) {
        this.rooms[kp_name].updateProfile(displayName, profileInfo)
      }
    }
  }

  // header support?
  // keypair, endpoint, body, querystring, method
  async rpc(method, endpoint, querystring, body, keypair) {
    await this.capsReady
    this.anyKeypair = keypair
    if (this.useV3) {
      return sogs_rpcv3(method, endpoint, querystring, body,
          this.serverURL, this.serverPubkeyHex, keypair, this.blinded)
    }
    return sogs_rpcv4(method, endpoint, querystring, body,
        this.serverURL, this.serverPubkeyHex, keypair, this.blinded)
  }

  async subscribe() {
    const result = await lib.lsrpc(this.serverURL, 'required=sogs', this.serverPubkeyHex,
      '/capabilities', 'GET', '', {})
    if (!result.capabilities) {
      console.log('SessionOpenGroupV3Server::subscribe - unknown result', result)
      this.caps = []
      return
    }
    //console.log('SessionOpenGroupV3Server::subscribe - capabilities', result.capabilities)
    this.caps = result.capabilities

    //this.caps = await getCapabilities(this.serverURL, this.serverPubkeyHex, keypair)
    this.blinded = this.caps.includes('blind')

    console.debug('SessionOpenGroupV3Server::subscribe - has blinding', this.blinded)
    this.capsResolve()
  }

  async joinRoom(keypair, room, options = {}) {
    const key = this._getKey(keypair, room)
    if (this.rooms[key]) {
      console.log('SessionOpenGroupV3Server::joinRoom', keypair.publicKeyHex, 'already joined', room)
      return
    }
    this.rooms[key] = new SessionOpenGroupV3Room(this, keypair, room, options)
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
      const requests = [{
        method: 'GET',
        path: '/capabilities',
        //type: 'capabilities',
      }]
      //const tokenLookup = {}
      const reqTrack = [false]
      for (const id in this.rooms) {
        const room = this.rooms[id]
        await room.ensureToken()
        if (!room.token) {
          console.warn('SessionOpenGroupV3Server::getMessages - ', room.room, 'no token (yet?) to poll with')
          continue
        }
        //tokenLookup[room.token] = room
        // roomIdsToPoll
        // subrequesst options?
        // - capabilities
        // - messages
        // - inbox
        // - outbox
        // - pollInfo
        // - deleteMessage
        // - addRemoveModerators
        // - banUnbanUser
        // - deleteAllPosts
        // - updateRoom
        // - deleteReaction
        // batch or sequence
        reqTrack.push(id)
        requests.push({
          /*
          type: 'pollInfo',
          pollInfo: {
            roomId: room.room,
            infoUpdated: 0,
          }
          */
          method: 'GET',
          path: '/room/' + room.room + '/pollInfo/0',
        })
        reqTrack.push(id)
        requests.push({
          /*
          type: 'messages',
          messages: {
            roomId: room.room,
            sinceSeqNo: room.lastId,
          }
          */
          method: 'GET',
          path: '/room/' + room.room + '/messages/' + (room.lastId ? 'since/' + room.lastId : 'recent/') + '?t=r&reactors=5'
        })
        /*
        requests.push({
          room_id: room.room,
          auth_token: room.token,
          from_message_server_id: room.lastId,
          from_deletion_server_id: 0,
        })
        */
      }
      if (this.blinded) {
        // max id from across all rooms
        reqTrack.push(false)
        requests.push({
          /*
          type: 'inbox',
          inboxSince: {
            id: this.lastInboxId,
          }
          */
          method: 'GET',
          path: '/inbox' + (this.lastInboxId !== undefined ? '/since/' + this.lastInboxId : '')
        })
        reqTrack.push(false)
        requests.push({
          /*
          type: 'outbox',
          outboxSince: {
            id: this.lastOutboxId,
          }
          */
          method: 'GET',
          path: '/outbox' + (this.lastOutboxId !== undefined ? '/since/' + this.lastOutboxId : '')
        })
      }

      if (!requests.length) {
        // probably should log, so we don't look like we're working
        console.warn('SessionOpenGroupV3Server::getMessages - ', this.serverURL, 'no requests to make')
        // probably shouldn't stop incase a token does come in
        return
      }

      //console.log('requests', requests)
      const responses = await this.rpc('POST', '/batch', '', JSON.stringify(requests), this.anyKeypair)
      //console.log('responses', responses)
      if (!responses?.length) {
        console.warn('SessionOpenGroupV3Server::getMessages - ', this.serverURL, 'no responses', responses)
        return null
      }
      if (responses?.length !== requests.length) {
        console.warn('SessionOpenGroupV3Server::getMessages - ', this.serverURL, 'request/response mismatch', responses?.length, '!=', requests.length)
      }

      const msgs = []
      let boxCnt = 0
      for (const id in requests) {
        const request = requests[id]
        const response = responses[id]
        const roomId = reqTrack[id]
        if (!roomId) {
          // maybe we just see if response.body.capabilities is set?
          //console.log('id', id, 'test', !id, 'type', typeof(id))
          if (id === '0') {
            if (this.caps.join() !== response.body.capabilities.join()) {
              this.caps = response.body.capabilities
              console.log('new capabilities detected', this.caps)
            }
          } else {
            if (1) {
              //console.log(id, 'box' + boxCnt, response.body)
              // inbox: expires_at, id, message, posted_at, recipient, sender
              if (boxCnt === 0) {
                if (response.body.length) {
                  const id = Math.max(...response.body.map(i => i.id))
                  console.log('inbox now at', id)
                  this.lastInboxId = id
                }
              } else
              if (boxCnt === 1) {
                if (response.body.length) {
                  const id = Math.max(...response.body.map(i => i.id))
                  console.log('outbox now at', id)
                  this.lastOutboxId = id
                }
              }
              // i got to decode these messages
              if (Array.isArray(response.body)) {
                //
                const isOutbox = boxCnt === 1
                for(const body of response.body) {
                  //console.log('body', body)
                  // body: expires_at, id, message, posted_t, recipient, sender
                  const msgBuf = Buffer.from(body.message, 'base64')
                  const otherBlindedPubkey = isOutbox ? body.recipient : body.sender
                  const data = await loki_crypto.decryptWithSessionBlindingProtocol(msgBuf, isOutbox, otherBlindedPubkey,
                    this.serverPubkeyHex, this.anyKeypair.ed25519KeyPair
                  )
                  // plainTextBuf
                  //console.log('data', data)
                  const humanId = body.id + ' from ' + body.sender + 'to' + body.recipient + ' in inbox at ' + body.posted_at + ' on ' + this.serverURL
                  const content = protobuf.decodeContentMessage(loki_crypto.removeMessagePadding(data.plainTextBuf), humanId)
                  // content: attachments, contact, preview, body, expireTimer
                  // profile
                  //console.log('content', content)

                  // our internal format
                  const message = {
                    //openGroup:
                    serverURL: this.serverURL,
                    id: body.id,
                    source: body.sender,
                    destination: body.recipient,
                    // unique to the intended message
                    timestamp: body.posted_at,
                    // specific to the transport
                    existedBy: body.posted_at,
                    // access to quotes/attachments/etc
                    body: content.dataMessage.body,
                    content,
                    // might as well be verified but no sig
                    //verified,
                  }
                  //console.log('inbox', message)

                  // if dataMessage, unpack it a bit
                  if (content.dataMessage) {
                    // unique to the intended message
                    //console.log('SessionOpenGroupV3Server::getMessages - content.dataMessage', content.dataMessage)
                    // body, timestamp, profile
                    // seems be like a BigInt thats 0
                    //if (content.dataMessage.timestamp) message.timestamp = content.dataMessage.timestamp
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
                    // attachments, contact, preview
                  }

                  msgs.push(message)
                }
              } else {
                if (response.body?.message) {
                  const msgBuf = Buffer.from(response.body.message, 'base64')
                }
              }
              boxCnt++
            }
          }
          continue
        }
        const room = this.rooms[roomId]
        //console.log('roomId', roomId, 'room', room, Object.keys(this.rooms))
        let last = room.lastId

        if (response.code >= 400) {
          console.warn('SessionOpenGroupV3Server::getMessages - subresult got a bad status code', response.code, request, response)
          continue
        }
        if (response.body && response.body.active_users) {
          // active_users, read, token, upload, write, details
          //console.log('details', response.body.details)
          // active_users, active_users_cutoff, admins, created, image_id
          // info_updates, message_sequence, moderators, name, read, token, upload, write
          continue
        }
        //console.log('uhm messages?', response)
        // if this is always sorted asc, can just grab the last message id
        for (const i in response.body) {
          // server_id, public_key, timestamp, data, signature
          // unclear what seqno is about
          /*
            {
              id: 380490,
              session_id: '15ec65479ab9008322ac623ea105a698eb321879e9b078ab4313d731aa77d92768',
              posted: 1668248367.725775,
              // this is used for polling
              seqno: 247632,
              data: 'CigKE29ubHkgaWYgeW91IGJlbGlldmWqBhAKDlZlY3RvcjEyUHJvTWF4gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              signature: 'TkSbMVCKJoIFf+fhWB2RAuap7W2/zTp+kC5BZKqw67A3okmW7Odwh7EQ+K8E8OpLNfnkCCX9+IrFuKxFeTsSBg==',
              reactions: {}
            }
            serverMsg {
              id: 385620,
              session_id: '157a067f6fa8c298807cc438043c87066863f7ac772c998367d0b7140da2fc5e64',
              posted: 1668917881.091192,
              seqno: 70908,

              data: null,
              deleted: true,
              edited: 1668917973.470715,
              reactions: {}
            }
          */
          const serverMsg = response.body[i]
          //console.log('serverMsg', serverMsg)
          const humanId = serverMsg.id + ' from ' + serverMsg.session_id + ' in ' + room.room + ' on ' + this.serverURL
          if (serverMsg.deleted) {
            msgs.push({
              // identity
              serverURL: this.serverURL,
              room: room.room,
              id: serverMsg.id,
              source: serverMsg.session_id,
              roomHandle: room,
              destination: room.keypair.publicKeyHex,
              // unique to the intended message
              timestamp: serverMsg.posted,
              // specific to the transport
              existedBy: serverMsg.posted,
              // new
              edited: serverMsg.edited,
              deleted: true,
              // is this how we want this?
              reactions: serverMsg.reactions,
            })
          }

          // has content
          if (serverMsg.data) {
            // get content
            const contentBuf = Buffer.from(serverMsg.data, 'base64')
            const content = protobuf.decodeContentMessage(contentBuf, humanId)
            // check sig
            let verified = false
            try {
              if (this.blinded) {
                const senderBuf = Buffer.from(serverMsg.session_id, 'hex')
                //console.log('doing blinded verification', senderBuf)
                verified = await loki_crypto.verifySigDataV3(
                  this.serverPubkeyHex,
                  senderBuf,
                  contentBuf,
                  serverMsg.signature,
                )
              } else {
                verified = loki_crypto.verifySigDataV2(
                  Buffer.from(serverMsg.session_id, 'hex'),
                  contentBuf,
                  Buffer.from(serverMsg.signature, 'base64')
                )
              }
              if (!verified) {
                console.warn('SessionOpenGroupV3Server::getMessages - Could not verify signature on', humandId)
              }
            } catch (e) {
              console.warn('SessionOpenGroupV3Server::getMessages - Could not verify signature on', humanId, e)
            }

            // make sure message is decoded
            // discard messages on first poll
            // and not a message we send
            // FIXME: blinding support
            const notUs = room.keypair.publicKeyHex !== serverMsg.session_id
            if (content && room.lastId && notUs) {
              //console.log('data', data)
              const message = {
                // identity
                serverURL: this.serverURL,
                room: room.room,
                id: serverMsg.id,
                // this isn't working
                // will be blinded afaik...
                source: serverMsg.session_id,
                roomHandle: room,
                body: content.dataMessage.body,
                destination: room.keypair.publicKeyHex,
                // unique to the intended message
                timestamp: serverMsg.posted,
                // specific to the transport
                existedBy: serverMsg.posted,
                // access to quotes/attachments/etc
                content,
                verified,
                // is this how we want this?
                reactions: serverMsg.reactions,
              }
              // if dataMessage, unpack it a bit
              if (content.dataMessage) {
                // unique to the intended message
                //console.log('SessionOpenGroupV3Server::getMessages - content.dataMessage', content.dataMessage)
                // body, timestamp, profile
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
                // attachments, contact, preview
              }
              msgs.push(message)
            }
          }
          last = Math.max(last, serverMsg.seqno)
        }
        //console.log('setting', room.room, 'to' , last)
        room.lastId = last
      }
      if (0 && msgs.length) {
        console.debug('SessionOpenGroupV3Server::getMessages - dispatching', msgs.length, 'messages', msgs)
      }
      return msgs
    } catch (e) {
      console.error('SessionOpenGroupV3Server::getMessages - Getting messages error', e)
    }
    return null
  }
}

class SessionOpenGroupV3Room {
  constructor(server, keypair, room, options = {}) {
    this.server = server
    this.keypair = keypair
    this.room   = room

    this.lastId = options.lastId || 0
    this.token = options.token || ''
    // active_users, active_users_cutoff, admins, created, image_id, info_updates,
    // message_sequence, moderators, name, read, token, upload, write
    this.roomData = {}
    this.displayName = undefined
    this.profileInfo = undefined
  }

  async ensureToken() {
    if (!this.token) {
      //this.token = await getToken(this.server.serverURL, this.room, this.server.serverPubkeyHex, this.keypair.privKey, this.keypair.publicKeyHex)
      this.roomData = await this.server.rpc('GET', '/room/' + this.room, '', '', this.keypair)
      this.token = this.roomData.token
      this.lastId = this.roomData.message_sequence
      console.log('SessionOpenGroupV3Room::ensureToken - setting', this.room + '@' + this.server.serverURL, 'last message to', this.lastId)
    }
  }

  async subscribe() {
    // this adds us to the count
    await this.ensureToken()
    if (!this.token) {
      console.log('SessionOpenGroupV3Room::subscribe - Can not subscribe no token')
      return
    }
    if (this.server.blinded) {
      // srvkey + ourkey => blindedkey
      const srvU8A = binary.hexStringToUint8Array(this.server.serverPubkeyHex)
      const blindingValues = await loki_crypto.getBlindingValues(srvU8A, this.keypair.ed25519KeyPair)
      //console.log('blindingValues', blindingValues)
      const ka = blindingValues.secretKey
      const kA = blindingValues.publicKey
      //console.log('kA', kA) // uint8(32)
      //pubkey = `15${toHex(kA)}`;
      const hexStr = Buffer.from(kA).toString('hex')
      //console.log('hexStr', hexStr)
      const pubkey = '15' + hexStr
      console.log('SessionOpenGroupV3Room::subscribe - joined room', this.room, 'blinded as', pubkey)
    }
  }

  async unsubscribe() {
    // DELETE token
  }

  updateProfile(displayName, profileInfo) {
    if (displayName !== undefined) this.displayName = displayName
    if (profileInfo !== undefined) this.profileInfo = profileInfo
  }

  async send(text, options = {}) {
    await this.ensureToken()
    try {
      // we need to pad text
      const ts = Date.now()

      // padPlainTextBuffer returns uint8 array
      // probably should be creating a OpenGroupMessageV2 message

      // we need to inject profile stuff into options...
      if (options.displayName === undefined && this.displayName !== undefined) {
        options.displayName = this.displayName
      }
      if (options.avatar === undefined && this.profileInfo !== undefined) {
        options.avatar = this.profileInfo?.avatar_image
      }

      //console.log('send options', options, 'dn', this.displayName, 'pi', this.profileInfo)
      const plaintextBuf = Buffer.from(protobuf.encodeContentMessage(text, ts, options))

      // maybe we should sign it with our pubkey, not the server's pubkey
      const signatureB64 = await loki_crypto.getSigDataBlinded(this.server.serverPubkeyHex,
            this.keypair.ed25519KeyPair, plaintextBuf)
      //console.log('got sig')
      //const signatureBuf = Buffer.from(signatureB64, 'base64')
      //console.log('signature', signature, signature.byteLength)

      // srvkey + ourkey => blindedkey
      const srvU8A = binary.hexStringToUint8Array(this.server.serverPubkeyHex)
      const blindingValues = await loki_crypto.getBlindingValues(srvU8A, this.keypair.ed25519KeyPair)
      //console.log('blindingValues', blindingValues)
      const ka = blindingValues.secretKey
      const kA = blindingValues.publicKey
      //console.log('kA', kA) // uint8(32)
      //pubkey = `15${toHex(kA)}`;
      const hexStr = Buffer.from(kA).toString('hex')
      //console.log('hexStr', hexStr)
      const pubkey = '15' + hexStr
      const blindedPkBuf = Buffer.from(pubkey, 'hex')
      //console.log('our blinded pubkey', pubkey)

          /*
            {
              id: 380490,
              session_id: '15ec65479ab9008322ac623ea105a698eb321879e9b078ab4313d731aa77d92768',
              posted: 1668248367.725775,
              seqno: 247632,
              data: 'CigKE29ubHkgaWYgeW91IGJlbGlldmWqBhAKDlZlY3RvcjEyUHJvTWF4gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              signature: 'TkSbMVCKJoIFf+fhWB2RAuap7W2/zTp+kC5BZKqw67A3okmW7Odwh7EQ+K8E8OpLNfnkCCX9+IrFuKxFeTsSBg==',
              reactions: {}
            }
          */

      // blindedJson
      /*
      const message = {
        message: plaintextBuf.toString('base64'),
        timestamp: ts, // sentTimestamp
        // serverId
        sender: pubkey,
        // b64sig
        signature: signatureB64 // already in b64
        // files
        //reactions: {}
      }
      */

      const message = {
        session_id: pubkey,
        posted: ts, // sentTimestamp
        // seqno
        data: plaintextBuf.toString('base64'),
        signature: signatureB64, // already in b64
        reactions: {}
      }

      /*
      const message = {
        // sender
        //session_id: this.keypair.publicKeyHex,
        data: plaintextBuf.toString('base64'), // base64 encode plaintextBuf
        signature: this.server.blinded ?
          await loki_crypto.getSigDataBlinded(this.server.serverPubkeyHex,
            this.keypair.ed25519KeyPair, plaintextBuf) :
          loki_crypto.getSigDataV2(this.keypair.privKey, plaintextBuf), //base64
        // whisper_to
        // whisper_mods
        // files
      }
      */

      //const messageBuf = Buffer.from(protobuf.encodeContentMessage(message, ts, options))
      // our signing pubkey
      //console.log('message', message, this.keypair.ed25519KeyPair.publicKey)
      //console.log('blindedPkBuf', blindedPkBuf)
      // this verifies fine now
      //await loki_crypto.verifySigDataV3(this.server.serverPubkeyHex, blindedPkBuf, plaintextBuf, message.signature)
      //return
      //this.roomData = await this.server.rpc('GET', '/room/' + this.room, '', '', this.keypair)
      const result = await this.server.rpc('POST', '/room/' + this.room + '/message', '', JSON.stringify(message), this.keypair)
      //console.log('result', result)
      // should give a 201

      // id, session_id, posted, seqno, data, signature, reactions, filtered
      if (!result || !result.id || !result.seqno) {
        console.error('SessionOpenGroupV3Room::send - bad result?', result)
        // FIXME: problem just call self again...
        return false
      }
      return result.id
    } catch (e) {
      console.error('SessionOpenGroupV3Room::send - Sending messages error', e)
    }
    return null
  }

  async messageDelete(messageId) {
    const result = await this.server.rpc('DELETE', '/room/' + this.room + '/message/' + messageId, '', '', this.keypair)
    //console.log('result', result)
    // {} seems to mean it worked
    if (result && Object.keys(result).length === 0) {
      return true
    }
    // 404 if already deleted
    console.error('SessionOpenGroupV3Room::delete - Wrong response received', result)
    return false
  }
}

module.exports = {
  SessionOpenGroupV3Manager: new SessionOpenGroupV3Manager(),
}