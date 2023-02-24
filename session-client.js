const fs = require('fs')
const urlparser    = require('url')
const EventEmitter = require('events')

const lib = require('./lib/lib.js')
const attachemntUtils = require('./lib/attachments.js')
const openGroupUtilsV2 = require('./lib/open_group_v2.js')
const openGroupUtilsV3 = require('./lib/open_group_v3.js')
const keyUtil = require('./external/mnemonic/index.js')

/**
 * Default home server URL
 * @constant
 * @default
 */
const FILESERVERV2_URL = 'http://filev2.getsession.org' // no trailing slash for v2
const FILESERVERV2_PUBKEY = 'da21e1d886c6fbaea313f75298bd64aab03a97ce985b46bb2dad9f2089c8ee59'

/**
 * Creates a new Session client
 * @class
 * @property {Number} pollRate How much delay between poll requests
 * @property {Number} lastHash Poll for messages from this hash on
 * @property {String} displayName Send messages with this profile name
 * @property {String} homeServer URL for this identity's file server
 * @property {String} homeServerPubKey Pubkey in hex for this identity's file server
 * @property {String} identityOutput human readable string with seed words if generated a new identity
 * @property {String} ourPubkeyHex This identity's pubkey (SessionID)
 * @property {object} keypair This identity's keypair buffers
 * @property {Boolean} open Should we continue polling for messages
 * @property {String} encAvatarUrl Encrypted avatar URL
 * @property {Buffer} profileKeyBuf Key to decrypt avatar URL
 * @implements EventEmitter
 * @module session-client
 * @exports SessionClient
 * @author Ryan Tharp
 * @license ISC
 * @tutorial sample.js
 */
class SessionClient extends EventEmitter {
  /**
   * @constructor
   * @param {object} [options] Creation client options
   * @param {Number} [options.pollRate] How much delay between poll requests, Defaults: 1000
   * @param {Number} [options.lastHash] lastHash Poll for messages from this hash on Defaults: '' (Read all messages)
   * @param {Number} [options.homeServer] Which server holds your profile and attachments Defaults: https://file.getsession.org/
   * @param {Number} [options.displayName] Send messages with this profile name, Defaults: false (Don't send a name)
   * @example
   * const sessionClient = new SessionClient()
   */
  constructor(options = {}) {
    super()
    this.pollRate = options.pollRate || 3000
    this.lastHash = options.lastHash || ''
    this.homeServer = options.homeServer || FILESERVERV2_URL
    this.homeServerPubKey = options.homeServerPubkey || FILESERVERV2_PUBKEY
    this.displayName = options.displayName || false
    this.openGroupServers = {}
    this.openGroupV2Servers = {}
    this.pollServer = false
    this.groupInviteTextTemplate = '{pubKey} has invited you to join {name} at'
    this.groupInviteNonC1TextTemplate = ' You may not be able to join this channel if you are using a mobile session client'
    this.lastPoll = 0
  }

  // maybe a setName option
  // we could return identityOutput
  // also identityOutput in a more structured way would be good
  /**
   * set an identity for this session client
   * sets this.identityOutput
   * @public
   * @param {Object} options a list of options of how to set up the identity
   * @param {string} [options.seed] a space separate list of seed words
   * @param {Object} [options.keypair] a buffer keypair
   * @param {buffer} options.keypair.privKey a buffer that contains a curve25519-n private key
   * @param {buffer} options.keypair.pubKey a buffer that contains a curve25519-n public key
   * @param {string} [options.displayName] use this string as the profile name for messages
   * @param {string} [options.avatarFile] path to an image file to use as avatar
   * @example
   * client.loadIdentity({
   *   seed: fs.existsSync('seed.txt') && fs.readFileSync('seed.txt').toString(),
   *   //displayName: 'Sample Session Client',
   *   //avatarFile: 'avatar.png',
   * }).then(async() => {
   *   // Do stuff
   * })
   */
  async loadIdentity(options = {}) {
    if (options.seed) {
      // decode seed into keypair
      options.keypair = await keyUtil.wordsToKeyPair(options.seed)
      if (options.keypair.err) {
        console.error('err', options.keypair.err)
        process.exit(1)
      }
      if (!options.keypair) {
        console.error('keypair generation failed')
        process.exit(1)
      }
      this.identityOutput = 'Loaded SessionID ' + options.keypair.pubKey.toString('hex') + ' from seed words'
    }
    // ensure keypair
    if (!options.keypair) {
      const res = await keyUtil.newKeypair()
      this.identityOutput = 'SessionID ' + res.keypair.pubKey.toString('hex') + ' seed words: ' + res.words
      options.keypair = res.keypair
    }
    // ensure hexstr
    options.keypair.publicKeyHex = options.keypair.pubKey.toString('hex')
    if (options.displayName) {
      this.displayName = options.displayName
    }
    // process keypair
    this.keypair = options.keypair
    this.ourPubkeyHex = options.keypair.pubKey.toString('hex')
    // we need ourPubkeyHex set
    if (options.avatarFile) {
      if (fs.existsSync(options.avatarFile)) {
        const avatarOk = false
        const avatarDisk = fs.readFileSync(options.avatarFile)
        if (!avatarOk) {
          console.log('SessionClient::loadIdentity - unable to read avatar state, resetting avatar')
          await this.changeAvatar(avatarDisk)
        }
      } else {
        console.error('SessionClient::loadIdentity - avatarFile', options.avatarFile, 'is not found')
      }
    }
  }

  /**
   * start listening for messages
   * @public
   */
  async open() {
    if (this.pollServer) {
      console.warn('SessionClient - already opened')
      return
    }
    if (!this.ourPubkeyHex || this.ourPubkeyHex.length < 66) {
      console.error('no identity loaded')
      return
    }
    if (this.debugTimer) console.log(Date.now(), 'SessionClient::open - validated', this.ourPubkeyHex)
    // lazy load recv library
    if (!this.recvLib) {
      /**
       * @private
       * @property {Object} recvLib
       */
      this.recvLib = require('./lib/recv.js')
    }
    //console.log('library loaded', this.ourPubkeyHex)
    this.pollServer = true

    // start polling our box
    //console.log('start poll', this.ourPubkeyHex)
    await this.poll()
    //console.log('start watchdog', this.ourPubkeyHex)
    this.watchdog() // backup for production use
  }

  /**
   * watch poller, and make sure it's running if it should be running
   * @private
   */
  async watchdog() {
    // if closed
    if (!this.pollServer) {
      return // don't reschedule
    }
    // make sure we've polled successfully at least once
    if (this.lastPoll) {
      const ago = Date.now() - this.lastPoll
      // if you missed 10 polls in a roll
      if (ago > this.pollRate * 10 * 5) {
        this.lastPoll = Date.now() // prevent amplification
        // this scrolls off any error right now
        if (!this.watchdogSent > 3) {
          console.warn('SessionClient::watchdog - polling failure, would restart poller', ago, this.pollRate)
          this.watchdogSent++
        }
        //this.poll()
      }
    }
    // schedule us again
    setTimeout(() => {
      this.watchdog()
    }, this.pollRate)
  }

  /**
   * poll storage server for messages and emit events
   * @public
   * @fires SessionClient#updateLastHash
   * @fires SessionClient#preKeyBundle
   * @fires SessionClient#receiptMessage
   * @fires SessionClient#nullMessage
   * @fires SessionClient#messages
   */
  async poll() {
    // if closed
    if (!this.pollServer) {
      if (this.debugTimer) console.log(Date.now(), 'closed...')
      return // don't reschedule
    }
    if (this.debugTimer) console.trace(Date.now(), 'polling...', this.ourPubkeyHex, this.lastHash)
    //const ts = Date.now()
    const dmResult = await this.recvLib.checkBox(
      this.ourPubkeyHex, this.keypair, this.lastHash, lib, this.debugTimer
    )
    // dmResult being undefined usually means there was a network hiccup
    //console.debug(Date.now(), 'SessionClient::poll - recvLib got', dmResult)
    //console.log('polling took', (Date.now() - ts).toLocaleString())
    // commit the lastHash as soon as possible
    // as well as only commit it if it's returned
    if (dmResult && dmResult.lastHash && dmResult.lastHash !== this.lastHash) {
      /**
       * Handle when the cursor in the pubkey's inbox moves
       * @callback updateLastHashCallback
       * @param {String} hash The last hash returns from the storage server for this pubkey
       */
      /**
       * Exposes the last hash, so you can persist between reloads where you left off
       * and not process commands twice
       * @event SessionClient#updateLastHash
       * @type updateLastHashCallback
       */
      this.emit('updateLastHash', dmResult.lastHash)
      this.lastHash = dmResult.lastHash
    }
    const groupResults = (await Promise.all(Object.keys(this.openGroupServers).map(async (openGroup) => {
      //console.log('poll - polling open group', openGroup, this.openGroupServers[openGroup])
      //console.log('poll - open group token', this.openGroupServers[openGroup].token)
      const groupMessages = await this.openGroupServers[openGroup].getMessages()
      if (groupMessages && groupMessages.length > 0) {
        return { openGroup, groupMessages }
      }
      return undefined
    }))).filter((m) => !!m)
    const v2GroupResults = await openGroupUtilsV2.SessionOpenGroupV2Manager.getMessages()
    const v3GroupResults = await openGroupUtilsV3.SessionOpenGroupV3Manager.getMessages()
    const newerGroupResults = [...v2GroupResults, ...v3GroupResults]
    //console.debug('newerGroupResults', newerGroupResults.length)

    if (this.debugTimer) console.log(Date.now(), 'polled...', this.ourPubkeyHex)
    if (dmResult || groupResults.length > 0 || newerGroupResults.length > 0) {
      const messages = newerGroupResults
      if (dmResult) {
        if (dmResult.messages.length) {
          // emit them...

          dmResult.messages.forEach(msg => {
            //console.log('poll -', msg)
            // separate out simple messages to make it easier
            if (msg.dataMessage && (msg.dataMessage.body || msg.dataMessage.attachments)) {
              // maybe there will be something here...
              //console.log('pool dataMessage', msg.dataMessage)
              //console.log('DM attachments', msg.dataMessage.attachments)
              // skip session resets
              // desktop: msg.dataMessage.body === 'TERMINATE' &&
              if (!(msg.flags === 1)) { // END_SESSION
                // escalate source
                messages.push({ ...msg.dataMessage, source: msg.source })
              }
            } else
            if (msg.messageRequestResponse) {
              // messageRequestResponse: { isApproved: true/false }
              // snodeExp/source/hash
              /**
               * Message Request Response message
               * @event SessionClient#messageRequestResponse
               * @type messageCallback
               */
              this.emit('messageRequestResponse', msg)
            } else
            if (msg.unsendMessage) {
              // when someone deletes a message
              // msg: timestamp, author (sessionid)
              /**
               * Unsend message
               * @event SessionClient#unsendMessage
               * @type messageCallback
               */
              this.emit('unsendMessage', msg)
            } else
            if (msg.typingMessage) {
              // timestamp, action: 0
              // snodeExp/source
              //console.log('typingMessage', msg)
              /**
               * Typing message
               * @event SessionClient#typingMessage
               * @type messageCallback
               */
              this.emit('typingMessage', msg)
            } else
            if (msg.receiptMessage) {
              // msg.recieptMessage.timestamp is an array of unsigned protobuf longs..
              //console.log(msg.source, 'receiptMessage', msg.receiptMessage.type, msg.receiptMessage.timestamp, msg.snodeExp)
              /**
               * Read Receipt message
               * @event SessionClient#receiptMessage
               * @type messageCallback
               */
              this.emit('receiptMessage', msg)
            } else
            if (msg.configurationMessage) {
              /**
               * Multidevice config message
               * @event SessionClient#configurationMessage
               * @type messageCallback
               */
              this.emit('configurationMessage', msg)
            } else
            if (msg.nullMessage) {
              console.log('nullMessage', msg)
              /**
               * session established message
               * @event SessionClient#nullMessage
               * @type messageCallback
               */
              this.emit('nullMessage', msg)
            } else {
              console.log('poll - unhandled message', msg)
            }
          })
        }
      }
      if (groupResults.length) {
        groupResults.forEach(group => group.groupMessages.forEach(message => {
          // Exclude our own messages
          if (message.user.username !== this.ourPubkeyHex) {
            // FIXME: quotes? attachments?
            messages.push({
              openGroup: group.openGroup,
              body: message.text,
              profile: {
                displayName: message.user.name,
                avatar: message.user.avatar_image.url,
              },
              source: message.user.username,
            })
          }
        }))
      }
      if (messages.length) {
        /**
         * content dataMessage protobuf
         * @callback messagesCallback
         * @param {Array} messages an array of Content protobuf
         */
        /**
         * Messages usually with content
         * @module session-client
         * @event SessionClient#messages
         * @type messagesCallback
         */
        this.emit('messages', messages)
      }
    }
    this.lastPoll = Date.now()
    if (this.debugTimer) console.log(Date.now(), 'scheduled...', this.pollRate + 'ms')
    setTimeout(() => {
      if (this.debugTimer) console.log(Date.now(), 'firing...')
      this.poll()
    }, this.pollRate)
  }

  /**
   * stop listening for messages
   * @public
   */
  close() {
    if (this.debugTimer) console.log('closing')
    this.pollServer = false
  }

  async getLastHashFromSwarm() {
    const pubKey = this.ourPubkeyHex
    const url = await lib.getSwarmsnodeUrl(pubKey)
    const messageData = await lib.pubKeyAsk(url, 'retrieve', pubKey, {
      lastHash: this.lastHash
    })
    //console.log('getLastHashFromSwarm', messageData)
    if (!messageData.messages || !messageData.messages.length) {
      return undefined
    }
    const lastMsg = messageData.messages.pop()
    return lastMsg.hash
  }

  /**
   * get and decrypt all attachments
   * @public
   * @param {Object} message message to download attachments from
   * @return {Promise<Array>} an array of buffers of downloaded data
   */
  async getAttachments(msg) {
    /*
    attachment AttachmentPointer {
      id: Long { low: 159993, high: 0, unsigned: true },
      contentType: 'image/jpeg',
      key: Uint8Array(64) [
        132, 169, 117,  10, 194,  47, 216,  60,  27,   1, 227,
         49,  16, 116, 170,  67,  89, 135, 139,  11,  75,  54,
        130, 184,  16, 174, 252,  26, 164, 251, 114, 244,  37,
        180,  52, 139, 149, 108,  60,  16,  63, 154, 161,  80,
         85, 198,  90, 116,  56, 214, 212, 111, 156,  55, 221,
         44,  39, 202,  46,   4, 190, 169, 193,  26
      ],
      size: 6993,
      digest: Uint8Array(32) [
        193,  15, 127,  86,  79,   0, 239, 104,
        202, 189,  49, 238,  79, 192, 119, 168,
        221, 223, 237,  30, 171, 191,  48, 181,
         94,   6,   7, 155, 209, 116,  84, 171
      ],
      fileName: 'images.jpeg',
      url: 'https://file-static.lokinet.org/f/ciebnq'
    }
    */
    return Promise.all(msg.attachments.map(async attachment => {
      // attachment.key
      // could check digest too (should do that inside decryptCBC tho)
      // hack around session support for multiple servers
      const options = { pubkey: this.homeServerPubKey }
      // downloadEncryptedAttachment should return a buffer
      const res = await attachemntUtils.downloadEncryptedAttachment(attachment.url, attachment.key, options)
      //console.log('attachmentRes', res)
      return res
    }))
  }

  /**
   * get and decrypt all attachments
   * @public
   * @param {Buffer} data image data
   * @return {Promise<Object>} returns an attachmentPointer
   */
  async makeImageAttachment(data) {
    if (data === undefined) {
      console.trace('SessionClient::makeImageAttachment - params passed is undefined')
      return
    }
    return attachemntUtils.uploadEncryptedAttachment(this.homeServer, this.homeServerPubKey, data)
  }

  /**
   * Change your avatar
   * @public
   * @param {Buffer} data image data
   * @return {Promise<object>} avatar's URL and profileKey to decode
   */
  async changeAvatar(data) {
    if (!this.ourPubkeyHex) {
      console.error('SessionClient::changeAvatar - Identity not set up yet')
      return
    }
    const res = await attachemntUtils.uploadEncryptedAvatar(
      this.homeServer, this.homeServerPubKey, data)
    //console.log('SessionClient::changeAvatar - res', res)
    /* profileKeyBuf: buffer
      url: string */

    // update our state
    this.encAvatarUrl = res.url
    this.profileKeyBuf = res.profileKeyBuf

    return res
  }

  /**
   * decode an avatar (usually from a message)
   * @public
   * @param {String} url Avatar URL
   * @param {Uint8Array} profileKeyUint8
   * @returns {Promise<Buffer>} a buffer containing raw binary data for image of avatar
   */
  async decodeAvatar(url, profileKeyUint8) {
    const buf = Buffer.from(profileKeyUint8)
    // hack around session support for multiple servers
    const options = { pubkey: this.homeServerPubKey }
    return attachemntUtils.downloadEncryptedAvatar(url, buf, options)
  }

  /**
   * Send a Session message
   * @public
   * @param {String} destination pubkey of who you want to send to
   * @param {String} [messageTextBody] text message to send
   * @param {object} [options] Send options
   * @param {object} [options.attachments] Attachment Pointers to send
   * @param {String} [options.displayName] Profile name to send as
   * @param {object} [options.avatar] Avatar URL/ProfileKey to send
   * @param {object} [options.groupInvitation] groupInvitation to send
   * @param {object} [options.flags] message flags to set
   * @param {object} [options.nullMessage] include a nullMessage
   * @returns {Promise<Bool>} If operation was successful or not
   * @example
   * sessionClient.send('05d233c6c8daed63a48dfc872a6602512fd5a18fc764a6d75a08b9b25e7562851a', 'I didn\'t change the pubkey')
   */
  async send(destination, messageTextBody, options = {}) {
    // lazy load recv library
    if (!this.sendLib) {
      this.sendLib = require('./lib/send.js')
    }
    const sendOptions = { ...options }
    if (this.displayName) sendOptions.displayName = this.displayName
    if (this.encAvatarUrl && this.profileKeyBuf) {
      sendOptions.avatar = {
        url: this.encAvatarUrl,
        profileKeyBuf: this.profileKeyBuf
      }
      //console.log('session-client::send - inserting avatar info', sendOptions)
    }
    try {
      return this.sendLib.send(destination, this.keypair, messageTextBody, lib, sendOptions)
    } catch (e) {
      console.error('session-client::send - exception', e)
    }
    return false
  }

  /**
   * Send an open group invite
   * Currently works on desktop not on iOS/Android
   * @public
   * @param {String} destination pubkey of who you want to send to
   * @param {String} serverName Server description
   * @param {String} serverAddress Server URL
   * @param {Number} channelId Channel number
   * @returns {Promise<Bool>} If operation was successful or not
   * @example
   * sessionClient.sendOpenGroupInvite('05d233c6c8daed63a48dfc872a6602512fd5a18fc764a6d75a08b9b25e7562851a', 'Session Chat', 'https://chat.getsession.org/', 1)
   */
  async sendOpenGroupInvite(destination, serverName, serverAddress, channelId) {
    return this.sendLib.send(destination, this.keypair, undefined, lib, {
      groupInvitation: {
        serverAddress: serverAddress,
        channelId: parseInt(channelId),
        serverName: serverName
      }
    })
  }

  /**
   * Send an open group invite with additional text for mobile
   * seems to work with V2 (leave channel as 1)
   * @public
   * @param {String} destination pubkey of who you want to send to
   * @param {String} serverName Server description
   * @param {String} serverAddress Server URL
   * @param {Number} channelId Channel number
   * @returns {Promise<Bool>} If operation was successful or not
   * @example
   * sessionClient.sendOpenGroupInvite('05d233c6c8daed63a48dfc872a6602512fd5a18fc764a6d75a08b9b25e7562851a', 'Session Chat', 'https://chat.getsession.org/', 1)
   */
  async sendSafeOpenGroupInvite(destination, serverName, serverAddress, channelId) {
    // FIXME: maybe send a text with this
    channelId = parseInt(channelId)
    // this.groupInviteTextTemplate = '{pubKey} has invited you to join {name} at {url}'
    let msg = this.groupInviteTextTemplate
    msg = msg.replace(/{pubKey}/g, this.ourPubkeyHex)
    msg = msg.replace(/{name}/g, serverName)
    msg = msg.replace(/{url}/g, serverAddress)
    if (channelId !== 1) {
      msg += this.groupInviteNonC1TextTemplate
    }
    await this.send(destination, msg)
    // send the URL separately...
    await this.send(destination, serverAddress)
    return this.sendOpenGroupInvite(destination, serverName, serverAddress, channelId)
  }

  /**
   * Join Open Group V2, Receive Open Group V2 token
   * @public
   * @param {String} open group handle
   * @param {Number} open group Channel
   * @returns {Promise<Object>} Object {token: {String}, channelId: {Int}, lastMessageId: {Int}}
   * @example
   * sessionClient.joinOpenGroup('chat.getsession.org')
   */
  async joinOpenGroupV2(openGroupURL, options = {}) {
    console.log('Joining Open Group V2', openGroupURL)

    // parse URL into parts
    const urlDetails = new urlparser.URL(openGroupURL)
    const baseUrl = urlDetails.protocol + '//' + urlDetails.host
    const room = urlDetails.pathname.substr(1).toString()
    const serverPubkeyHex = urlDetails.searchParams.get('public_key')

    // ensure room
    const roomObj = await openGroupUtilsV2.SessionOpenGroupV2Manager.joinServerRoom(
      baseUrl, serverPubkeyHex, this.keypair, room, options)
    // returns false if can't get a token
    // get token, so we can get initial messages
    if (roomObj) {
      roomObj.ensureToken()
    }
    // return handle
    return roomObj
  }

  /**
   * Join Open Group V3, Receive Open Group V3 token
   * @public
   * @param {String} open group handle
   * @param {Number} open group Channel
   * @returns {Promise<Object>} Object {token: {String}, channelId: {Int}, lastMessageId: {Int}}
   * @example
   * sessionClient.joinOpenGroupV3('chat.getsession.org')
   */
  async joinOpenGroupV3(openGroupURL, options = {}) {
    console.log('Joining Open Group V3', openGroupURL)

    // parse URL into parts
    const urlDetails = new urlparser.URL(openGroupURL)
    const baseUrl = urlDetails.protocol + '//' + urlDetails.host
    const room = urlDetails.pathname.substr(1).toString()
    const serverPubkeyHex = urlDetails.searchParams.get('public_key')

    // ensure room
    const roomObj = await openGroupUtilsV3.SessionOpenGroupV3Manager.joinServerRoom(
      baseUrl, serverPubkeyHex, this.keypair, room, options)
    // returns false if can't get a token
    // get token, so we can get initial messages
    if (roomObj) {
      // FIXME: avatar
      if (this.displayName !== false) roomObj.updateProfile(this.displayName)
      roomObj.ensureToken()
    }
    // return handle
    return roomObj
  }

  /**
   * Send Open Group V2 Message
   * @public
   * @param {String} open group handle
   * @example
   * sessionClient.joinOpenGroup('chat.getsession.org')
   */
  async sendOpenGroupV2Message(roomObj, messageTextBody, options = {}) {
    return roomObj.send(messageTextBody, options)
  }

  /**
   * Send Open Group V3 Message
   * @public
   * @param {String} open group handle
   * @example
   * sessionClient.joinOpenGroup('chat.getsession.org')
   */
  async sendOpenGroupV3Message(roomObj, messageTextBody, options = {}) {
    // FIXME: avatar
    if (this.displayName !== false) roomObj.updateProfile(this.displayName)
    return roomObj.send(messageTextBody, options)
  }

  /**
   * Delete Open Group V2 Message
   * @public
   * @param {String} open group V2 handle
   * @param {Int} message ID to delete
   * @returns {Promise<Array>} result of deletion (false, null or true)
   * @example
   * sessionClient.joinOpenGroup('chat.getsession.org')
   */
  deleteOpenGroupV2Message(roomObj, messageIds) {
    if (!Array.isArray(messageIds)) { messageIds = [messageIds] }
    // fire them all off in parallel
    return Promise.all(messageIds.map(id => {
      return roomObj.messageDelete(id)
    }))
  }

  /**
   * Delete Open Group V3 Message
   * @public
   * @param {String} open group V3 handle
   * @param {Int} message ID to delete
   * @returns {Promise<Array>} result of deletion (false, null or true)
   * @example
   * sessionClient.joinOpenGroup('chat.getsession.org')
   */
  deleteOpenGroupV3Message(roomObj, messageIds) {
    return this.deleteOpenGroupV2Message(roomObj, messageIds)
  }
}

module.exports = SessionClient
