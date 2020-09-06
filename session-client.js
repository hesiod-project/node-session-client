const fs     = require('fs')
const EventEmitter  = require('events')

const lib = require('./lib/lib.js')
const attachemntUtils = require('./lib/attachments.js')
const keyUtil = require('./external/mnemonic/index.js')

/**
 * Default home server URL
 * @constant
 * @default
 */
const FILESERVER_URL = 'https://file.getsession.org/' // path required!

/**
 * Creates a new Session client
 * @class
 * @property {Number} pollRate How much delay between poll requests
 * @property {Number} lastHash Poll for messages from this hash on
 * @property {String} displayName Send messages with this profile name
 * @property {String} homeServer HTTPS URL for this identity's file server
 * @property {String} fileServerToken Token for avatar operations
 * @property {String} swarmUrl an storage server HTTPS URL for this identity's swarm
 * @property {String} identityOutput human readable string with seed words if generated a new identity
 * @property {String} ourPubkeyHex This identity's pubkey (SessionID)
 * @property {object} keypair This identity's keypair buffers
 * @property {Boolean} open Should we continue polling for messages
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
    this.pollRate = options.pollRate || 1000
    this.lastHash = options.lastHash || ''
    this.homeServer = options.homeServer || FILESERVER_URL
    this.fileServerToken = options.fileServerToken || ''
    this.displayName = options.displayName || false
    this.pollServer = false
  }

  // maybe a setName option
  // we could return identityOutput
  // also identityOutput in a more structured way would be good
  /**
   * set an identity for this session client
   * sets this.identityOutput
   * @async
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
      options.keypair = keyUtil.wordsToKeyPair(options.seed)
      this.identityOutput = 'Loaded SessionID ' + options.keypair.pubKey.toString('hex') + ' from seed words'
    }
    // ensure keypair
    if (!options.keypair) {
      const res = await keyUtil.newKeypair()
      this.identityOutput = 'SessionID ' + res.keypair.pubKey.toString('hex') + ' seed words: ' + res.words
      options.keypair = res.keypair
    }
    if (options.displayName) {
      this.displayName = options.displayName
    }
    // process keypair
    this.keypair = options.keypair
    this.ourPubkeyHex = options.keypair.pubKey.toString('hex')
    // we need ourPubkeyHex set
    if (options.avatarFile) {
      if (fs.existsSync(options.avatarFile)) {
        let avatarOk = false
        const avatarDisk = fs.readFileSync(options.avatarFile)
        // is this image uploaded to the server?
        const avatarRes = await attachemntUtils.getAvatar(FILESERVER_URL,
          this.ourPubkeyHex
        )
        if (!avatarRes) {
          console.warn('SessionClient::loadIdentity - getAvatar failure', avatarRes)
        } else {
          this.encAvatarUrl = avatarRes.url
          this.profileKeyBuf = Buffer.from(avatarRes.profileKey64, 'base64')
          const netData = await attachemntUtils.downloadEncryptedAvatar(
            this.encAvatarUrl, this.profileKeyBuf
          )
          if (!netData) {
            console.warn('SessionClient::loadIdentity - downloadEncryptedAvatar failure', netData)
          } else {
            if (avatarDisk.byteLength !== netData.byteLength ||
                Buffer.compare(avatarDisk, netData) !== 0) {
              console.log('SessionClient::loadIdentity - detected avatar change, replacing')
              await this.changeAvatar(avatarDisk)
            } else {
              avatarOk = true
            }
          }
        }
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
   * @async
   * @public
   */
  async open() {
    if (!this.ourPubkeyHex || this.ourPubkeyHex.length < 66) {
      console.error('no identity loaded')
      return
    }
    if (!this.swarmUrl) {
      this.swarmUrl = await lib.getSwarmsnodeUrl(this.ourPubkeyHex)
      //console.log('setting swarmUrl for', this.ourPubkeyHex, 'to', this.swarmUrl)
    }
    // lazy load recv library
    if (!this.recvLib) {
      /**
       * @private
       * @property {Object} recvLib
       */
      this.recvLib = require('./lib/recv.js')
    }
    this.pollServer = true
    // start polling our box
    this.poll()
  }

  /**
   * poll storage server for messages and emit events
   * @async
   * @public
   * @fires SessionClient#updateLastHash
   * @fires SessionClient#preKeyBundle
   * @fires SessionClient#receiptMessage
   * @fires SessionClient#nullMessage
   * @fires SessionClient#messages
   */
  async poll() {
    if (this.debugTimer) console.log('polling...')
    const result = await this.recvLib.checkBox(
      this.ourPubkeyHex, this.keypair, this.lastHash, lib, this.debugTimer
    )
    if (this.debugTimer) console.log('polled...')
    if (result) {
      if (result.lastHash !== this.lastHash) {
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
        this.emit('updateLastHash', result.lastHash)
        this.lastHash = result.lastHash
      }
      if (result.messages.length) {
        // emit them...
        const messages = []
        result.messages.forEach(msg => {
          //console.log('poll -', msg)
          // separate out simple messages to make it easier
          if (msg.dataMessage && (msg.dataMessage.body || msg.dataMessage.attachments)) {
            // maybe there will be something here...
            //console.log('pool dataMessage', msg)
            // skip session resets
            // desktop: msg.dataMessage.body === 'TERMINATE' &&
            if (!(msg.flags === 1)) { // END_SESSION
              // escalate source
              messages.push({ ...msg.dataMessage, source: msg.source })
            }
          } else
          if (msg.preKeyBundleMessage) {
            /**
             * content protobuf
             * @callback messageCallback
             * @param {object} content Content protobuf
             */
            /**
             * Received pre-key bundle message
             * @event SessionClient#preKeyBundle
             * @type messageCallback
             */
            this.emit('preKeyBundle', msg)
          } else
          if (msg.receiptMessage) {
            /**
             * Read Receipt message
             * @event SessionClient#receiptMessage
             * @type messageCallback
             */
            this.emit('receiptMessage', msg)
          } else
          if (msg.nullMessage) {
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
    }
    if (this.debugTimer) console.log('scheduled...')
    setTimeout(() => {
      if (this.debugTimer) console.log('firing...')
      if (this.pollServer) {
        if (this.debugTimer) console.log('calling...')
        this.poll()
      } else {
        if (this.debugTimer) console.log('closed...')
      }
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

  /**
   * get and decrypt all attachments
   * @async
   * @public
   * @param {Object} message message to download attachments from
   * @return {Promise<Array>} an array of buffers of downloaded data
   */
  getAttachments(msg) {
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
      const res = await attachemntUtils.downloadEncryptedAttachment(attachment.url, attachment.key)
      //console.log('attachmentRes', res)
      return res
    }))
  }

  /**
   * get and decrypt all attachments
   * @async
   * @public
   * @param {Buffer} data image data
   * @return {Promise<Object>} returns an attachmentPointer
   */
  async makeImageAttachment(data) {
    return attachemntUtils.uploadEncryptedAttachment(this.homeserver, data)
  }

  /**
   * get file server token for avatar operations
   * @async
   * @private
   * @fires SessionClient#fileServerToken
   */
  async ensureFileServerToken() {
    if (!this.fileServerToken) {
      // we need a token...
      this.fileServerToken = await attachemntUtils.getToken(
        this.homeserver, this.keypair.privKey, this.ourPubkeyHex
      )
      /**
       * Handle when we get a new home server token
       * @callback fileServerTokenCallback
       * @param {string} token The new token for their home server
       */
      /**
       * Exposes identity's home server token, to speed up start up
       * @event SessionClient#fileServerToken
       * @type fileServerTokenCallback
       */
      this.emit('fileServerToken', this.fileServerToken)
    }
    // else maybe verify token
  }

  /**
   * Change your avatar
   * @public
   * @async
   * @param {Buffer} data image data
   * @return {Promise<object>} avatar's URL and profileKey to decode
   * @uses ensureFileServerToken
   */
  async changeAvatar(data) {
    if (!this.ourPubkeyHex) {
      console.error('SessionClient::changeAvatar - Identity not set up yet')
      return
    }
    await this.ensureFileServerToken()
    const res = await attachemntUtils.uploadEncryptedAvatar(
      this.homeserver, this.fileServerToken, this.ourPubkeyHex, data)
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
   * @async
   * @public
   * @param {String} url Avatar URL
   * @param {Uint8Array} profileKeyUint8
   * @returns {Promise<Buffer>} a buffer containing raw binary data for image of avatar
   */
  decodeAvatar(url, profileKeyUint8) {
    const buf = Buffer.from(profileKeyUint8)
    return attachemntUtils.downloadEncryptedAvatar(url, buf)
  }

  /**
   * get any one's avatar
   * @async
   * @public
   * @param {String} url User's home server URL
   * @param {String} pubkeyHex Who's avatar you want
   * @returns {Promise<Buffer>} a buffer containing raw binary data for image of avatar
   */
  getAvatar(fSrvUrl, pubkeyHex) {
    return attachemntUtils.downloadEncryptedAvatar(fSrvUrl, pubkeyHex)
  }

  /**
   * Send a Session message
   * @async
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
  send(destination, messageTextBody, options = {}) {
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
    }
    return this.sendLib.send(destination, this.keypair, messageTextBody, lib, sendOptions)
  }

  /**
   * Send an open group invite
   * Currently works on desktop not on iOS/Android
   * @async
   * @public
   * @param {String} destination pubkey of who you want to send to
   * @param {String} serverName Server description
   * @param {String} serverAddress Server URL
   * @param {Number} channelId Channel number
   * @returns {Promise<Bool>} If operation was successful or not
   * @example
   * sessionClient.sendOpenGroupInvite('05d233c6c8daed63a48dfc872a6602512fd5a18fc764a6d75a08b9b25e7562851a', 'Session Chat', 'https://chat.getsession.org/', 1)
   */
  sendOpenGroupInvite(destination, serverName, serverAddress, channelId) {
    return this.sendLib.send(destination, this.keypair, undefined, lib, {
      groupInvitation: {
        serverAddress: serverAddress,
        channelId: channelId,
        serverName: serverName
      }
    })
  }

  /**
   * Request a session reset
   * @async
   * @public
   * @param {String} destination pubkey of who you want to send to
   * @returns {Promise<Bool>} If operation was successful or not
   * @example
   * sessionClient.sendSessionReset('05d233c6c8daed63a48dfc872a6602512fd5a18fc764a6d75a08b9b25e7562851a')
   */
  sendSessionReset(destination) {
    return this.sendLib.send(destination, this.keypair, 'TERMINATE', lib, {
      flags: 1
    })
  }

  /**
   * Respond that session has been established
   * @async
   * @public
   * @param {String} destination pubkey of who you want to send to
   * @returns {Promise<Bool>} If operation was successful or not
   * @example
   * sessionClient.sendSessionEstablished('05d233c6c8daed63a48dfc872a6602512fd5a18fc764a6d75a08b9b25e7562851a')
   */
  sendSessionEstablished(destination) {
    return this.sendLib.send(destination, this.keypair, '', lib, {
      nullMessage: true
    })
  }
}

module.exports = SessionClient
