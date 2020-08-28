const fs     = require('fs')
const EventEmitter  = require('events')

const lib = require('./lib/lib.js')
const attachemntUtils = require('./lib/attachments.js')
const keyUtil = require('./external/mnemonic/index.js')

const FILESERVER_URL = 'https://file.getsession.org/' // path required!

class SessionClient extends EventEmitter {
  // options.seed
  // options.keypair
  // options.seedUrl
  constructor(options = {}) {
    super()
    //console.log('ourPubkeyHex', this.ourPubkeyHex)
    this.pollRate = options.pollRate || 1000
    this.lastHash = options.lastHash || ''
    this.displayName = false
  }

  // maybe a setName / setAvatar option
  async loadIdentity(options = {}) {
    if (options.seed) {
      // decode seed into keypair
      options.keypair = keyUtil.wordsToKeyPair(options.seed)
      console.log('Loaded SessionID', options.keypair.pubKey.toString('hex'), 'from seed words')
    }
    // ensure keypair
    if (!options.keypair) {
      const res = await keyUtil.newKeypair()
      console.log('SessionID', res.keypair.pubKey.toString('hex'), 'seed words:', res.words)
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
      this.recvLib = require('./lib/recv.js')
    }
    this.open = true
    // start polling our box
    this.poll()
  }

  async poll() {
    const result = await this.recvLib.checkBox(
      this.ourPubkeyHex, this.swarmUrl, this.keypair, this.lastHash, lib
    )
    if (result) {
      if (result.lastHash !== this.lastHash) {
        this.emit('updateLastHash', result.lastHash)
        this.lastHash = result.lastHash
      }
      if (result.messages.length) {
        // emit them...
        const messages = []
        result.messages.forEach(msg => {
          // separate out simple messages to make it easier
          if (msg.dataMessage && (msg.dataMessage.body || msg.dataMessage.attachments)) {
            // escalate source
            messages.push({ ...msg.dataMessage, source: msg.source })
          } else
          if (msg.preKeyBundleMessage) {
            this.emit('preKeyBundle', msg)
          } else
          if (msg.receiptMessage) {
            this.emit('receiptMessage', msg)
          } else {
            console.log('poll - unhandled message', msg)
          }
        })
        if (messages.length) {
          this.emit('messages', messages)
        }
      }
    }
    setTimeout(() => {
      if (this.open) {
        this.poll()
      }
    }, this.pollRate)
  }

  // get and decrypt all attachments
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

  async makeAttachment(data) {
    const res = attachemntUtils.uploadEncryptedAttachment(FILESERVER_URL, data)
    return res
  }

  async ensureFileServerToken() {
    if (!this.fileServerToken) {
      // we need a token...
      this.fileServerToken = await attachemntUtils.getToken(
        FILESERVER_URL, this.keypair.privKey, this.ourPubkeyHex
      )
      this.emit('fileServerToken', this.fileServerToken)
    }
    // else maybe verify token
  }

  async changeAvatar(data) {
    if (!this.ourPubkeyHex) {
      console.error('SessionClient::changeAvatar - Identity not set up yet')
      return
    }
    await this.ensureFileServerToken()
    const res = await attachemntUtils.uploadEncryptedAvatar(
      FILESERVER_URL, this.fileServerToken, this.ourPubkeyHex, data)
    //console.log('SessionClient::changeAvatar - res', res)
    /* profileKeyBuf: buffer
      url: string */

    // update our state
    this.encAvatarUrl = res.url
    this.profileKeyBuf = res.profileKeyBuf

    return res
  }

  close() {
    this.open = false
  }

  // this.sendLib.send is async
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

  sendOpenGroupInvite(destination, serverName, serverAddress, channelId) {
    return this.sendLib.send(destination, this.keypair, undefined, lib, {
      groupInvitation: {
        serverAddress: serverAddress,
        channelId: channelId,
        serverName: serverName
      }
    })
  }
}

module.exports = SessionClient
