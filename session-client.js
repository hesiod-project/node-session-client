const libsignal     = require('libsignal')
const EventEmitter  = require('events')
const lib = require('./lib/lib.js')

const keyUtil = require('./external/mnemonic/index.js')

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
        this.emit('messages', result.messages)
      }
    }
    setTimeout(() => {
      if (this.open) {
        this.poll()
      }
    }, this.pollRate)
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
    return this.sendLib.send(destination, this.keypair, messageTextBody, lib, {
      displayName: this.displayName
    })
  }
}

module.exports = SessionClient
