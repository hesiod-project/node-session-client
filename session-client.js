const libsignal     = require('libsignal')
const EventEmitter  = require('events')
const lib = require('./lib/lib.js')

class SessionClient extends EventEmitter {
  // options.seed
  // options.keypair
  // options.seedUrl
  constructor(options = {}) {
    super()
    if (options.seed) {
      // decode seed into keypair
    }
    // ensure keypair
    if (!options.keypair) {
      options.keypair = libsignal.curve.generateKeyPair()
    }
    // process keypair
    this.keypair = options.keypair
    this.ourPubkeyHex = options.keypair.pubKey.toString('hex')
    //console.log('ourPubkeyHex', this.ourPubkeyHex)
    this.pollRate = options.pollRate || 1000
    this.lastHash = options.lastHash || ''
  }

  async open() {
    if (!this.swarmUrl) {
      this.swarmUrl = await lib.getSwarmsnodeUrl(this.ourPubkeyHex)
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
    this.lastHash = result.lastHash
    if (result.messages.length) {
      // emit them...
      this.emit('messages', result.messages)
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

  send(destination, messageTextBody, options = {}) {
    // lazy load recv library
    if (!this.sendLib) {
      this.sendLib = require('./lib/send.js')
    }
    return this.sendLib.send(destination, this.keypair, messageTextBody, lib)
  }
}

module.exports = SessionClient
