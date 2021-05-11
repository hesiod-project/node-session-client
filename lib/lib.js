//const http      = require('http')
const https     = require('https')
const TextEncoder = require('util').TextEncoder

// FIXME: remove fetch
const fetch = require('node-fetch')
const libloki = require('./lib.loki_crypto')
const ByteBuffer = require('bytebuffer')

// official seed node list
const seedNodeList = [
  {
    ip_url: 'http://116.203.53.213/',
    url: 'https://storage.seed1.loki.network/json_rpc'
  },
  {
    ip_url: 'http://212.199.114.66/',
    url: 'https://storage.seed3.loki.network/json_rpc'
  },
  {
    ip_url: 'http://144.76.164.202/',
    url: 'https://public.loki.foundation/json_rpc'
  }
]

const snodeHttpsAgent = new https.Agent({
  rejectUnauthorized: false
})

function getRandomOne(items) {
  return items[parseInt(Math.random() * items.length)]
}

let seedSSCache = null
async function getStorageServersFromSeed() {
  // ensure we only bug them once
  if (seedSSCache !== null) {
    return seedSSCache
  }
  const seed = getRandomOne(seedNodeList)
  // get 5 servers to start
  const params = {
    active_only: true,
    fields: {
      public_ip: true,
      storage_port: true,
    },
    // be nice to seed nodes
    limit: 5,
  }
  const res = await jsonrpc(seed.url, 'get_n_service_nodes', params)
  const storageSeedURLs = res.result.service_node_states.filter(
    snode => snode.public_ip !== '0.0.0.0'
  ).map(state => 'https://' + state.public_ip + ':' + state.storage_port + '/storage_rpc/v1')
  seedSSCache = storageSeedURLs // don't bug the lokid seeds again
  return storageSeedURLs
}

async function getStorageServersFromSS() {
  // prevent infinite loops by always relying on our (cached) seed list
  const nodeURL = await getRandomSnode(true)
  const params = {
    active_only: true,
    fields: {
      public_ip: true,
      storage_port: true,
    },
    // get the full list
    //limit: 1024,
  }
  // get_n_service_nodes is not allowed
  const body = {
    method: 'oxend_request',
    params: {
      endpoint: 'get_service_nodes',
      params
    }
  }
  try {
    const res = await jsonrpc(nodeURL, 'oxend_request', body.params, { snode: true })
    const storageSeedURLs = res.result.service_node_states.filter(
      snode => snode.public_ip !== '0.0.0.0'
    ).map(state => 'https://' + state.public_ip + ':' + state.storage_port + '/storage_rpc/v1')
    return storageSeedURLs
  } catch (e) {
    console.error('lib::getStorageServersFromSS - exception', e)
  }
}

// attachment uses this
async function bufferAsk(url, fetchOptions = {}) {
  const options = {
    ...fetchOptions,
    agent: snodeHttpsAgent
  }
  const result = await fetch(url, options)
  const text = await result.buffer()
  return text
}

// SOGS and attachment use this
async function textAsk(url, fetchOptions = {}) {
  const options = {
    ...fetchOptions,
  }
  let result = false
  try {
    result = await fetch(url, options)
    //console.log(url, 'code', result.status)
    const text = await result.text()
    return text
  } catch (e) {
    console.error('lib::textAsk - err', e, url, 'code', e.code)
    // e.code === ECONNRESET (socket hang up)
    // e.code === ECONNREFUSED (connect)
    // e.code === network timeout/request-timeout (e.type === request-timeout)
  }
}

// SOGS and attachment use this
async function jsonAsk(url, fetchOptions = {}) {
  const json = await textAsk(url, fetchOptions)
  //console.log('json', json)
  if (!json) return // don't try to parse obviously invalid json
  if (json === 'Not Found') return // likely forgot /json_rpc
  // avoid parsing text error messages
  // not in any swarm; not done syncing;
  if (json.match(/Service node is not ready:/)) {
    return
  }
  try {
    const obj = JSON.parse(json)
    return obj
  } catch (e) {
    console.error('lib::jsonAsk - err', e, 'json', json)
    return json
  }
}

async function jsonrpc(url, method, params, options = {}) {
  if (!url) {
    console.trace('lib::jsonrpc - no url')
    return
  }
  const body = {
    jsonrpc: '2.0',
    id: '0',
    method,
    params
  }
  const fetchOptions = {
    method: 'POST',
    body: JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json'
    },
    timeout: 30 * 1000,
    agent: options && options.snode ? snodeHttpsAgent : undefined,
  }
  return await jsonAsk(url, fetchOptions)
}

const textEncoder  = new TextEncoder()
async function lsrpc(baseUrl, querystring, destX25519hex, endpoint, method, body, headers) {
  const url = baseUrl + '/loki/v3/lsrpc'
  // encryptForRelayV2, encodeCiphertextPlusJson, encryptForPubKey

  // ephermalKeypair is x25519
  const ephermalKeypair = await libloki.generateEphemeralKeyPair()
  const ephermalPubkeyHex = ephermalKeypair.pubKey.toString('hex')

  // make OR sym key
  const destX25519buf = Buffer.from(destX25519hex, 'hex')
  const symKey = libloki.makeOnionSymKey(ephermalKeypair.privKey, destX25519buf)

  // new create unencrytped json metadata section
  const onionRequestPayloadMetadata = {
    // destination: host,protocol,port,destination,method,target
    ephemeral_key: ephermalPubkeyHex,
  }
  const payloadStr = JSON.stringify(onionRequestPayloadMetadata)
  const bufferJson = ByteBuffer.wrap(payloadStr, 'utf8')

  // now calculate encrypted payload (finalDestOptions)
  const rpcCall = {
    endpoint,
    body,
    method,
    headers,
  }
  if (querystring) {
    rpcCall.endpoint += '?' + querystring
  }
  //console.log('lsrpc rpcCall', rpcCall, 'destX25519hex', destX25519hex, 'url', url)

  const rpcStr = JSON.stringify(rpcCall)
  const rpcPlaintext = textEncoder.encode(rpcStr)
  const rpcCipherTextBuf = libloki.encryptGCM(symKey, rpcPlaintext)

  // we don't need to encrypt this
  const sizeBuf = Buffer.alloc(4)
  sizeBuf.writeUInt32LE(rpcCipherTextBuf.byteLength)
  const plaintextBuf = Buffer.concat([sizeBuf, rpcCipherTextBuf, bufferJson.buffer])

  const payloadBuf = plaintextBuf
  const fetchOptions = {
    method: 'POST',
    body: payloadBuf,
    timeout: 30 * 1000,
  }
  const data64 = await textAsk(url, fetchOptions)
  if (!data64) {
    console.error('lib::lsrpc - ', endpoint, 'got empty result')
    return false
  }
  let json
  try {
    const cipherText = Buffer.from(data64, 'base64')
    json = libloki.decryptGCM(symKey, cipherText)
  } catch (e) {
    console.error('lib::lsrpc - ', endpoint, 'exception', e, 'could not parse', data64)
    return false
  }
  try {
    const result = JSON.parse(json)
    if (!result) {
      console.error('empty json', json)
      return
    }
    //console.log('result', result)
    if (result.status_code !== 200) {
      console.warn('lib::lsrpc - ', endpoint, 'Got HTTP', result.status_code, 'retry?')
      //return
    }
    return result
  } catch (e) {
    console.error('lib::lsrpc - ', endpoint, 'exception', e)
  }
  return false
}

// only getStorageServersFromSeed should set useSeed to true
// lns also uses this
async function getRandomSnode(useSeed) {
  const allNodes = Object.entries(swarmMap).reduce((acc, [pubkey, obj]) => {
    const snodesUrlList = obj.snodes.map(snode =>
      'https://' + snode.ip + ':' + snode.port + '/storage_rpc/v1'
    )
    // Set makes it unique
    return Array.from(new Set(acc.concat(snodesUrlList)))
  }, useSeed ? await getStorageServersFromSeed() : await getStorageServersFromSS())
  return getRandomOne(allNodes)
}

// there's only one network ever...
const swarmMap = {}
const lastXMessages = []
// if we have the pubKey, can't we just internally look up the swarm...
async function pubKeyAsk(url, method, pubKey, params = {}) {
  const res = await jsonrpc(url, method, {...params, pubKey: pubKey }, { snode: true })
  if (!res) {
    console.warn('lib::pubKeyAsk - no response from', url, method, pubKey)
    return
  }
  // process swarm updates
  if (res.snodes) {
    // update swarmMap
    swarmMap[pubKey] = {
      updated_at: Date.now(),
      snodes: res.snodes
    }
    // retrieve can indicate a swarm reorg
    if (method !== 'get_snodes_for_pubkey') {
      console.warn('lib::pubKeyAsk - Swarm reorg for', pubKey)
      // retry
      return pubKeyAsk(url, method, params)
    }
  }
  if (method === 'retrieve') {
    //console.log('res', res, 'params', params)
    const newMsgs = []
    for (const i in res.messages) {
      const msg = res.messages[i]
      // msg.data, expiration, hash
      if (lastXMessages.indexOf(msg.expirartion) === -1) {
        lastXMessages.push(msg.expiration)
        newMsgs.push(msg)
      } else {
        console.log('filtered out duplicate', msg.expiration)
      }
    }
    res.messages = newMsgs
  }
  return res
}

// uses a lock; open and send can race...
let getSwarmsnodeUrlLock = false
// send/recv both use this
async function getSwarmsnodeUrl(pubkey) {
  if (!pubkey || pubkey.length < 66) {
    console.trace('lib::getSwarmsnodeUrl - invalid pubkey', pubkey && pubkey.length, pubkey)
    return
  }
  if (getSwarmsnodeUrlLock) {
    //console.warn('lib::getSwarmsnodeUrl - locked, waiting')
    return new Promise(resolve => {
      setTimeout(async () => {
        const url = await getSwarmsnodeUrl(pubkey)
        resolve(url)
      }, 1000)
    })
  }
  // cache snodes list
  if (!swarmMap[pubkey] || Date.now() - swarmMap[pubkey] > 3600) {
    // only lock if we need to check the network
    getSwarmsnodeUrlLock = true
    const nodeURL = await getRandomSnode(false)
    const snodesData = await pubKeyAsk(nodeURL, 'get_snodes_for_pubkey', pubkey)
    if (!snodesData) {
      console.error('lib::getSwarmnodeUrl - Could not get snodes from', nodeURL, 'pubkey', pubkey)
      // retry using a different node
      getSwarmsnodeUrlLock = false
      return
    }
    if (!snodesData.snodes) {
      console.error('lib::getSwarmnodeUrl - (2)Could not get snodes from', nodeURL, 'pubkey', pubkey, snodesData)
      getSwarmsnodeUrlLock = false
      return
    }
    // snodesData gets into swarmMap via pubKeyAsk
  }
  const randomNode = getRandomOne(swarmMap[pubkey].snodes)
  /*
  { address: 'o99bz7gpo3jhy8nx7zpaeau8ea7a9kkipwdszn3ppeai3khqdn1o.snode',
      ip: '68.183.236.72',
      port: '22021',
      pubkey_ed25519:
       '028a954d7551520416b4e44caf8fa62fe262facd4881dcc9eb3dce80eb3a7401',
      pubkey_x25519:
       '0ea63d99abcc85d1c810cf0b36df4193913e0d13033a50d6a8dfa4f830ec7f32' }
  */
  const newUrl = 'https://' + randomNode.ip + ':' + randomNode.port + '/storage_rpc/v1'
  getSwarmsnodeUrlLock = false
  return newUrl
}

module.exports = {
  bufferAsk,
  textAsk,
  jsonAsk,
  lsrpc,
  getRandomSnode,
  pubKeyAsk,
  getSwarmsnodeUrl
}
