//const http      = require('http')
const https       = require('https')
const TextEncoder = require('util').TextEncoder
const _sodium = require('libsodium-wrappers') // maybe put in session-client?

// FIXME: remove fetch and use http/https directly?
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

async function getStorageServersFromSS(edKey) {
  // prevent infinite loops by always relying on our (cached) seed list
  const nodeURL = await getRandomSnode(true)
  //console.log('libgetStorageServers - FromSSnodeURL', nodeURL)
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
    const res = await signed_jsonrpc(nodeURL, 'oxend_request', body.params, { snode: true, edKey })
    if (!res || !res.result) {
      console.warn('lib::getStorageServersFromSS - empty res', res)
      // maybe retry?
      return getStorageServersFromSS(edKey)
    }
    const storageSeedURLs = res.result.service_node_states.filter(
      snode => snode.public_ip !== '0.0.0.0'
    ).map(state => 'https://' + state.public_ip + ':' + state.storage_port + '/storage_rpc/v1')
    return storageSeedURLs
  } catch (e) {
    console.error('lib::getStorageServersFromSS - exception', e, nodeURL)
  }
}

// attachment uses this
async function bufferAsk(url, fetchOptions = {}) {
  let useOptions = fetchOptions
  if (url.match(/^https\:/)) {
    useOptions = {
      ...fetchOptions,
      agent: snodeHttpsAgent
    }
  }
  const result = await fetch(url, useOptions)
  const binData = await result.buffer()
  return binData
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
    console.error('lib::jsonAsk - err', e, 'json', json, 'options', fetchOptions)
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

function getNowWithNetworkOffset() {
  // make sure to call exports here, as we stub the exported one for testing.
  return Date.now() - exports.getLatestTimestampOffset();
}

async function getRetrieveSignatureParams(edKey, params) {
  if (!edKey) {
    console.trace('no edKey')
    process.exit(1)
  }
  if (!edKey.ed25519KeyPair) {
    console.trace('no edKey privateKey?', edKey)
    process.exit(1)
  }
  // error check
  /*
  if (isEmpty(params?.pubKey) || ourPubkey.key !== params.pubKey || !ourEd25519Key) {
    return null;
  }
  */
  //console.log('getRetrieveSignatureParams', edKey, params)
  // edKey.ed25519KeyPair.privateKey is a Uint8Array(64)
  const edKeyPrivBytes = edKey.ed25519KeyPair.privateKey
  const edKeyPubHex = Buffer.from(edKey.ed25519KeyPair.publicKey).toString('hex')

  const hasNamespace = params.namespace && params.namespace !== 0
  const namespace = params.namespace || 0

  //const edKeyPrivBytes = fromHexToArray(ourEd25519Key?.privKey)
  //const edKeyPrivBytes = new Uint8Array(ByteBuffer.wrap(ourEd25519Key?.privKey, 'hex').toArrayBuffer())

  //const signatureTimestamp = getNowWithNetworkOffset()
  const signatureTimestamp = Date.now()

  /*
  const verificationData = hasNamespace
    ? StringUtils.encode(`retrieve${namespace}${signatureTimestamp}`, 'utf8')
    : StringUtils.encode(`retrieve${signatureTimestamp}`, 'utf8')
  */
  const verificationData = hasNamespace
    ? `retrieve${namespace}${signatureTimestamp}`
    : `retrieve${signatureTimestamp}`
  //console.log('verificationData', verificationData)
  //const message = new Uint8Array(verificationData)

  await _sodium.ready
  const sodium = _sodium

  //try {
    // Uint8
    //console.log('message', message)
    const signature = sodium.crypto_sign_detached(verificationData, edKeyPrivBytes)
    //console.log('signature', signature)
    const signatureBase64 = Buffer.from(signature).toString('base64')

    const namespaceObject = hasNamespace ? { namespace } : {}

    return {
      timestamp: signatureTimestamp,
      signature: signatureBase64,
      pubkey_ed25519: edKeyPubHex,
      ...namespaceObject,
    }
/*
  } catch (e) {
    console.warn('getSignatureParams failed with: ', e.message);
    return null;
  }
*/
}

async function signed_jsonrpc(url, method, params, options = {}) {
  if (!options.edKey) {
    console.trace('lib::jsonrpc - no edKey')
    process.exit(1)
  }
  if (!url) {
    console.trace('lib::jsonrpc - no url')
    return
  }
  //console.trace('lib::signed_jsonrpc - options', options)
  const signatureParams = (await getRetrieveSignatureParams(options.edKey, params)) || {};
  params.namespace = 0 // needs to be number
  const signedParams = {...signatureParams, ...params }
  signedParams.timestamp = signatureParams.timestamp // always use the ms ts
  // we're logging these out incase there's a problem
  //console.log('lib::signed_jsonrpc - signedParams', url, method, signedParams)
  // pubKey:string, lashHash:string || '', namespace:number || 0
  const body = {
    jsonrpc: '2.0',
    id: '0',
    method,
    params: signedParams,
  }
  const fetchOptions = {
    method: 'POST',
    body: JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json'
    },
    timeout: 4 * 1000,
    agent: options && options.snode ? snodeHttpsAgent : undefined,
  }
  // try?
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
    endpoint, // /room/some-room
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
    console.error('lib::lsrpc - ', endpoint, 'got empty result', data64)
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
    // /caps doesnt have a status_code
    if (result.status_code && result.status_code >= 300) {
      console.warn('lib::lsrpc - ', endpoint, 'Got HTTP', result.status_code, 'retry?')
      //return
    }
    return result
  } catch (e) {
    console.error('lib::lsrpc - ', endpoint, 'exception', e)
  }
  return false
}

// shouldn't be needed
async function lsrpcv4(baseUrl, querystring, destX25519hex, endpoint, method, body, headers) {
  //[N][blob][json]
  // N is (4 bytes, little endian)
  const url = baseUrl + '/oxen/v4/lsrpc'
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
    endpoint: endpoint, // must always have /
    //body,
    method,
    headers,
  }
  if (querystring) {
    rpcCall.endpoint += '?' + querystring
  }
  //console.log('lsrpcv4 rpcCall', rpcCall, 'destX25519hex', destX25519hex, 'url', url)

  const rpcStr = JSON.stringify(rpcCall)
  let bencoding = 'l' + rpcStr.length + ':' + rpcStr
  if (body) {
    bencoding += body.length + ':' + body
  }
  bencoding += 'e'

  const rpcPlaintext = textEncoder.encode(bencoding)
  // GCM should be fine
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
  const data64 = await bufferAsk(url, fetchOptions)
  if (!data64) {
    console.error('lib::lsrpcv4 - ', endpoint, 'got empty result', data64)
    return false
  }
  let json, respBody
  try {
    const cipherText = Buffer.from(data64, 'base64')
    //console.debug('cipherText', cipherText.byteLength)
    data = libloki.decryptGCM(symKey, cipherText)
    //console.debug('decrypted', data.toString(), data.byteLength)
    // can bytes be more than 16 bits? yes, it's : terminated
    const str = data.slice(1).toString()
    //console.debug('str', str)
    const byteLength = str.indexOf(':')
    const bytes = parseInt(data.toString().substr(1, byteLength))
    json = data.slice(4, 4 + bytes).toString()
    //console.debug('bytes', bytes, '[' + json + ']')
    const str2 = data.slice(4 + bytes).toString()
    const byteLength2 = str2.indexOf(':')
    //console.debug('str2', str2, 'byteLength2', byteLength2)
    const bytes2 = parseInt(str2.substr(0, byteLength2))
    respBody = data.slice(4 + bytes + byteLength2 + 1, 5 + bytes + byteLength2 + bytes2).toString()
    //console.debug('bytes2', bytes2, '[' + respBody + ']')
  } catch (e) {
    console.error('lib::lsrpcv4 - ', endpoint, 'exception', e, 'could not parse', data64)
    return false
  }
  try {
    const result = JSON.parse(json)
    if (!result) {
      console.error('empty json', json)
      return
    }
    // result: code, headers
    //console.log('result', result)
    if (result.code >= 300) {
      console.warn('lib::lsrpcv4 - ', endpoint, 'Got HTTP', result.code, 'retry?', respBody)
      //return
    }
    const isJson = result?.headers['content-type'] === 'application/json'
    let retVal = isJson ? JSON.parse(respBody) : respBody
    return retVal
  } catch (e) {
    console.error('lib::lsrpcv4 - ', endpoint, 'exception', e, 'data', json, 'respBody', respBody)
  }
  return false
}

// only getStorageServersFromSeed should set useSeed to true
// lns also uses this
async function getRandomSnode(useSeed, edKey) {
  const allNodes = Object.entries(swarmMap).reduce((acc, [pubkey, obj]) => {
    const snodesUrlList = obj.snodes.map(snode =>
      'https://' + snode.ip + ':' + snode.port + '/storage_rpc/v1'
    )
    // Set makes it unique
    return Array.from(new Set(acc.concat(snodesUrlList)))
  }, useSeed ? await getStorageServersFromSeed() : await getStorageServersFromSS(edKey))
  if (!allNodes.length) {
    console.log('lib::getRandomSnode - allNodes', allNodes)
  }
  return getRandomOne(allNodes)
}

// there's only one network ever...
const swarmMap = {}
const lastXMessages = []
// FIXME: we have the pubKey, we can just internally look up the URL (swarm)...
// maybe can do 3 queries here and show confirmations...
async function pubKeyAsk(url, method, pubKey, edKey, params = {}) {
  if (!edKey) {
    console.trace('lib::pubKeyAsk - no edKey')
    process.exit(1)
  }
  if (edKey.ttl) {
    console.trace('why ttl in edKey?')
    process.exit(1)
  }
  const res = await signed_jsonrpc(url, method, {...params, pubKey: pubKey }, { snode: true, edKey })
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
      console.warn('lib::pubKeyAsk - Swarm reorg for', pubKey, 'url', url, 'is no longer valid', res)
      // res: hf, snodes[snode: address, ip, port, port_https, port_omq, pubkey_*], swarm, t
      // retry with new URL
      return pubKeyAsk(await getSwarmsnodeUrl(pubKey, edKey), method, pubKey, edKey, params)
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
async function getSwarmsnodeUrl(pubkey, edKey) {
  if (!edKey) {
    console.trace('lib::getSwarmsnodeUrl - no edKey')
    process.exit(1)
  }
  if (!pubkey || pubkey.length < 66) {
    console.trace('lib::getSwarmsnodeUrl - invalid pubkey', pubkey && pubkey.length, pubkey)
    return
  }
  if (getSwarmsnodeUrlLock) {
    //console.warn('lib::getSwarmsnodeUrl - locked, waiting')
    return new Promise(resolve => {
      setTimeout(async () => {
        const url = await getSwarmsnodeUrl(pubkey, edKey)
        resolve(url)
      }, 1000)
    })
  }
  // cache snodes list
  if (!swarmMap[pubkey] || ((Date.now() - swarmMap[pubkey]) > 3600)) {
    // only lock if we need to check the network
    getSwarmsnodeUrlLock = true
    const nodeURL = await getRandomSnode(false, edKey)
    const snodesData = await pubKeyAsk(nodeURL, 'get_snodes_for_pubkey', pubkey, edKey)
    if (!snodesData) {
      console.error('lib::getSwarmnodeUrl - Could not get snodes from', nodeURL, 'pubkey', pubkey)
      // retry using a different node
      getSwarmsnodeUrlLock = false
      // recall it
      return getSwarmsnodeUrl(pubkey, edKey)
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
  lsrpcv4,
  getRandomSnode,
  pubKeyAsk,
  getSwarmsnodeUrl
}
