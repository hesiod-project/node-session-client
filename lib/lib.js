const https = require('https')

// FIXME: remove fetch
const fetch = require('node-fetch')
//const http = require('http')

// FIXME: get official seed node list
const seedUrl = 'https://206.81.100.174:20003/storage_rpc/v1'

const snodeHttpsAgent = new https.Agent({
  rejectUnauthorized: false
})

async function bufferAsk(url, fetchOptions = {}) {
  const options = {
    ...fetchOptions,
    agent: snodeHttpsAgent
  }
  const result = await fetch(url, options)
  const text = await result.buffer()
  return text
}

async function textAsk(url, fetchOptions = {}) {
  const options = {
    ...fetchOptions,
    agent: snodeHttpsAgent
  }
  let result = false
  try {
    result = await fetch(url, options)
    const text = await result.text()
    return text
  } catch (e) {
    console.error('lib::textAsk - err', e)
    // e.code === ECONNRESET
  }
}

async function jsonAsk(url, fetchOptions = {}) {
  const json = await textAsk(url, fetchOptions)
  //console.log('json', json)
  try {
    const obj = JSON.parse(json)
    return obj
  } catch (e) {
    console.error('lib::jsonAsk - err', e, 'json', json)
    return json
  }
}

async function jsonrpc(url, method, params) {
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
    }
  }
  return await jsonAsk(url, fetchOptions)
}

function getRandomOne(items) {
  return items[parseInt(Math.random() * items.length)]
}

function getRandomSnode() {
  const allNodes = Object.entries(swarmMap).reduce((acc, [pubkey, obj]) => {
    const snodesUrlList = obj.snodes.map(snode =>
      'https://' + snode.ip + ':' + snode.port + '/storage_rpc/v1'
    )
    // Set makes it unique
    return Array.from(new Set(acc.concat(snodesUrlList)))
  }, [seedUrl])
  //console.log('lib::getSwarmsnodeUrl - allNodes', allNodes)
  return getRandomOne(allNodes)
}

// there's only one network ever...
const swarmMap = {}
async function getSwarmsnodeUrl(pubkey) {
  if (!pubkey || pubkey.length < 66) {
    console.trace('lib::getSwarmsnodeUrl - invalid pubkey', pubkey && pubkey.length, pubkey)
    return
  }
  // cache snodes list
  if (!swarmMap[pubkey] || Date.now() - swarmMap[pubkey] > 3600) {
    const snodeData = await jsonrpc(
      getRandomSnode(), 'get_snodes_for_pubkey', { pubKey: pubkey }
    )
    if (!snodeData || !snodeData.snodes) {
      console.error('Could not get snodes from seedUrl')
      return
    }
    // we could map snodes into URLs
    swarmMap[pubkey] = {
      updated_at: Date.now(),
      snodes: snodeData.snodes
    }
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
  return newUrl
}

module.exports = {
  bufferAsk,
  textAsk,
  jsonAsk,
  jsonrpc,
  getRandomSnode,
  getSwarmsnodeUrl
}
