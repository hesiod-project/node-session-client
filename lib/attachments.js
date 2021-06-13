const urlparser = require('url')
const crypto    = require('crypto')
const lib = require('./lib.js')
// eslint-disable-next-line camelcase
const loki_crypto = require('./lib.loki_crypto.js')

// upload to file server v2 or open group server v2
async function uploadFile(baseUrl, serverPubKey, data, token = false) {
  const buf = Buffer.from(data)
  const postBody = JSON.stringify({
    file: buf.toString('base64'),
  })
  let headers = {}

  // only needed for rooms?
  if (token) {
    headers = {
      Authorization: 'Bearer ' + token,
    }
  }
  let fileRes
  try {
    fileRes = await lib.lsrpc(baseUrl, '', serverPubKey, 'files', 'POST', postBody, headers)
  } catch (e) {
    console.error('attachments::uploadFile - err', e)
  }
  if (!fileRes || fileRes.status_code !== 200) {
    console.log('attachments::uploadFile - unknown result', fileRes)
    return false
  }
  return fileRes.result
}

// upload avatar to file server v2 or open group server v2
async function uploadEncryptedAvatar(baseUrl, serverPubkey, imgData) {
  // encryptProfile is still GCM
  //https://github.com/oxen-io/session-desktop/blob/clearnet/libtextsecure/crypto.js#L91
  const profileKeyBuf = crypto.randomBytes(32) // Buffer (object)
  const finalBuf = loki_crypto.encryptGCM(profileKeyBuf, imgData)

  // upload to server
  const fileId = await uploadFile(baseUrl, serverPubkey, finalBuf)

  // now we communicate it
  return {
    profileKeyBuf: profileKeyBuf,
    fileId: fileId,
    url: baseUrl + '/files/' + fileId + '?public_key=' + serverPubkey,
  }
}

// download avatar to file server v2 or open group server v2
// returns a buffer
async function downloadEncryptedAvatar(url, keyBuf, options = {}) {
  if (!Buffer.isBuffer(keyBuf)) {
    console.trace('lib::downloadEncryptedAvatar - non buffer passed in as key')
    return
  }
  if (!url) {
    console.trace('lib::downloadEncryptedAvatar - falsish url passed in')
    return
  }

  // parse URL into parts
  const urlDetails = new urlparser.URL(url)
  // no trailing slash
  const baseUrl = urlDetails.protocol + '//' + urlDetails.host
  const fileId = urlDetails.pathname.replace('/files/', '')
  const serverPubkeyHex = urlDetails.searchParams.get('public_key')
  const serverPubKey = serverPubkeyHex || options.pubkey
  const endpoint = 'files/' + fileId

  const obj = await lib.lsrpc(baseUrl, '', serverPubKey, endpoint, 'GET', '', {})
  if (!obj || obj.status_code !== 200) {
    console.log('downloadEncryptedAvatar got non-200 result code', obj)
    return false
  }
  const ivCiphertextAndTag = Buffer.from(obj.result, 'base64')

  const fileBuf = loki_crypto.decryptGCM(keyBuf, ivCiphertextAndTag)
  return fileBuf
}

// Attachments status: UNTESTED

// FIXME: mime type, filename
async function uploadEncryptedAttachment(homeSrvUrl, serverPubkey, data) {
  const keysBuf = crypto.randomBytes(64) // aes(32) and mac(32)
  const ivCiphertextAndMac = await loki_crypto.encryptCBC(keysBuf, data)

  // FIXME: these two actions can be done in parallel
  const fileId = await uploadFile(homeSrvUrl, serverPubkey, ivCiphertextAndMac)
  const digest = crypto.createHash('sha256').update(ivCiphertextAndMac).digest()
  // end
  return {
    key: keysBuf.toString('base64'),
    contentType: 'image/jpeg',
    url: homeSrvUrl + '/files/' + fileId + '?public_key=' + serverPubkey,
    fileName: 'images.jpeg',
    size: data.byteLength,
    digest: digest.toString('base64')
  }
}

// different than avatar because uses aes-CBC
async function downloadEncryptedAttachment(url, keys, options) {
  // parse URL into parts
  const urlDetails = new urlparser.URL(url)
  // no trailing slash
  const baseUrl = urlDetails.protocol + '//' + urlDetails.host
  const fileId = urlDetails.pathname.replace('/files/', '')
  const serverPubkeyHex = urlDetails.searchParams.get('public_key')
  const serverPubKey = serverPubkeyHex || options.pubkey
  const endpoint = 'files/' + fileId

  // FIXME: may need a token for open groups

  const obj = await lib.lsrpc(baseUrl, '', serverPubKey, endpoint, 'GET', '', {})
  if (!obj || obj.status_code !== 200) {
    console.log('downloadEncryptedAvatar got non-200 result code', obj)
    return false
  }
  const ivCiphertextAndMac = Buffer.from(obj.result, 'base64')

  // CBC strips the trailing mac off
  const fileBuf = loki_crypto.decryptCBC(keys, ivCiphertextAndMac)
  return fileBuf
}

module.exports =  {
  // no longer possible
  //getAvatar,
  uploadEncryptedAvatar,
  downloadEncryptedAvatar,
  uploadEncryptedAttachment,
  downloadEncryptedAttachment
}
