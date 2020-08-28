const crypto = require('crypto')
const lib = require('./lib.js')
// eslint-disable-next-line camelcase
const loki_crypto = require('./lib.loki_crypt.js')
const FormData = require('form-data')

const AVATAR_USER_ANNOTATION_TYPE = 'network.loki.messenger.avatar'

// generic ADN "POST files" function
// used by uploadEncryptedFile and other direct calls for attachments
async function uploadFile(baseUrl, token, type, filename, data, notes) {
  const buf = Buffer.from(data)
  //console.log('file type', typeof(data), 'length', data.length)
  //console.log('buffer type', typeof(buf), 'length', buf.byteLength)

  const formData = new FormData()
  formData.append('type', type)
  formData.append('kind', 'image')
  formData.append('content', buf, {
    filename: filename,
    contentType: 'image/jpeg'
  })
  // set annotations if needed
  if (notes) {
    formData.append('annotations', JSON.stringify(notes))
  }
  let fileRes
  try {
    fileRes = await lib.jsonAsk(baseUrl + 'files?access_token=' + token, {
      method: 'POST',
      body: formData,
      headers: formData.getHeaders()
    })
  } catch (e) {
    console.error('attachments::uploadFile - err', e)
  }
  return fileRes.data.url
}

// could set the username field too
// set your avatar
/*
const notes = [{
  type: 'moe.sapphire.tractorbeam.session.avatar',
  value: {
    sessionID: sessionID,
    profileKey: avatarNoteValue.profileKey,
    source: avatarNoteValue.url,
  }
}]
*/
async function uploadEncryptedAvatar(baseUrl, token, sessionID, imgData, notes) {
  // encrypt
  const profileKeyBuf = crypto.randomBytes(32) // Buffer (object)
  const finalBuf = loki_crypto.encryptGCM(profileKeyBuf, imgData)
  const type = 'moe.sapphire.tractorbeam.session.avatar'
  const filename = sessionID + '_avatar.jpg'
  // upload to OG server
  const fileUrl = await uploadFile(baseUrl, token, type, filename, finalBuf, notes)
  // now set in the user profile (PATCH /users/me)
  // result shouldn't matter
  await lib.jsonAsk(baseUrl + 'users/me?access_token=' + token, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      annotations: [{
        type: AVATAR_USER_ANNOTATION_TYPE,
        value: {
          url: fileUrl,
          profileKey: profileKeyBuf.toString('base64')
        }
      }]
    })
  })
  return {
    profileKeyBuf: profileKeyBuf,
    url: fileUrl
  }
}

// returns a buffer
async function downloadEncryptedAvatar(url, keyBuf) {
  if (!Buffer.isBuffer(keyBuf)) {
    console.trace('lib::downloadEncryptedAvatar - non buffer passed in as key')
    return
  }
  if (!url) {
    console.trace('lib::downloadEncryptedAvatar - falsish url passed in')
    return
  }

  const ivCiphertextAndTag = await lib.bufferAsk(url) // binary download
  // returns a buffer
  const file = loki_crypto.decryptGCM(keyBuf, ivCiphertextAndTag)
  return file
}

async function getAvatar(fSrvUrl, pubkeyHex) {
  const res = await lib.jsonAsk(fSrvUrl + 'users/@' + pubkeyHex + '?include_annotations=1')
  if (res.meta.code !== 200 || !res.data) {
    console.error('attachments::getAvatar - error', res)
    return
  }
  const avatarNote = res.data.annotations.find(node => node.type === AVATAR_USER_ANNOTATION_TYPE)
  if (!avatarNote) {
    console.warn('attachments::getAvatar - no', AVATAR_USER_ANNOTATION_TYPE, 'note, notes:', res.data.annotations)
    return
  }
  return {
    url: avatarNote.value.url,
    // costs nothing to include
    // and you can decode on your own...
    profileKey64: avatarNote.value.profileKey
  }
}

async function getToken(fSrvUrl, privKey, pubkeyHex) {
  const chalUrl = fSrvUrl + 'loki/v1/get_challenge?pubKey=' + pubkeyHex
  const data = await lib.jsonAsk(chalUrl)
  if (!data.cipherText64 || !data.serverPubKey64) {
    console.error('lib::getToken - data', typeof (data), data)
    return
  }
  // decode server public key
  const serverPubKeyBuff = Buffer.from(data.serverPubKey64, 'base64')
  // make sym key
  const symmetricKey = await loki_crypto.makeSymmetricKey(privKey, serverPubKeyBuff)
  // decrypt
  const tokenBuf = await loki_crypto.DHDecrypt64(symmetricKey, data.cipherText64)
  const token = tokenBuf.toString() // fix up type
  // set up submit to activate token
  const subUrl = fSrvUrl + 'loki/v1/submit_challenge'
  let activateRes
  try {
    activateRes = await lib.textAsk(subUrl, {
      method: 'POST',
      body: JSON.stringify({
        token: token,
        pubKey: pubkeyHex
      }),
      headers: {
        'Content-Type': 'application/json'
      }
    })
  } catch (e) {
    console.error('attachments::getToken - submit_challenge err', e)
    // retry counter?
    // retry chal x 3 and then apply for new toke
  }
  if (activateRes !== '') {
    console.error('Failed to get token for', fSrvUrl, pubkeyHex)
  }
  return token
}

async function uploadEncryptedAttachment(homeSrvUrl, data) {
  const keysBuf = crypto.randomBytes(64) // aes(32) and mac(32)
  const ivCiphertextAndMac = await loki_crypto.encryptCBC(keysBuf, data)
  // FIXME: these two actions can be done in parallel
  const url = await uploadFile(homeSrvUrl, 'loki',
    'org.getsession.attachment', 'images.jpeg', ivCiphertextAndMac)
  const digest = crypto.createHash('sha256').update(ivCiphertextAndMac).digest()
  return {
    key: keysBuf.toString('base64'),
    contentType: 'image/jpeg',
    url: url,
    fileName: 'images.jpeg',
    size: data.byteLength,
    digest: digest.toString('base64')
  }
}

async function downloadEncryptedAttachment(url, keys) {
  const ivCiphertextAndMac = await lib.bufferAsk(url) // binary download
  // CBC strips the trailing mac off
  const fileDataBuf = loki_crypto.decryptCBC(keys, ivCiphertextAndMac)
  return fileDataBuf
}

module.exports =  {
  //uploadFile,
  getAvatar,
  getToken,
  uploadEncryptedAvatar,
  downloadEncryptedAvatar,
  uploadEncryptedAttachment,
  downloadEncryptedAttachment
}
