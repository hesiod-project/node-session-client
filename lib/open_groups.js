const lib = require('./lib.js')
// eslint-disable-next-line camelcase
const loki_crypto = require('./lib.loki_crypto.js')

async function getToken(openGroup, privKey, pubkeyHex) {
    const openGroupUrl = `https://${openGroup}`
    const chalUrl = `${openGroupUrl}/loki/v1/get_challenge?pubKey=${pubkeyHex}`
    const data = await lib.jsonAsk(chalUrl)
    if (!data.cipherText64 || !data.serverPubKey64) {
        console.error('open_groups::getToken - data', typeof (data), data)
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
    const subUrl = `${openGroupUrl}/loki/v1/submit_challenge`
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
        console.error('open_groups::getToken - submit_challenge err', e)
    }
    if (activateRes !== '') {
        console.error('Failed to get token for', openGroupUrl, pubkeyHex)
    }
    return token
}

async function subscribe(openGroup, token, channelId) {
    console.log('Subscribing to Open Group', openGroup)
    try {
        const subscriptionResult = await lib.jsonAsk(`https://${openGroup}/channels/${channelId}/subscribe`,
            {
                method: 'post',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-type': 'application/json',
                    Accept: 'application/json',
                    'Accept-Charset': 'utf-8'
                }
            })
        if (subscriptionResult.meta && subscriptionResult.meta.code && subscriptionResult.meta.code === 200) {
            return subscriptionResult
        } else {
            console.error('open_groups::subscribe - Wrong response received', subscriptionResult)
        }
    } catch (e) {
        console.error('open_groups::subscribe - Subscribe error', e)
    }
    return null
}

async function getMessages(openGroup, token, channelId, sinceId) {
    try {
        const messageListResult = await lib.jsonAsk(`https://${openGroup}/channels/${channelId}/messages?since_id=${sinceId}`,
            {
                method: 'get',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-type': 'application/json',
                    Accept: 'application/json',
                    'Accept-Charset': 'utf-8'
                }
            })
        if (messageListResult.meta && messageListResult.meta.code && messageListResult.meta.code === 200 && messageListResult.data) {
            return messageListResult.data
        } else {
            console.error('open_groups::getMessages - Wrong response received', subscriptionResult)
        }
    } catch (e) {
        console.error('open_groups::getMessages - Getting messages error', e)
    }
    return null
}

module.exports = {
    getToken,
    subscribe,
    getMessages
}
