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
            console.error('open_groups::getMessages - Wrong response received', messageListResult)
        }
    } catch (e) {
        console.error('open_groups::getMessages - Getting messages error', e)
    }
    return null
}

async function send(openGroup, token, channelId, privKey, text) {
    try {
        const sigVer = 1
        const mockAdnMessage = { text }
        const timestamp = new Date().getTime()
        const annotations = [
            {
                type: 'network.loki.messenger.publicChat',
                value: {
                    timestamp,
                    // sig: '6b07d9f8c7bb4c5e28a43b4dd2aa4889405361e709258a0420ba55c8aa6784c1b3059787a7adeec85bbce66832fa61efa7398a55ee9f45aa396a9c05f9edb105',
                    //sigver: sigVer
                }

            }
        ]

        const sig = await loki_crypto.getSigData(
            sigVer,
            privKey,
            annotations[0].value,
            mockAdnMessage
        )

        annotations[0].value.sig = sig
        annotations[0].value.sigver = sigVer

        const payload = {
            text,
            annotations
        }
        const messageSendResult = await lib.jsonAsk(`https://${openGroup}/channels/${channelId}/messages`,
            {
                method: 'POST',
                body: JSON.stringify(payload),
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-type': 'application/json',
                    Accept: 'application/json',
                    'Accept-Charset': 'utf-8'
                }
            })
        console.log(messageSendResult)
        if (messageSendResult.meta && messageSendResult.meta.code && messageSendResult.meta.code === 200 && messageSendResult.data) {
            return messageSendResult.data
        } else {
            console.error('open_groups::send - Wrong response received', messageSendResult)
        }
    } catch (e) {
        console.error('open_groups::send - Sending messages error', e)
    }
    return null
}

async function messageDelete(openGroup, token, channelId, messageIds = []) {
    try {
        const messageDeleteResult = await lib.jsonAsk(`https://${openGroup}/loki/v1/moderation/messages?ids=${encodeURIComponent(messageIds)}`,
            {
                method: 'DELETE',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-type': 'application/json',
                    Accept: 'application/json',
                    'Accept-Charset': 'utf-8'
                }
            })
        if (messageDeleteResult.meta && messageDeleteResult.meta.code && messageDeleteResult.meta.code === 200 && messageDeleteResult.data) {
            return messageDeleteResult.data
        } else {
            console.error('open_groups::delete - Wrong response received', messageDeleteResult)
        }
    } catch (e) {
        console.error('open_groups::delete - Getting messages error', e)
    }
    return null
}

module.exports = {
    getToken,
    subscribe,
    getMessages,
    send,
    messageDelete
}
