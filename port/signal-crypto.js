const { Crypto } = require('@peculiar/webcrypto')
const webcrypto = new Crypto()

async function hmacSha256(key, plaintext) {
  const algorithm = {
    name: 'HMAC',
    hash: 'SHA-256'
  }
  const extractable = false

  /*
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    key,
    algorithm,
    extractable,
    ['sign']
  );

  return window.crypto.subtle.sign(algorithm, cryptoKey, plaintext);
  */
  const cryptoKey = await webcrypto.subtle.importKey(
    'raw',
    key,
    algorithm,
    extractable,
    ['sign']
  )

  return webcrypto.subtle.sign(algorithm, cryptoKey, plaintext)
}

async function decryptAesCtr(key, ciphertext, counter) {
  const extractable = false
  const algorithm = {
    name: 'AES-CTR',
    counter: new Uint8Array(counter),
    length: 128
  }
  const cryptoKey = await webcrypto.subtle.importKey(
    'raw',
    key,
    algorithm,
    extractable,
    ['decrypt']
  )
  const plaintext = await webcrypto.subtle.decrypt(
    algorithm,
    cryptoKey,
    ciphertext
  )
  return plaintext
}

function HKDF(input, salt, info) {
  // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
  // TODO: We dont always need the third chunk, we might skip it
  const signFunc = function(key, data) {
    return webcrypto.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']).then(function(key) {
      return webcrypto.subtle.sign({ name: 'HMAC', hash: 'SHA-256' }, key, data)
    })
  }
  return signFunc(salt, input).then(function(PRK) {
    const infoBuffer = new ArrayBuffer(info.byteLength + 1 + 32)
    const infoArray = new Uint8Array(infoBuffer)
    infoArray.set(new Uint8Array(info), 32)
    infoArray[infoArray.length - 1] = 1
    return signFunc(PRK, infoBuffer.slice(32)).then(function(T1) {
      infoArray.set(new Uint8Array(T1))
      infoArray[infoArray.length - 1] = 2
      return signFunc(PRK, infoBuffer).then(function(T2) {
        infoArray.set(new Uint8Array(T2))
        infoArray[infoArray.length - 1] = 3
        return signFunc(PRK, infoBuffer).then(function(T3) {
          return [T1, T2, T3]
        })
      })
    })
  })
}

module.exports = {
  hmacSha256,
  decryptAesCtr,
  HKDF
}
