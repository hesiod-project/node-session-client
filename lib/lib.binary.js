// move to a binary utility lib
const concatUInt8Array = (...args) => {
  const totalLength = args.reduce((acc, current) => acc + current.length, 0)

  const concatted = new Uint8Array(totalLength)
  let currentIndex = 0
  args.forEach(arr => {
    concatted.set(arr, currentIndex)
    currentIndex += arr.length
  })

  return concatted
}

/**
 * Take a string value with the given encoding and converts it to an `ArrayBuffer`.
 * @param value The string value.
 * @param encoding The encoding of the string value.
 */
function encode(value, encoding) {
  //return ByteBuffer.wrap(value, encoding).toArrayBuffer();
  const buf = Buffer.from(value, encoding)
  const ab = new ArrayBuffer(buf.length)
  const view = new Uint8Array(ab)
  for (let i = 0; i < buf.length; ++i) {
    view[i] = buf[i]
  }
  return ab
}

/**
 * Take a buffer and convert it to a string with the given encoding.
 * @param buffer The buffer.
 * @param stringEncoding The encoding of the converted string value.
 */
function decode(buffer, stringEncoding) {
  const buf = Buffer.from(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  return buf.toString(stringEncoding)
  // [] or Uint8Array
  //console.log('typeof', typeof(buffer), buffer)
  //return ByteBuffer.wrap(buffer).toString(stringEncoding);
}

const fromUInt8ArrayToBase64 = d => decode(d, 'base64')

function fromBase64ToUint8Array(base64Str) {
  const buf = Buffer.from(base64Str, 'base64')
  return new Uint8Array(buf.buffer)
}

const stringToArrayBuffer = str => {
  if (typeof str !== 'string') {
    throw new TypeError("'string' must be a string")
  }

  return encode(str, 'binary')
}

const stringToUint8Array = str => {
  if (!str) {
    return new Uint8Array()
  }

  return new Uint8Array(stringToArrayBuffer(str))
}

// FIXME:
function hexStringToUint8Array(hexString) {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hexString')
  }
  const arrayBuffer = new Uint8Array(hexString.length / 2)

  for (let i = 0; i < hexString.length; i += 2) {
    const byteValue = parseInt(hexString.substr(i, 2), 16)
    if (isNaN(byteValue)) {
      throw new Error('Invalid hexString')
    }
    arrayBuffer[i / 2] = byteValue
  }

  return arrayBuffer
}

module.exports = {
  concatUInt8Array,
  encode,
  decode,
  fromUInt8ArrayToBase64,
  fromBase64ToUint8Array,
  stringToArrayBuffer, // not really used externally
  stringToUint8Array, // not really used externally
  hexStringToUint8Array
}
