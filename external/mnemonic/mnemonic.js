/* eslint camelcase: 0 */
class MnemonicError extends Error {}

let crc32
/* eslint-disable */
if (typeof (module) === 'undefined') {
  // browser
  function loadFile(file, cb) {
    fetch('mnemonic/' + file).then(async resp => {
      const words = await resp.json()
      cb(words)
    })
  }
} else {
  // node
  function loadFile(file, cb) {
    cb(require('./' + file))
  }
}
/* eslint-enable */

/*
 mnemonic.js : Converts between 4-byte aligned strings and a human-readable
 sequence of words. Uses 1626 common words taken from wikipedia article:
 http://en.wiktionary.org/wiki/Wiktionary:Frequency_lists/Contemporary_poetry
 Originally written in python special for Electrum (lightweight Bitcoin client).
 This version has been reimplemented in javascript and placed in public domain.
 */

const mn_default_wordset = 'english'

function mn_get_checksum_index(words, prefix_len) {
  let trimmed_words = ''
  for (let i = 0; i < words.length; i++) {
    trimmed_words += words[i].slice(0, prefix_len)
  }
  let signedChecksum
  if (typeof (module) === 'undefined') {
    // browser
    // eslint-disable-next-line no-undef
    signedChecksum = CRC32.str(trimmed_words)
  } else {
    // node
    signedChecksum = crc32.unsigned(trimmed_words)
  }
  const unsignedChecksum = (new Uint32Array([signedChecksum]))[0]
  const index = unsignedChecksum % words.length
  return index
}

let iAmReady
const ready = new Promise(resolve => {
  iAmReady = resolve
})

// hex, language => mnemonic
async function mn_encode(str, wordset_name) {
  'use strict'
  await ready
  wordset_name = wordset_name || mn_default_wordset
  const wordset = mn_words[wordset_name]
  let out = []
  const n = wordset.words.length
  for (let j = 0; j < str.length; j += 8) {
    str =
      str.slice(0, j) +
      mn_swap_endian_4byte(str.slice(j, j + 8)) +
      str.slice(j + 8)
  }
  for (let i = 0; i < str.length; i += 8) {
    const x = parseInt(str.substr(i, 8), 16)
    const w1 = x % n
    const w2 = (Math.floor(x / n) + w1) % n
    const w3 = (Math.floor(Math.floor(x / n) / n) + w2) % n
    out = out.concat([wordset.words[w1], wordset.words[w2], wordset.words[w3]])
  }
  if (wordset.prefix_len > 0) {
    out.push(out[mn_get_checksum_index(out, wordset.prefix_len)])
  }
  return out.join(' ')
}

function mn_swap_endian_4byte(str) {
  'use strict'
  if (str.length !== 8) { throw new MnemonicError('Invalid input length: ' + str.length) }
  return str.slice(6, 8) + str.slice(4, 6) + str.slice(2, 4) + str.slice(0, 2)
}

function mn_decode(str, wordset_name) {
  'use strict'
  wordset_name = wordset_name || mn_default_wordset
  const wordset = mn_words[wordset_name]

  let out = ''
  const n = wordset.words.length
  const wlist = str.split(' ')
  let checksum_word = ''
  if (wlist.length < 12) { throw new MnemonicError("You've entered too few words, please try again") }
  if (
    (wordset.prefix_len === 0 && wlist.length % 3 !== 0) ||
    (wordset.prefix_len > 0 && wlist.length % 3 === 2)
  ) { throw new MnemonicError("You've entered too few words, please try again") }
  if (wordset.prefix_len > 0 && wlist.length % 3 === 0) {
    throw new MnemonicError(
      'You seem to be missing the last word in your private key, please try again'
    )
  }
  if (wordset.prefix_len > 0) {
    // Pop checksum from mnemonic
    checksum_word = wlist.pop()
  }
  // Decode mnemonic
  for (let i = 0; i < wlist.length; i += 3) {
    let w1, w2, w3
    if (wordset.prefix_len === 0) {
      w1 = wordset.words.indexOf(wlist[i])
      w2 = wordset.words.indexOf(wlist[i + 1])
      w3 = wordset.words.indexOf(wlist[i + 2])
    } else {
      w1 = wordset.trunc_words.indexOf(wlist[i].slice(0, wordset.prefix_len))
      w2 = wordset.trunc_words.indexOf(
        wlist[i + 1].slice(0, wordset.prefix_len)
      )
      w3 = wordset.trunc_words.indexOf(
        wlist[i + 2].slice(0, wordset.prefix_len)
      )
    }
    if (w1 === -1 || w2 === -1 || w3 === -1) {
      throw new MnemonicError('invalid word in mnemonic')
    }
    const x = w1 + n * ((n - w1 + w2) % n) + n * n * ((n - w2 + w3) % n)
    if (x % n !== w1) {
      throw new MnemonicError(
        'Something went wrong when decoding your private key, please try again'
      )
    }
    out += mn_swap_endian_4byte(('0000000' + x.toString(16)).slice(-8))
  }
  // Verify checksum
  if (wordset.prefix_len > 0) {
    const index = mn_get_checksum_index(wlist, wordset.prefix_len)
    const expected_checksum_word = wlist[index]
    if (
      expected_checksum_word.slice(0, wordset.prefix_len) !==
      checksum_word.slice(0, wordset.prefix_len)
    ) {
      throw new MnemonicError(
        'Your private key could not be verified, please verify the checksum word'
      )
    }
  }
  return out
}

// Note: the value is the prefix_len
const languages = {
/*
  chinese_simplified: 1,
  dutch: 4,
  electrum: 0,
*/
  english: 3
/*
  esperanto: 4,
  french: 4,
  german: 4,
  italian: 4,
  japanese: 3,
  lojban: 4,
  portuguese: 4,
  russian: 4,
  spanish: 4,
*/
}

const mn_words = {}
for (const [language, prefix_len] of Object.entries(languages)) {
  // eslint-disable-next-line no-undef
  loadFile('english.json', function(words) {
    mn_words[language] = {
      prefix_len,
      words
    }

    for (const i in mn_words) {
      if (Object.prototype.hasOwnProperty.call(mn_words, i)) {
        if (mn_words[i].prefix_len === 0) {
          continue
        }
        mn_words[i].trunc_words = []
        for (let j = 0; j < mn_words[i].words.length; ++j) {
          mn_words[i].trunc_words.push(
            mn_words[i].words[j].slice(0, mn_words[i].prefix_len)
          )
        }
      }
    }

    iAmReady()
  })
}

// node and browser compatibility
; // this semicolon is required
(function(ref) {
  if (ref.constructor.name === 'Module') {
    // node
    crc32 = require('buffer-crc32')
    //global.Headers = fetch.Headers;
    module.exports = {
      mn_encode,
      mn_decode
    }
  } else {
    // browser
    // should be already set
    //window['crc32'] =
  }
})(typeof (module) === 'undefined' ? this : module)
