var bbs58checkBlake256 = require('./bs58checkBlake256')
var Buffer = require('safe-buffer').Buffer

const STEcdsaSecp256k1 = 0

function decodeRaw (buffer, version) {
  // check version only if defined
  if (version !== undefined && buffer[0] !== version[0] && buffer[1] !== version[1]) throw new Error('Invalid network version')

  // invalid length
  if (buffer.length !== 35) throw new Error('Invalid WIF length')

  return {
    version: (buffer[0] << 8) + buffer[1], // Int expected for version???
    privateKey: buffer.slice(3, 35)
  }
}

function encodeRaw (version, privateKey) {
  if (privateKey.length !== 32) throw new TypeError('Invalid privateKey length')

  var result = Buffer.alloc(35)
  result.writeUInt16BE(version, 0)
  // Assume STEcdsaSecp256k1.
  result.writeUInt8(STEcdsaSecp256k1, 2)
  privateKey.copy(result, 3)

  return result
}

function decode (string, version) {
  return decodeRaw(bbs58checkBlake256.decodeBlake256SingleHash(string), version)
}

function encode (version, privateKey, _) {
  if (typeof version === 'number') return bbs58checkBlake256.encodeBlake256SingleHash(encodeRaw(version, privateKey))

  return bbs58checkBlake256.encodeBlake256SingleHash(
    encodeRaw(
      version.version,
      version.privateKey
    )
  )
}

module.exports = {
  decode: decode,
  decodeRaw: decodeRaw,
  encode: encode,
  encodeRaw: encodeRaw
}
