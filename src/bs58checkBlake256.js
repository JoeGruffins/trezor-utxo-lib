var Buffer = require('safe-buffer').Buffer
var bblake256 = require('./crypto').blake256
var bs58 = require('bs58')

function decodeBlake256Address (address) {
  var buffer = bs58.decode(address)
  if (buffer.length !== 26) throw new Error(address + ' invalid address length')
  var payload
  try {
    payload = decode(buffer, true)
  } catch (e) {
    throw new Error(address + ' ' + e.message)
  }
  return payload
}

function decodeBlake256 (key) {
  var buffer = bs58.decode(key)
  return decode(buffer, true)
}

function decode (buffer, double) {
  const want = buffer.slice(-4)
  const payload = buffer.slice(0, -4)
  var got = bblake256(payload)
  if (double) {
    got = bblake256(got)
  }
  got = got.slice(0, 4)

  if (want[0] ^ got[0] |
      want[1] ^ got[1] |
      want[2] ^ got[2] |
      want[3] ^ got[3]) throw new Error('invalid checksum')

  return payload
}

function decodeBlake256SingleHash (key) {
  var buffer = bs58.decode(key)
  return decode(buffer)
}

function encodeBlake256 (payload) {
  var checksum = bblake256(bblake256(payload)).slice(0, 4)
  return bs58.encode(Buffer.concat([payload, checksum]))
}

function encodeBlake256SingleHash (payload) {
  var checksum = bblake256(payload).slice(0, 4)
  return bs58.encode(Buffer.concat([payload, checksum]))
}

module.exports = {
  encodeBlake256: encodeBlake256,
  encodeBlake256SingleHash: encodeBlake256SingleHash,
  decodeBlake256Address: decodeBlake256Address,
  decodeBlake256: decodeBlake256,
  decodeBlake256SingleHash: decodeBlake256SingleHash
}
