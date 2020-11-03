var baddress = require('./address')
var bcrypto = require('./crypto')
var bwifBlake256 = require('./wifBlake256')
var coins = require('./coins')
var ecdsa = require('./ecdsa')
var randomBytes = require('randombytes')
var typeforce = require('typeforce')
var types = require('./types')
var wif = require('wif')

var NETWORKS = require('./networks')
var BigInteger = require('bigi')

var ecurve = require('ecurve')
var secp256k1 = ecdsa.__curve

var fastcurve = require('./fastcurve')

function ECPair (d, Q, options) {
  if (options) {
    typeforce({
      compressed: types.maybe(types.Boolean),
      network: types.maybe(types.Network)
    }, options)
  }

  options = options || {}

  if (d) {
    if (d.signum() <= 0) throw new Error('Private key must be greater than 0')
    if (d.compareTo(secp256k1.n) >= 0) throw new Error('Private key must be less than the curve order')
    if (Q) throw new TypeError('Unexpected publicKey parameter')

    this.d = d
  } else {
    typeforce(types.ECPoint, Q)

    this.__Q = Q
  }

  this.compressed = options.compressed === undefined ? true : options.compressed
  this.network = options.network || NETWORKS.bitcoin
}

Object.defineProperty(ECPair.prototype, 'Q', {
  get: function () {
    if (!this.__Q && this.d) {
      this.__Q = secp256k1.G.multiply(this.d)
    }

    return this.__Q
  }
})

ECPair.fromPublicKeyBuffer = function (buffer, network) {
  var Q = ecurve.Point.decodeFrom(secp256k1, buffer)

  return new ECPair(null, Q, {
    compressed: Q.compressed,
    network: network
  })
}

ECPair.fromWIF = function (string, network) {
  var decode = network && coins.isDecred(network) ? bwifBlake256.decode : wif.decode
  var decoded = decode(string)
  var version = decoded.version

  // list of networks?
  if (types.Array(network)) {
    network = network.filter(function (x) {
      return version === x.wif
    }).pop()  // We should not use pop since it depends on the order of the networks for the same wif

    if (!network) throw new Error('Unknown network version')

  // otherwise, assume a network object (or default to bitcoin)
  } else {
    network = network || NETWORKS.bitcoin

    if (version !== network.wif) throw new Error('Invalid network version')
  }

  var d = BigInteger.fromBuffer(decoded.privateKey)

  return new ECPair(d, null, {
    compressed: decoded.compressed,
    network: network
  })
}

ECPair.makeRandom = function (options) {
  options = options || {}

  var rng = options.rng || randomBytes

  var d
  do {
    var buffer = rng(32)
    typeforce(types.Buffer256bit, buffer)

    d = BigInteger.fromBuffer(buffer)
  } while (d.signum() <= 0 || d.compareTo(secp256k1.n) >= 0)

  return new ECPair(d, null, options)
}

ECPair.prototype.getAddress = function () {
  const net = this.getNetwork()
  var hash160 = coins.isDecred(net) ? bcrypto.hash160blake256 : bcrypto.hash160
  return baddress.toBase58Check(hash160(this.getPublicKeyBuffer()), net.pubKeyHash, net)
}

ECPair.prototype.getNetwork = function () {
  return this.network
}

ECPair.prototype.getPublicKeyBuffer = function () {
  return this.Q.getEncoded(this.compressed)
}

/**
 * Get the private key as a 32 bytes buffer. If it is smaller than 32 bytes, pad it with zeros
 * @return Buffer
 */
ECPair.prototype.getPrivateKeyBuffer = function () {
  if (!this.d) throw new Error('Missing private key')

  var bigIntBuffer = this.d.toBuffer()
  if (bigIntBuffer.length > 32) throw new Error('Private key size exceeds 32 bytes')

  if (bigIntBuffer.length === 32) {
    return bigIntBuffer
  }
  var newBuffer = Buffer.alloc(32)
  bigIntBuffer.copy(newBuffer, newBuffer.length - bigIntBuffer.length, 0, bigIntBuffer.length)
  return newBuffer
}

ECPair.prototype.sign = function (hash) {
  if (!this.d) throw new Error('Missing private key')

  var sig = fastcurve.sign(hash, this.d)
  if (sig !== undefined) return sig
  return ecdsa.sign(hash, this.d)
}

ECPair.prototype.toWIF = function () {
  if (!this.d) throw new Error('Missing private key')

  const encode = this.network && coins.isDecred(this.network) ? bwifBlake256.encode : wif.encode
  return encode(this.network.wif, this.d.toBuffer(32), this.compressed)
}

ECPair.prototype.verify = function (hash, signature) {
  var fastsig = fastcurve.verify(hash, signature, this.getPublicKeyBuffer())
  if (fastsig !== undefined) return fastsig
  return ecdsa.verify(hash, signature, this.Q)
}

module.exports = ECPair
