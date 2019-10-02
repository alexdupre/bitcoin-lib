package com.alexdupre

import java.math.BigInteger

import com.alexdupre.bitcoincash.Crypto.PublicKey

/**
  * see https://en.bitcoin.it/wiki/Protocol_specification
  */
package object bitcoincash {
  val MaxScriptElementSize = 520
  val MaxPubkeysPerMultisig = 20

  val ONE_MEGABYTE = 1000000
  val MAX_TX_SIZE = ONE_MEGABYTE
  val MAX_COINBASE_SCRIPTSIG_SIZE = 100

  val MAX_TX_SIGOPS_COUNT = 20000

  /**
    * signature hash flags
    */
  val SIGHASH_ALL = 1
  val SIGHASH_NONE = 2
  val SIGHASH_SINGLE = 3
  val SIGHASH_FORKID = 0x40
  val SIGHASH_ANYONECANPAY = 0x80


  implicit object NumericSatoshi extends Numeric[Satoshi] {
    // @formatter:off
    override def compare(x: Satoshi, y: Satoshi): Int = x.compare(y)
    override def minus(x: Satoshi, y: Satoshi): Satoshi = x - y
    override def negate(x: Satoshi): Satoshi = -x
    override def plus(x: Satoshi, y: Satoshi): Satoshi = x + y
    override def times(x: Satoshi, y: Satoshi): Satoshi = x * y.toLong
    override def toDouble(x: Satoshi): Double = x.toLong
    override def toFloat(x: Satoshi): Float = x.toLong
    override def toInt(x: Satoshi): Int = x.toLong.toInt
    override def toLong(x: Satoshi): Long = x.toLong
    override def fromInt(x: Int): Satoshi = Satoshi(x)
    def parseString(str: String): Option[Satoshi] = ???
    // @formatter:on
  }

  implicit final class SatoshiLong(private val n: Long) extends AnyVal {
    def sat = Satoshi(n)
  }

  implicit final class MilliBtcDouble(private val n: Double) extends AnyVal {
    def millibtc = MilliBtc(n)
  }

  implicit final class BtcDouble(private val n: Double) extends AnyVal {
    def btc = Btc(n)
  }

  // @formatter:off
  implicit def satoshi2btc(input: Satoshi): Btc = input.toBtc
  implicit def btc2satoshi(input: Btc): Satoshi = input.toSatoshi
  implicit def satoshi2millibtc(input: Satoshi): MilliBtc = input.toMilliBtc
  implicit def millibtc2satoshi(input: MilliBtc): Satoshi = input.toSatoshi
  implicit def btc2millibtc(input: Btc): MilliBtc = input.toMilliBtc
  implicit def millibtc2btc(input: MilliBtc): Btc = input.toBtc
  // @formatter:on

  /**
    *
    * @param input compact size encoded integer as used to encode proof-of-work difficulty target
    * @return a (result, isNegative, overflow) tuple were result is the decoded integer
    */
  def decodeCompact(input: Long): (BigInteger, Boolean, Boolean) = {
    val nSize = (input >> 24).toInt
    val (nWord, result) = if (nSize <= 3) {
      val nWord1 = (input & 0x007fffffL) >> 8 * (3 - nSize)
      (nWord1, BigInteger.valueOf(nWord1))
    } else {
      val nWord1 = input & 0x007fffffL
      (nWord1, BigInteger.valueOf(nWord1).shiftLeft(8 * (nSize - 3)))
    }
    val isNegative = nWord != 0 && (input & 0x00800000) != 0
    val overflow = nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))
    (result, isNegative, overflow)
  }

  /**
    *
    * @param value input value
    * @return the compact encoding of the input value. this is used to encode proof-of-work target into the `bits`
    *         block header field
    */
  def encodeCompact(value: BigInteger): Long = {
    var size = value.toByteArray.length
    var compact = if (size <= 3) value.longValue << 8 * (3 - size) else value.shiftRight(8 * (size - 3)).longValue
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if ((compact & 0x00800000L) != 0) {
      compact >>= 8
      size += 1
    }
    compact |= size << 24
    compact |= (if (value.signum() == -1) 0x00800000 else 0)
    compact
  }

  def isAnyoneCanPay(sighashType: Int): Boolean = (sighashType & SIGHASH_ANYONECANPAY) != 0

  def isForkId(sighashType: Int): Boolean = (sighashType & SIGHASH_FORKID) != 0

  def isHashSingle(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_SINGLE

  def isHashNone(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_NONE

  def computeLegacyP2PkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val hash = pub.hash160
    chainHash match {
      case Block.RegtestGenesisBlock.hash | Block.TestnetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, hash)
      case Block.LivenetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.PubkeyAddress, hash)
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
  }

  def computeP2PkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val hash = pub.hash160
    val hrp = chainHash match {
      case Block.LivenetGenesisBlock.hash => "bitcoincash"
      case Block.TestnetGenesisBlock.hash => "bchtest"
      case Block.RegtestGenesisBlock.hash => "bchreg"
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
    CashAddr.encodeAddress(hrp, CashAddr.Type.PubKey, hash)
  }
}
