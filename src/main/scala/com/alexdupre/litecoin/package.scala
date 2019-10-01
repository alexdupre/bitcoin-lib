package com.alexdupre

import java.math.BigInteger

import com.alexdupre.litecoin.Crypto.PublicKey

/**
  * see https://en.bitcoin.it/wiki/Protocol_specification
  */
package object litecoin {
  val MaxScriptElementSize = 520

  val MAX_BLOCK_WEIGHT = 4000000
  val WITNESS_SCALE_FACTOR = 4

  /**
    * signature hash flags
    */
  val SIGHASH_ALL = 1
  val SIGHASH_NONE = 2
  val SIGHASH_SINGLE = 3
  val SIGHASH_ANYONECANPAY = 0x80

  object SigVersion {
    val SIGVERSION_BASE = 0
    val SIGVERSION_WITNESS_V0 = 1
  }

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

  implicit final class MilliLtcDouble(private val n: Double) extends AnyVal {
    def milliltc = MilliLtc(n)
  }

  implicit final class LtcDouble(private val n: Double) extends AnyVal {
    def ltc = Ltc(n)
  }

  // @formatter:off
  implicit def satoshi2ltc(input: Satoshi): Ltc = input.toLtc
  implicit def ltc2satoshi(input: Ltc): Satoshi = input.toSatoshi
  implicit def satoshi2milliltc(input: Satoshi): MilliLtc = input.toMilliLtc
  implicit def milliltc2satoshi(input: MilliLtc): Satoshi = input.toSatoshi
  implicit def ltc2milliltc(input: Ltc): MilliLtc = input.toMilliLtc
  implicit def milliltc2ltc(input: MilliLtc): Ltc = input.toLtc
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

  def isHashSingle(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_SINGLE

  def isHashNone(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_NONE

  def computeP2PkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val hash = pub.hash160
    chainHash match {
      case Block.RegtestGenesisBlock.hash | Block.TestnetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, hash)
      case Block.LivenetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.PubkeyAddress, hash)
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
  }

  def computeBIP44Address(pub: PublicKey, chainHash: ByteVector32) = computeP2PkhAddress(pub, chainHash)

  /**
    *
    * @param pub       public key
    * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
    * @return the p2swh-of-p2pkh address for this key). It is a Base58 address that is compatible with most litecoin wallets
    */
  def computeP2ShOfP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val script = Script.pay2wpkh(pub)
    val hash = Crypto.hash160(Script.write(script))
    chainHash match {
      case Block.RegtestGenesisBlock.hash | Block.TestnetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.ScriptAddress2Testnet, hash)
      case Block.LivenetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.ScriptAddress2, hash)
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
  }

  def computeBIP49Address(pub: PublicKey, chainHash: ByteVector32) = computeP2ShOfP2WpkhAddress(pub, chainHash)

  /**
    *
    * @param pub       public key
    * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
    * @return the BIP84 address for this key (i.e. the p2wpkh address for this key). It is a Bech32 address that will be
    *         understood only by native sewgit wallets
    */
  def computeP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String = {
    val hash = pub.hash160
    val hrp = chainHash match {
      case Block.LivenetGenesisBlock.hash => "ltc"
      case Block.TestnetGenesisBlock.hash => "tltc"
      case Block.RegtestGenesisBlock.hash => "rltc"
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
    Bech32.encodeWitnessAddress(hrp, 0, hash)
  }

  def computeBIP84Address(pub: PublicKey, chainHash: ByteVector32) = computeP2WpkhAddress(pub, chainHash)
}
