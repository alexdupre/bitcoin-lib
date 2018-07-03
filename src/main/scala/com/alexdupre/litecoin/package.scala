package com.alexdupre

import java.math.BigInteger

import com.alexdupre.litecoin.Crypto.PublicKey
import org.spongycastle.util.encoders.Hex

/**
  * see https://en.bitcoin.it/wiki/Protocol_specification
  */
package object litecoin {
  val Coin = 100000000L
  val Cent = 1000000L
  val MaxMoney = 84000000 * Coin
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

  object Hash {
    val Zeroes: BinaryData = "0000000000000000000000000000000000000000000000000000000000000000"
    val One: BinaryData = "0100000000000000000000000000000000000000000000000000000000000000"
  }

  object SigVersion {
    val SIGVERSION_BASE = 0
    val SIGVERSION_WITNESS_V0 = 1
  }

  implicit object NumericSatoshi extends Numeric[Satoshi] {
    // @formatter:off
    override def plus(x: Satoshi, y: Satoshi): Satoshi = x + y
    override def toDouble(x: Satoshi): Double = x.toLong
    override def toFloat(x: Satoshi): Float = x.toLong
    override def toInt(x: Satoshi): Int = x.toLong.toInt
    override def negate(x: Satoshi): Satoshi = Satoshi(-x.amount)
    override def fromInt(x: Int): Satoshi = Satoshi(x)
    override def toLong(x: Satoshi): Long = x.toLong
    override def times(x: Satoshi, y: Satoshi): Satoshi = ???
    override def minus(x: Satoshi, y: Satoshi): Satoshi = ???
    override def compare(x: Satoshi, y: Satoshi): Int = x.compare(y)
    // @formatter:on
  }

  implicit final class SatoshiLong(private val n: Long) extends AnyVal {
    def satoshi = Satoshi(n)
  }

  implicit final class MilliSatoshiLong(private val n: Long) extends AnyVal {
    def millisatoshi = MilliSatoshi(n)
  }

  implicit final class LtcDouble(private val n: Double) extends AnyVal {
    def ltc = Ltc(n)
  }

  implicit final class LiteDouble(private val n: Double) extends AnyVal {
    def lite = Lite(n)
  }

  implicit def satoshi2ltc(input: Satoshi): Ltc = Ltc(BigDecimal(input.amount) / Coin)

  implicit def ltc2satoshi(input: Ltc): Satoshi = Satoshi((input.amount * Coin).toLong)

  implicit def satoshi2lite(input: Satoshi): Lite = ltc2lite(satoshi2ltc(input))

  implicit def lite2satoshi(input: Lite): Satoshi = ltc2satoshi(lite2ltc(input))

  implicit def ltc2lite(input: Ltc): Lite = Lite(input.amount * 1000L)

  implicit def lite2ltc(input: Lite): Ltc = Ltc(input.amount / 1000L)

  implicit def satoshi2millisatoshi(input: Satoshi): MilliSatoshi = MilliSatoshi(input.amount * 1000L)

  implicit def millisatoshi2satoshi(input: MilliSatoshi): Satoshi = Satoshi(input.amount / 1000L)

  implicit def ltc2millisatoshi(input: Ltc): MilliSatoshi = satoshi2millisatoshi(ltc2satoshi(input))

  implicit def millisatoshi2ltc(input: MilliSatoshi): Ltc = satoshi2ltc(millisatoshi2satoshi(input))

  implicit def lite2millisatoshi(input: Lite): MilliSatoshi = satoshi2millisatoshi(lite2satoshi(input))

  implicit def millisatoshi2lite(input: MilliSatoshi): Lite = satoshi2lite(millisatoshi2satoshi(input))

  def toHexString(blob: BinaryData) = Hex.toHexString(blob)

  def fromHexString(hex: String): BinaryData = Hex.decode(hex.stripPrefix("0x"))

  implicit def string2binaryData(input: String): BinaryData = BinaryData(fromHexString(input))

  implicit def seq2binaryData(input: Seq[Byte]): BinaryData = BinaryData(input)

  implicit def array2binaryData(input: Array[Byte]): BinaryData = BinaryData(input)

  implicit def binaryData2array(input: BinaryData): Array[Byte] = input.data.toArray

  implicit def binaryData2Seq(input: BinaryData): Seq[Byte] = input.data

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
      val nWord1 = (input & 0x007fffffL)
      (nWord1, BigInteger.valueOf(nWord1).shiftLeft(8 * (nSize - 3)))
    }
    val isNegative = nWord != 0 && (input & 0x00800000) != 0
    val overflow = nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))
    (result, isNegative, overflow)
  }

  def isAnyoneCanPay(sighashType: Int): Boolean = (sighashType & SIGHASH_ANYONECANPAY) != 0

  def isHashSingle(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_SINGLE

  def isHashNone(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_NONE

  def computeP2PkhAddress(pub: PublicKey, chainHash: BinaryData): String = {
    val hash = pub.hash160
    chainHash match {
      case Block.RegtestGenesisBlock.hash | Block.TestnetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, hash)
      case Block.LivenetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.PubkeyAddress, hash)
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
  }

  def computeBIP44Address(pub: PublicKey, chainHash: BinaryData) = computeP2PkhAddress(pub, chainHash)

  /**
    *
    * @param pub public key
    * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
    * @return the p2swh-of-p2pkh address for this key). It is a Base58 address that is compatible with most litecoin wallets
    */
  def computeP2ShOfP2WpkhAddress(pub: PublicKey, chainHash: BinaryData): String = {
    val script = Script.pay2wpkh(pub)
    val hash = Crypto.hash160(Script.write(script))
    chainHash match {
      case Block.RegtestGenesisBlock.hash | Block.TestnetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.ScriptAddress2Testnet, hash)
      case Block.LivenetGenesisBlock.hash => Base58Check.encode(Base58.Prefix.ScriptAddress2, hash)
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
  }

  def computeBIP49Address(pub: PublicKey, chainHash: BinaryData) = computeP2ShOfP2WpkhAddress(pub, chainHash)

    /**
    *
    * @param pub public key
    * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
    * @return the BIP84 address for this key (i.e. the p2wpkh address for this key). It is a Bech32 address that will be
    *         understood only by native sewgit wallets
    */
  def computeP2WpkhAddress(pub: PublicKey, chainHash: BinaryData): String = {
    val hash = pub.hash160
    val hrp = chainHash match {
      case Block.LivenetGenesisBlock.hash => "ltc"
      case Block.TestnetGenesisBlock.hash => "tltc"
      case Block.RegtestGenesisBlock.hash => "rltc"
      case _ => throw new IllegalArgumentException("Unknown chain hash: " + chainHash)
    }
    Bech32.encodeWitnessAddress(hrp, 0, hash)
  }

  def computeBIP84Address(pub: PublicKey, chainHash: BinaryData) = computeP2WpkhAddress(pub, chainHash)
}
