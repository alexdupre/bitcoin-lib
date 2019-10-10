package com.alexdupre.bitcoincash

import scala.util.Try
import scodec.bits.ByteVector

/**
  * See https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
  */
object CashAddr {

  object Type {
    val PubKey = 0.toByte
    val Script = 1.toByte
  }

  val alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

  // 5 bits integer
  // CashAddr works with 5bits values, we use this type to make it explicit: whenever you see Int5 it means 5bits values, and
  // whenever you see Byte it means 8bits values
  type Int5 = Byte

  // char -> 5 bits value
  private val InvalidChar = 255.toByte
  val map = {
    val result = new Array[Int5](255)
    for (i <- 0 until result.length) result(i) = InvalidChar
    alphabet.zipWithIndex.foreach { case (c, i) => result(c) = i.toByte }
    result
  }

  private def expand(hrp: String): Array[Int5] = {
    val result = new Array[Int5](hrp.length)
    var i = 0
    while (i < hrp.length) {
      result(i) = (hrp(i).toInt & 31).toByte
      i = i + 1
    }
    result
  }

  def polymod(values: Array[Int5], values1: Array[Int5]): Long = {
    val GEN = Array(0x98f2bc8e61L, 0x79b76d99e2L, 0xf33e5fb3c4L, 0xae2eabe2a8L, 0x1e4f43e470L)
    var chk = 1L
    values.foreach(v => {
      val b = chk >>> 35
      chk = ((chk & 0x07ffffffffL) << 5) ^ v
      for (i <- 0 until 5) {
        if (((b >>> i) & 1) != 0) chk = chk ^ GEN(i)
      }
    })
    values1.foreach(v => {
      val b = chk >>> 35
      chk = ((chk & 0x07ffffffffL) << 5) ^ v
      for (i <- 0 until 5) {
        if (((b >>> i) & 1) != 0) chk = chk ^ GEN(i)
      }
    })
    chk ^ 1L
  }

  /**
    * decodes a cashaddr string
    *
    * @param cashaddr cashaddr string
    * @return a (hrp, data) tuple
    */
  def decode(cashaddr: String): (String, Array[Int5]) = {
    val input = cashaddr.toLowerCase()
    val pos = input.lastIndexOf(':')
    val hrp = input.take(pos)
    val data = new Array[Int5](input.length - pos - 1)
    for (i <- 0 until data.size) {
      val elt = map(input(pos + 1 + i))
      require(elt != InvalidChar, s"invalid bech32 character ${input(pos + 1 + i)}")
      data(i) = elt
    }
    val checksum = polymod(expand(hrp), 0.toByte +: data)
    require(checksum == 0, s"invalid checksum for $cashaddr")
    (hrp, data.dropRight(8))
  }

  /**
    *
    * @param hrp  Human Readable Part
    * @param data data (a sequence of 5 bits integers)
    * @return a checksum computed over hrp and data
    */
  private def checksum(hrp: String, data: Array[Int5]): Array[Int5] = {
    val values = expand(hrp) ++ (0.toByte +: data)
    val poly = polymod(values, Array(0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte))
    val result = new Array[Int5](8)
    for (i <- 0 to 7) result(i) =  ((poly >>> 5 * (7 - i)) & 31).toByte
    result
  }

  /**
    *
    * @param input a sequence of 8 bits integers
    * @return a sequence of 5 bits integers
    */
  private def eight2five(input: Array[Byte]): Array[Int5] = {
    var buffer = 0L
    val output = collection.mutable.ArrayBuffer.empty[Byte]
    var count = 0
    input.map(b => {
      buffer = (buffer << 8) | (b & 0xff)
      count = count + 8
      while (count >= 5) {
        output.append(((buffer >> (count - 5)) & 31).toByte)
        count = count - 5
      }
    })
    if (count > 0) output.append(((buffer << (5 - count)) & 31).toByte)
    output.toArray
  }

  /**
    *
    * @param input a sequence of 5 bits integers
    * @return a sequence of 8 bits integers
    */
  private def five2eight(input: Array[Int5]): Array[Byte] = {
    var buffer = 0L
    val output = collection.mutable.ArrayBuffer.empty[Byte]
    var count = 0
    input.map(b => {
      buffer = (buffer << 5) | (b & 31)
      count = count + 5
      while (count >= 8) {
        output.append(((buffer >> (count - 8)) & 0xff).toByte)
        count = count - 8
      }
    })
    require(count <= 4, "Zero-padding of more than 4 bits")
    require((buffer & ((1 << count) - 1)) == 0, "Non-zero padding in 8-to-5 conversion")
    output.toArray
  }

  /**
    * encode a bitcoin cash address
    *
    * @param hrp            should be "bitcoincash" or "bchtest"
    * @param type           type (0 to 15, only 0 = P2PKH and 1 = P2SH are currently defined)
    * @param data           hash: 20 bytes (P2PKH or P2SH)
    * @return a cashaddr encoded witness address
    */
  def encodeAddress(hrp: String, `type`: Byte, data: ByteVector): String = {
    val size = (data.length * 8) match {
      case 160 => 0
      case 192 => 1
      case 224 => 2
      case 256 => 3
      case 320 => 4
      case 384 => 5
      case 448 => 6
      case 512 => 7
      case _ => throw new IllegalArgumentException("requirement failed: invalid address length")
    }
    val version = (`type` << 3) | size
    val data1 = CashAddr.eight2five(version.toByte +: data.toArray)
    val checksum = CashAddr.checksum(hrp, data1)
    hrp + ":" + new String((data1 ++ checksum).map(i => alphabet(i)))
  }

  /**
    * decode a bitcoin cash address
    *
    * @param address address
    * @return a (prefix, type, hash) tuple
    */
  def decodeAddress(address: String): (String, Byte, ByteVector) = {
    val SIZE = Seq(160, 192, 224, 256, 320, 384, 448, 512)
    if (address.indexWhere(_.isLower) != -1 && address.indexWhere(_.isUpper) != -1) throw new IllegalArgumentException("input mixes lowercase and uppercase characters")
    val (hrp, data) = decode(address)
    require(hrp == "bitcoincash" || hrp == "bchtest" || hrp == "bchreg", s"invalid HRP $hrp")
    val bin1 = five2eight(data)
    require(bin1.length > 0, s"missing version")
    val version = bin1(0)
    require(version >= 0 && version <= 16, "invalid version")
    val hashSize = SIZE(version & 0x07)
    val bin = bin1.drop(1)
    require(bin.length == hashSize / 8, s"invalid hash length ${bin.length}")
    val `type` = (version >> 3) & 0x0f
    (hrp, version.toByte, ByteVector.view(bin))
  }

  /**
    * decode a bitcoin cash address
    *
    * @param address address (optional prefix)
    * @return a (prefix, type, hash) tuple
    */
  def decodeAddressTolerant(address: String): (String, Byte, ByteVector) = {
    if (address.contains(':')) decodeAddress(address)
    else {
      def tryPrefixes(ps: List[String]): (String, Byte, ByteVector) = ps match {
        case Nil => throw new IllegalArgumentException("unable to auto-detect address prefix")
        case prefix :: tail => Try(decodeAddress(s"$prefix:$address")).toOption.fold(tryPrefixes(tail))(identity)
      }
      tryPrefixes(List("bitcoincash", "bchtest", "bchreg"))
    }
  }

}
