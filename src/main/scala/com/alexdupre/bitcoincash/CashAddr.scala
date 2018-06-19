package com.alexdupre.bitcoincash

import scala.util.Try

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
  val map: Map[Char, Int5] = alphabet.zipWithIndex.toMap.mapValues(_.toByte)
  // 5 bits value -> char
  val pam: Map[Int5, Char] = map.map(_.swap)

  def expand(hrp: String): Seq[Int5] = hrp.map(c => (c.toInt & 31).toByte)

  def polymod(values: Seq[Int5]): Long = {
    val GEN = Seq(0x98f2bc8e61L, 0x79b76d99e2L, 0xf33e5fb3c4L, 0xae2eabe2a8L, 0x1e4f43e470L)
    var chk = 1L
    values.map(v => {
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
  def decode(cashaddr: String): (String, Seq[Int5]) = {
    val input = cashaddr.toLowerCase()
    val pos = input.lastIndexOf(':')
    val hrp = input.take(pos)
    val data = input.drop(pos + 1).map(c => map(c))
    val checksum = polymod(expand(hrp) ++ (0.toByte +: data))
    require(checksum == 0, s"invalid checksum for $cashaddr")
    (hrp, data.dropRight(8))
  }

  /**
    *
    * @param hrp  Human Readable Part
    * @param data data (a sequence of 5 bits integers)
    * @return a checksum computed over hrp and data
    */
  def checksum(hrp: String, data: Seq[Int5]): Seq[Int5] = {
    val values = expand(hrp) ++ (0.toByte +: data)
    val poly = polymod(values ++ Seq(0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte, 0.toByte))
    for (i <- 0 to 7) yield ((poly >>> 5 * (7 - i)) & 31).toByte
  }

  /**
    *
    * @param input a sequence of 8 bits integers
    * @return a sequence of 5 bits integers
    */
  def eight2five(input: Seq[Byte]): Seq[Int5] = {
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
    output
  }

  /**
    *
    * @param input a sequence of 5 bits integers
    * @return a sequence of 8 bits integers
    */
  def five2eight(input: Seq[Int5]): Seq[Byte] = {
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
    output
  }

  /**
    * encode a bitcoin cash address
    *
    * @param hrp            should be "bitcoincash" or "bchtest"
    * @param type           type (0 to 15, only 0 = P2PKH and 1 = P2SH are currently defined)
    * @param data           hash: 20 bytes (P2PKH or P2SH)
    * @return a cashaddr encoded witness address
    */
  def encodeAddress(hrp: String, `type`: Byte, data: BinaryData): String = {
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
    val data1 = CashAddr.eight2five(version.toByte +: data)
    val checksum = CashAddr.checksum(hrp, data1)
    hrp + ":" + new String((data1 ++ checksum).map(i => CashAddr.pam(i)).toArray)
  }

  /**
    * decode a bitcoin cash address
    *
    * @param address address
    * @return a (prefix, type, hash) tuple
    */
  def decodeAddress(address: String): (String, Byte, BinaryData) = {
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
    (hrp, version.toByte, bin)
  }

  /**
    * decode a bitcoin cash address
    *
    * @param address address (optional prefix)
    * @return a (prefix, type, hash) tuple
    */
  def decodeAddressTolerant(address: String): (String, Byte, BinaryData) = {
    if (address.contains(':')) decodeAddress(address)
    else {
      def tryPrefixes(ps: Seq[String]): (String, Byte, BinaryData) = ps match {
        case Nil => throw new IllegalArgumentException("unable to auto-detect address prefix")
        case prefix :: tail => Try(decodeAddress(s"$prefix:$address")).toOption.fold(tryPrefixes(tail))(identity)
      }
      tryPrefixes(Seq("bitcoincash", "bchtest", "bchreg"))
    }
  }

}
