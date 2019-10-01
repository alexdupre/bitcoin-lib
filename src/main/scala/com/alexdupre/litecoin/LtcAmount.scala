package com.alexdupre.litecoin

sealed trait LtcAmount

case class Satoshi(private val underlying: Long) extends LtcAmount with Ordered[Satoshi] {
  // @formatter:off
  def +(other: Satoshi) = Satoshi(underlying + other.underlying)
  def -(other: Satoshi) = Satoshi(underlying - other.underlying)
  def unary_-() = Satoshi(-underlying)
  def *(m: Long) = Satoshi(underlying * m)
  def *(m: Double) = Satoshi((underlying * m).toLong)
  def /(d: Long) = Satoshi(underlying / d)
  def compare(other: Satoshi): Int = underlying.compare(other.underlying)
  def max(other: LtcAmount): Satoshi = other match {
    case other: Satoshi => if (underlying > other.underlying) this else other
    case other: MilliLtc => if (underlying > other.toSatoshi.underlying) this else other.toSatoshi
    case other: Ltc => if (underlying > other.toSatoshi.underlying) this else other.toSatoshi
  }
  def min(other: LtcAmount): Satoshi = other match {
    case other: Satoshi => if (underlying < other.underlying) this else other
    case other: MilliLtc => if (underlying < other.toSatoshi.underlying) this else other.toSatoshi
    case other: Ltc => if (underlying < other.toSatoshi.underlying) this else other.toSatoshi
  }
  def toLtc: Ltc = Ltc(BigDecimal(underlying) / LtcAmount.Coin)
  def toMilliLtc: MilliLtc = toLtc.toMilliLtc
  def toLong = underlying
  // @formatter:on
}

case class MilliLtc(private val underlying: BigDecimal) extends LtcAmount with Ordered[MilliLtc] {
  // @formatter:off
  def +(other: MilliLtc) = MilliLtc(underlying + other.underlying)
  def -(other: MilliLtc) = MilliLtc(underlying - other.underlying)
  def unary_-() = MilliLtc(-underlying)
  def *(m: Long) = MilliLtc(underlying * m)
  def *(m: Double) = MilliLtc(underlying * m)
  def /(d: Long) = MilliLtc(underlying / d)
  def compare(other: MilliLtc): Int = underlying.compare(other.underlying)
  def max(other: LtcAmount): MilliLtc = other match {
    case other: Satoshi => if (underlying > other.toMilliLtc.underlying) this else other.toMilliLtc
    case other: MilliLtc => if (underlying > other.underlying) this else other
    case other: Ltc => if (underlying > other.toMilliLtc.underlying) this else other.toMilliLtc
  }
  def min(other: LtcAmount): MilliLtc = other match {
    case other: Satoshi => if (underlying < other.toMilliLtc.underlying) this else other.toMilliLtc
    case other: MilliLtc => if (underlying < other.underlying) this else other
    case other: Ltc => if (underlying < other.toMilliLtc.underlying) this else other.toMilliLtc
  }
  def toLtc: Ltc = Ltc(underlying / 1000)
  def toSatoshi: Satoshi = toLtc.toSatoshi
  def toBigDecimal = underlying
  def toDouble: Double = underlying.toDouble
  def toLong: Long = underlying.toLong
  // @formatter:on
}

case class Ltc(private val underlying: BigDecimal) extends LtcAmount with Ordered[Ltc] {
  require(underlying.abs <= 21e6, "amount must not be greater than 21 millions")

  // @formatter:off
  def +(other: Ltc) = Ltc(underlying + other.underlying)
  def -(other: Ltc) = Ltc(underlying - other.underlying)
  def unary_-() = Ltc(-underlying)
  def *(m: Long) = Ltc(underlying * m)
  def *(m: Double) = Ltc(underlying * m)
  def /(d: Long) = Ltc(underlying / d)
  def compare(other: Ltc): Int = underlying.compare(other.underlying)
  def max(other: LtcAmount): Ltc = other match {
    case other: Satoshi => if (underlying > other.toLtc.underlying) this else other.toLtc
    case other: MilliLtc => if (underlying > other.toLtc.underlying) this else other.toLtc
    case other: Ltc => if (underlying > other.underlying) this else other
  }
  def min(other: LtcAmount): Ltc = other match {
    case other: Satoshi => if (underlying < other.toLtc.underlying) this else other.toLtc
    case other: MilliLtc => if (underlying < other.toLtc.underlying) this else other.toLtc
    case other: Ltc => if (underlying < other.underlying) this else other
  }
  def toMilliLtc: MilliLtc = MilliLtc(underlying * 1000)
  def toSatoshi: Satoshi = Satoshi((underlying * LtcAmount.Coin).toLong)
  def toBigDecimal = underlying
  def toDouble: Double = underlying.toDouble
  def toLong: Long = underlying.toLong
  // @formatter:on
}

object LtcAmount {
  val Coin = 100000000L
  val Cent = 1000000L
  val MaxMoney = 21e6 * Coin
}