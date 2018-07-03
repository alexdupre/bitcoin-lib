package com.alexdupre.litecoin

sealed trait LtcAmount

case class Satoshi(amount: Long) extends LtcAmount {
  // @formatter:off
    def toLong = amount
    def +(other: Satoshi) = Satoshi(amount + other.amount)
    def -(other: Satoshi) = Satoshi(amount - other.amount)
    def *(m: Long) = Satoshi(amount * m)
    def /(d: Long) = Satoshi(amount / d)
    def compare(other: Satoshi): Int = if (amount == other.amount) 0 else if (amount < other.amount) -1 else 1
    def <= (that: Satoshi): Boolean = compare(that) <= 0
    def >= (that: Satoshi): Boolean = compare(that) >= 0
    def <  (that: Satoshi): Boolean = compare(that) <  0
    def >  (that: Satoshi): Boolean = compare(that) > 0
    def unary_-() = Satoshi(-amount)
    // @formatter:on
}

case class Lite(amount: BigDecimal) extends LtcAmount {
  // @formatter:off
    def +(other: Lite) = Lite(amount + other.amount)
    def -(other: Lite) = Lite(amount - other.amount)
    def *(m: Long) = Lite(amount * m)
    def /(d: Long) = Lite(amount / d)
    def compare(other: Lite): Int = if (amount == other.amount) 0 else if (amount < other.amount) -1 else 1
    def <= (that: Lite): Boolean = compare(that) <= 0
    def >= (that: Lite): Boolean = compare(that) >= 0
    def <  (that: Lite): Boolean = compare(that) <  0
    def >  (that: Lite): Boolean = compare(that) > 0
    def unary_-() = Lite(-amount)
    // @formatter:on
}

case class Ltc(amount: BigDecimal) extends LtcAmount {
  require(amount.abs <= 84e6, "amount must not be greater than 84 millions")
  // @formatter:off
    def +(other: Ltc) = Ltc(amount + other.amount)
    def -(other: Ltc) = Ltc(amount - other.amount)
    def *(m: Long) = Ltc(amount * m)
    def /(d: Long) = Ltc(amount / d)
    def compare(other: Ltc): Int = if (amount == other.amount) 0 else if (amount < other.amount) -1 else 1
    def <= (that: Ltc): Boolean = compare(that) <= 0
    def >= (that: Ltc): Boolean = compare(that) >= 0
    def <  (that: Ltc): Boolean = compare(that) <  0
    def >  (that: Ltc): Boolean = compare(that) > 0
    def unary_-() = Ltc(-amount)
    // @formatter:on
}

case class MilliSatoshi(amount: Long) extends LtcAmount {
  // @formatter:off
    def toLong = amount
    def +(other: MilliSatoshi) = MilliSatoshi(amount + other.amount)
    def -(other: MilliSatoshi) = MilliSatoshi(amount - other.amount)
    def *(m: Long) = MilliSatoshi(amount * m)
    def /(d: Long) = MilliSatoshi(amount / d)
    def compare(other: MilliSatoshi): Int = if (amount == other.amount) 0 else if (amount < other.amount) -1 else 1
    def <= (that: MilliSatoshi): Boolean = compare(that) <= 0
    def >= (that: MilliSatoshi): Boolean = compare(that) >= 0
    def <  (that: MilliSatoshi): Boolean = compare(that) <  0
    def >  (that: MilliSatoshi): Boolean = compare(that) > 0
    def unary_-() = MilliSatoshi(-amount)
    // @formatter:on
}

