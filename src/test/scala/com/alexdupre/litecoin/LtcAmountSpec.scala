package com.alexdupre.litecoin

import org.scalatest.FunSuite

class LtcAmountSpec extends FunSuite {

  test("ltc/milliltc/satoshi conversions") {
    val x = 12.34567 ltc
    val y: MilliLtc = x
    val z: Satoshi = x
    val z1: Satoshi = y
    assert(x.toBigDecimal === BigDecimal(12.34567))
    assert(x.toDouble === 12.34567)
    assert(x.toLong === 12L)
    assert(y.toBigDecimal === BigDecimal(12345.67))
    assert(y.toDouble === 12345.67)
    assert(y.toLong === 12345L)
    assert(z === z1)
    assert(z.toLong === 1234567000L)
    val x1: Ltc = z1
    assert(x1 === x)
    val y1: MilliLtc = z1
    assert(y1 === y)
  }

  test("conversions overflow") {
    intercept[IllegalArgumentException] {
      22e6 ltc
    }
  }

  test("arithmetic operations") {
    val x = 1.1 ltc
    val y: Ltc = x - Satoshi(50000)
    val z: Satoshi = y
    assert(z === Satoshi(109950000))
    assert(z + MilliLtc(1.5) === Satoshi(109950000 + 150000))
    assert(z + z === Satoshi(109950000 + 109950000))
    assert(z + z - z === z)
    assert((z + z) / 2 === z)
    assert((z * 3) / 3 === z)
    assert(z * 1.5 === Satoshi(164925000))
    assert(Seq(500 sat, 100 sat, 50 sat).sum === Satoshi(650))
    assert(Ltc(1) + Ltc(2) === Ltc(3))
    assert(MilliLtc(1) + MilliLtc(2) === MilliLtc(3))
    assert(Satoshi(1) + Satoshi(2) === Satoshi(3))
    assert(Ltc(1.3) + MilliLtc(100) - Satoshi(100000000) === Ltc(0.4))
    assert(Satoshi(130000000) + MilliLtc(200) - Ltc(1.1) === Satoshi(40000000))
  }

  test("comparisons") {
    val x: Satoshi = 1.001 ltc
    val y: Satoshi = 1 ltc
    val z: Satoshi = 1 milliltc

    assert(x >= x)
    assert(x <= x)
    assert(x > y)
    assert(y < x)
    assert(x < y + z + z)
    assert(x === y + z)
    assert(Ltc(32) > Ltc(31))
    assert(MilliLtc(32) > MilliLtc(31))
    assert(Ltc(1.3) < MilliLtc(1301))
    assert(Ltc(1.3) > MilliLtc(1299))
    assert(Satoshi(100000) < MilliLtc(1.001))
    assert(Satoshi(100000) > MilliLtc(0.999))
  }

  test("negate amount") {
    assert(Satoshi(-20) === -Satoshi(20))
    assert(MilliLtc(-1.5) === -MilliLtc(1.5))
    assert(Ltc(-2.5) === -Ltc(2.5))
  }

  test("max/min") {
    assert((100 sat).max(101 sat) === Satoshi(101))
    assert((100 sat).min(101 sat) === Satoshi(100))
    assert((100000 sat).max(0.999 milliltc) === Satoshi(100000))
    assert((100000 sat).min(0.999 milliltc) === Satoshi(99900))
    assert((100000000 sat).max(0.999 ltc) === Satoshi(100000000))
    assert((100000000 sat).min(0.999 ltc) === Satoshi(99900000))
    assert((100 milliltc).max(101 milliltc) === MilliLtc(101))
    assert((100 milliltc).min(101 milliltc) === MilliLtc(100))
    assert((1 milliltc).max(90000 sat ) === MilliLtc(1))
    assert((1 milliltc).min(90000 sat ) === MilliLtc(0.9))
    assert((100 milliltc).max(0.2 ltc) === MilliLtc(200))
    assert((100 milliltc).min(0.2 ltc) === MilliLtc(100))
    assert((1.1 ltc).max(0.9 ltc) === Ltc(1.1))
    assert((1.1 ltc).min(0.9 ltc) === Ltc(0.9))
    assert((1.1 ltc).max(900 milliltc) === Ltc(1.1))
    assert((1.1 ltc).min(900 milliltc) === Ltc(0.9))
    assert((1.1 ltc).max(90000000 sat) === Ltc(1.1))
    assert((1.1 ltc).min(90000000 sat) === Ltc(0.9))
  }

}
