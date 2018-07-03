package com.alexdupre.litecoin

import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class LtcAmountSpec extends FunSuite {

  test("ltc/satoshi conversions") {
    val x = 12.34567 ltc
    val y: Lite = x
    val z: Satoshi = x
    val z1: Satoshi = y
    assert(z === z1)
    assert(y.amount === BigDecimal(12345.67))
    assert(z.amount === 1234567000L)
    val x1: Ltc = z1
    assert(x1 === x)
    val x2: Lite = z1
    assert(x2 === y)

    val z3: MilliSatoshi = x

    val z4: MilliSatoshi = y
    assert(z3 == z4)
    assert(z3.amount == 1234567000000L)

    val z5 = 1234567000000L millisatoshi
    val x4: Ltc = z5
    assert(x4 == x)
  }

  test("conversions overflow") {
    intercept[IllegalArgumentException] {
      val toomany = 85e6 ltc
    }
  }

  test("basic operations") {
    val x = 1.1 ltc
    val y: Ltc = x - Satoshi(50000)
    val z: Satoshi = y
    assert(z === Satoshi(109950000))
    assert(z + z === Satoshi(109950000 + 109950000))
    assert(z + z - z === z)
    assert((z + z) / 2 === z)
    assert((z * 3) / 3 === z)
    assert(Seq(500 satoshi, 100 satoshi, 50 satoshi).sum === Satoshi(650))
    assert(Ltc(1) + Ltc(2) == Ltc(3))
    assert(Lite(1) + Lite(2) == Lite(3))
    assert(Satoshi(1) + Satoshi(2) == Satoshi(3))
    assert(MilliSatoshi(1) + MilliSatoshi(2) == MilliSatoshi(3))
  }

  test("basic comparisons") {
    val x: Satoshi = 1.001 ltc
    val y: Satoshi = 1 ltc
    val z: Satoshi = 1 lite

    assert(x >= x)
    assert(x <= x)
    assert(x > y)
    assert(y < x)
    assert(x < y + z + z)
    assert(x == y + z)
    assert(Ltc(32) > Ltc(31))
    assert(Lite(32) > Lite(31))
    assert(MilliSatoshi(32) > MilliSatoshi(31))
  }

  test("negate amount") {
    assert(Satoshi(-20) == -Satoshi(20))
  }
}
