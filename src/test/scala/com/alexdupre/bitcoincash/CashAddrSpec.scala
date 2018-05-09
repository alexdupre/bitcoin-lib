package com.alexdupre.bitcoincash

import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class CashAddrSpec extends FunSuite {
  test("valid checksums") {
    val inputs = Seq(
      "prefix:x64nx6hz",
      "p:gpf8m4h7",
      "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn",
      "bchtest:testnetaddress4d6njnut",
      "bchreg:555555555555555555555555555555555555555555555udxmlmrz"
    )
    val outputs = inputs.map(CashAddr.decode)
    assert(outputs.length == inputs.length)
  }

  test("decode & encode addresses") {
    val inputs = Seq(
      "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a" -> "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu",
      "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy" -> "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR",
      "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r" -> "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb",
      "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq" -> "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC",
      "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e" -> "3LDsS579y7sruadqu11beEJoTjdFiFCdX4",
      "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37" -> "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw"
    )
    inputs.map {
      case (address, legacy) =>
        val (_, version1, bin1) = CashAddr.decodeAddress(address)
        val legacyComputed = Base58Check.encode(if (version1 == 0) Base58.Prefix.PubkeyAddress else Base58.Prefix.ScriptAddress, bin1)
        val (version2, bin2) = Base58Check.decode(legacy)
        val addressComputed = CashAddr.encodeAddress("bitcoincash", if (version2 == Base58.Prefix.PubkeyAddress) 0 else 8, bin2)
        assert(bin1 == bin2)
        assert(legacyComputed == legacy)
        assert(addressComputed == address)
    }
  }

  test("auto-detect prefixes") {
    val inputs = Seq(
      "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a" -> "bitcoincash",
      "qqvr7l20wjz75sdpgrq0xta9v3zhqs0jggfx4uwd7r" -> "bchtest"
    )
    inputs.map {
      case (address, prefix) =>
        val (detected, _, _) = CashAddr.decodeAddressTolerant(address)
        assert(detected == prefix)
    }
  }

  test("reject invalid addresses") {
    val addresses = Seq(
      "bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", // wrong network
      "bitcoincash:QR95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy", // upper-lower mix
      "bitcoincash:qqyq78nf2w", // wrong hash size
      "bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks602" // wrong checksum
    )
    addresses.map(address => {
      intercept[IllegalArgumentException] {
        CashAddr.decodeAddress(address)
      }
    })
  }
}
