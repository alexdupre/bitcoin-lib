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

  test("legacy address translation") {
    val inputs = Seq(
      "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu" -> "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
      "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR" -> "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
      "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb"  -> "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r",
      "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC" -> "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
      "3LDsS579y7sruadqu11beEJoTjdFiFCdX4" -> "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
      "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw" -> "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37"
    )
    inputs.map {
      case (legacy, address) =>
        val (addrPrefix, bin1) = Base58Check.decode(legacy)
        val addressComputed = CashAddr.encodeAddress("bitcoincash", if (addrPrefix == Base58.Prefix.PubkeyAddress) CashAddr.Type.PubKey else CashAddr.Type.Script, bin1)
        val (_, addrType, bin2) = CashAddr.decodeAddress(address)
        val legacyComputed = Base58Check.encode(if (addrType == CashAddr.Type.PubKey) Base58.Prefix.PubkeyAddress else Base58.Prefix.ScriptAddress, bin1)
        assert(bin1 == bin2)
        assert(addressComputed == address)
        assert(legacyComputed == legacy)
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

  test("test vectors") {
    def CashAddrType(n: Int): Byte = n.toByte
    val CashAddr.Type.PubKey       = CashAddr.Type.PubKey
    val CashAddr.Type.Script       = CashAddrType(1)
    val cases = Seq(
      ("bitcoincash",
       CashAddr.Type.PubKey,
       BinaryData("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
       "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"),
      ("bchtest",
       CashAddr.Type.Script,
       BinaryData("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"),
       "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t"),
      ("prefix", 15.toByte, BinaryData("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"), "prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf"),
      // 24 bytes
      ("bitcoincash",
       CashAddr.Type.PubKey,
       BinaryData("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
       "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0"),
      ("bchtest",
       CashAddr.Type.Script,
       BinaryData("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
       "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr"),
      ("prefix",
       15.toByte,
       BinaryData("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"),
       "prefix:09adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2p29kc2lp"),
      // 28 bytes
      ("bitcoincash",
       CashAddr.Type.PubKey,
       BinaryData("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
       "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz"),
      ("bchtest",
       CashAddr.Type.Script,
       BinaryData("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
       "bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt"),
      ("prefix",
       15.toByte,
       BinaryData("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"),
       "prefix:0gagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkc5djw8s9g"),
      // 32 bytes
      ("bitcoincash",
       CashAddr.Type.PubKey,
       BinaryData(
         "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825" +
           "C060"),
       "bitcoincash:" +
         "qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake"),
      ("bchtest",
       CashAddr.Type.Script,
       BinaryData(
         "3173EF6623C6B48FFD1A3DCC0CC6489B0A07" +
           "BB47A37F47CFEF4FE69DE825C060"),
       "bchtest:" +
         "pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6"),
      ("prefix",
       15.toByte,
       BinaryData(
         "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825" +
           "C060"),
       "prefix:" +
         "0vch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxqsh6jgp6w"),
      // 40 bytes
      ("bitcoincash",
       CashAddr.Type.PubKey,
       BinaryData(
         "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B256311" +
           "97D194B5C238BEB136FB"),
       "bitcoincash:" +
         "qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39g" +
         "r3uvz"),
      ("bchtest",
       CashAddr.Type.Script,
       BinaryData(
         "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B256311" +
           "97D194B5C238BEB136FB"),
       "bchtest:" +
         "pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm" +
         "6ynej"),
      ("prefix",
       15.toByte,
       BinaryData(
         "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B256311" +
           "97D194B5C238BEB136FB"),
       "prefix:" +
         "0nq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvwsv" +
         "ctzqy"),
      // 48 bytes
      ("bitcoincash",
       CashAddr.Type.PubKey,
       BinaryData(
         "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696" +
           "B98241223D8CE62AD48D863F4CB18C930E4C"),
       "bitcoincash:" +
         "qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7" +
         "n933jfsunqex2w82sl"),
      ("bchtest",
       CashAddr.Type.Script,
       BinaryData(
         "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696" +
           "B98241223D8CE62AD48D863F4CB18C930E4C"),
       "bchtest:" +
         "ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7" +
         "n933jfsunqnzf7mt6x"),
      ("prefix",
       15.toByte,
       BinaryData(
         "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696" +
           "B98241223D8CE62AD48D863F4CB18C930E4C"),
       "prefix:" +
         "0h3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7" +
         "n933jfsunqakcssnmn"),
      // 56 bytes
      ("bitcoincash",
       CashAddr.Type.PubKey,
       BinaryData(
         "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E" +
           "6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"),
       "bitcoincash:" +
         "qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhv" +
         "w8ym5d8qx7sz7zz0zvcypqscw8jd03f"),
      ("bchtest",
       CashAddr.Type.Script,
       BinaryData(
         "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E" +
           "6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"),
       "bchtest:" +
         "pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhv" +
         "w8ym5d8qx7sz7zz0zvcypqs6kgdsg2g"),
      ("prefix",
       15.toByte,
       BinaryData(
         "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E" +
           "6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"),
       "prefix:" +
         "0mvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhv" +
         "w8ym5d8qx7sz7zz0zvcypqsgjrqpnw8"),
      // 64 bytes
      ("bitcoincash",
       CashAddr.Type.PubKey,
       BinaryData(
         "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E" +
           "67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA0" +
           "8884175B"),
       "bitcoincash:" +
         "qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5fl" +
         "ttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w"),
      ("bchtest",
       CashAddr.Type.Script,
       BinaryData(
         "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E" +
           "67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA0" +
           "8884175B"),
       "bchtest:" +
         "plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5fl" +
         "ttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez"),
      ("prefix",
       15.toByte,
       BinaryData(
         "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E" +
           "67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA0" +
           "8884175B"),
       "prefix:" +
         "0lg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5fl" +
         "ttj6ydvjc0pv3nchp52amk97tqa5zygg96ms92w6845")
    )
    cases.map {
      case (prefix, version, content, expected) =>
        val address = CashAddr.encodeAddress(prefix, version, content)
        assert(address == expected)
    }

  }
}
