package com.alexdupre.litecoin

import org.scalatest.FunSuite

/**
  * Created by fabrice on 19/04/17.
  */
class Bech32Spec extends FunSuite {
  test("valid checksums") {
    val inputs = Seq(
      "A12UEL5L",
      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
      "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
      "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
    )
    val outputs = inputs.map(Bech32.decode)
    assert(outputs.length == inputs.length)
  }

  test("decode addresses") {
    val inputs = Seq(
      "LTC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KGMN4N9" -> "0014751e76e8199196d454941c45d1b3a323f1433bd6",
      "tltc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qsnr4fp" -> "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      "ltc1sw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kx7lrn8" -> "8128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
      "LTC1SW50QZGYDF5" -> "9002751e",
      "ltc1sw508d6qejxtdg4y5r3zarvaryvc27we9" -> "8210751e76e8199196d454941c45d1b3a323",
      "tltc1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesu9tmgm" -> "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
    )
    inputs.map {
      case (address, bin) =>
        val (_, _, bin1) = Bech32.decodeWitnessAddress(address)
        assert(toHexString(bin1) == bin.substring(4))
    }
  }

  test("create addresses") {
    assert(Bech32.encodeWitnessAddress("ltc", 0, BinaryData("751e76e8199196d454941c45d1b3a323f1433bd6")) == "LTC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KGMN4N9".toLowerCase)
    assert(Bech32.encodeWitnessAddress("tltc", 0, BinaryData("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")) == "tltc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qsnr4fp")
    assert(Bech32.encodeWitnessAddress("rltc", 0, BinaryData("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433")) == "rltc1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesxuhrdn")
  }

  test("reject invalid addresses") {
    val addresses = Seq(
      "tltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
      "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
      "ltc1rw5uspcuh",
      "tltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9jxtdg4y5r3zarvary0c5xw7kw5rljs90",
      "tltc1qrp33g0q5c5txsp9arysrx4k6zd",
      "tltc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qjxtptv"
    )
    addresses.map(address => {
      intercept[IllegalArgumentException] {
        Bech32.decodeWitnessAddress(address)
      }
    })
  }
}
