package com.alexdupre.litecoin

import com.alexdupre.litecoin.Crypto.{PrivateKey, PublicKey}
import com.alexdupre.litecoin.DeterministicWallet.KeyPath
import org.scalatest.FunSuite
import scodec.bits._

/**
  * BIP 49 (Derivation scheme for P2WPKH-nested-in-P2SH based accounts) reference tests (changed for litecoin)
  * see https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
  */
class BIP49Spec extends FunSuite {
  test("BIP49 reference tests") {
    val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ").toSeq, "")
    val master = DeterministicWallet.generate(seed)
    assert(DeterministicWallet.encode(master, DeterministicWallet.xprv) == "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")

    val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/49'/2'/0'"))
    assert(DeterministicWallet.encode(accountKey, DeterministicWallet.Mtpv) == "Mtpv7RooeEQDUitupgpJcxZnfDwvq8hC24R7GAiscrqFhHHhit96vCNY7yudJgrM841dMbiRUQceC12566XAHHC8Rd1BtnBdokq9tmF7jLLvUdh")

    val key = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 0L :: Nil)
    assert(key.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/49'/2'/0'/0/0")).secretkeybytes)
    assert(key.privateKey.toBase58(Base58.Prefix.SecretKey) == "T8xSEcthDYN4rNUu4eTqtZTDSvphsjgBNbKawBeCkUqZLZ9MH8Ff")
    assert(key.privateKey == PrivateKey(hex"0xb02c7ab9f8827bc028780d5dfd6bab2a1f35d2b89f9b246829802ba5b83ba1c201"))
    assert(key.publicKey == PublicKey(hex"0x03f7a0a5d44504ea8a2494c7e32c895ba4968d3dab66a4d790380be8b0539f36bc"))
    assert(computeBIP49Address(key.publicKey, Block.LivenetGenesisBlock.hash) == "M7wtsL7wSHDBJVMWWhtQfTMSYYkyooAAXM")
  }
}
