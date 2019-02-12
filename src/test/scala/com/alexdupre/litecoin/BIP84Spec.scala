package com.alexdupre.litecoin

import com.alexdupre.litecoin.Crypto.PublicKey
import com.alexdupre.litecoin.DeterministicWallet.KeyPath
import org.scalatest.FunSuite

/**
  * BIP 84 (Derivation scheme for P2WPKH based accounts) reference tests (changed for litecoin)
  * see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
  */
class BIP84Spec extends FunSuite {
  test("BIP49 reference tests") {
    val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" "), "")
    val master = DeterministicWallet.generate(seed)
    assert(DeterministicWallet.encode(master, DeterministicWallet.xprv) == "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")
    assert(DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.xpub) == "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8")

    val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/2'/0'"))
    assert(DeterministicWallet.encode(accountKey, DeterministicWallet.xprv) == "xprv9yjv4vNKzFSMtRJP6BQfLMnGE3TZJQnmZL7AHsm2CqCav1B9rKdquT5FRBYAvJL5VQHAXHUb9bYMCpNKd21ezPBf8PjCLP1NytuYGJYkL49")
    assert(DeterministicWallet.encode(DeterministicWallet.publicKey(accountKey), DeterministicWallet.xpub) == "xpub6CjGURuDpczf6uNrCCwfhVizn5J3hsWcvZ2m6GAdmAjZnoWJPrx6TFPjGSftc2o5fvox6ubQjSXmjjaHZjwYMH7SGFpHHb9Jg24zBf66mbE")

    val key = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 0L :: Nil)
    assert(key.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/2'/0'/0/0")).secretkeybytes)
    assert(Base58Check.encode(Base58.Prefix.SecretKey, key.privateKey.toBin) == "T5ZCYhLqXu6EJKk2nhjvwsaLH357CisixhLGWpKXEiqWTUtzte6o")
    assert(key.publicKey == PublicKey(BinaryData("02e49c9b9b5d0f127235dc26a0c252814c52fb333d651a946773f59d72c2da9904")))
    assert(computeBIP84Address(key.publicKey, Block.LivenetGenesisBlock.hash) == "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh")

    val key1 = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 1L :: Nil)
    assert(key1.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/2'/0'/0/1")).secretkeybytes)
    assert(Base58Check.encode(Base58.Prefix.SecretKey, key1.privateKey.toBin) == "T6LRyVtoN2JxywNyYXwk9KoMpWa34Fjino4upyy9RKs5QQmC8RSr")
    assert(key1.publicKey == PublicKey(BinaryData("021c1750d4a5ad543967b30e9447e50da7a5873e8be133eb25f2ce0ea5638b9d17")))
    assert(computeBIP84Address(key1.publicKey, Block.LivenetGenesisBlock.hash) == "ltc1qwlezpr3890hcp6vva9twqh27mr6edadreqvhnn")

    val key2 = DeterministicWallet.derivePrivateKey(accountKey, 1L :: 0L :: Nil)
    assert(key2.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/2'/0'/1/0")).secretkeybytes)
    assert(Base58Check.encode(Base58.Prefix.SecretKey, key2.privateKey.toBin) == "TARZNteayzJqRiXnqKJX3h5zr6H4tx4sXvoZ21pHjAEgNc1g2MWm")
    assert(key2.publicKey == PublicKey(BinaryData("029857513f0fe1dc125f219ffef22098e14c653c4bcb0a2aaeff47b3a252569f1a")))
    assert(computeBIP84Address(key2.publicKey, Block.LivenetGenesisBlock.hash) == "ltc1qyeljcy9v88jg8sqvnqh0m5q390xruc5r98q9yy")
  }
}
