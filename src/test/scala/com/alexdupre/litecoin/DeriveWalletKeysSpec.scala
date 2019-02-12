package com.alexdupre.litecoin

import org.scalatest.FunSuite

/**
  * check that we can restore BIP44, BIP49 and BIP84 wallets and generate valid xpubs and addresses.
  * please note that this test only shows how to derive account keys and addresses. Change keys and addresses can
  * use the same scheme will a different derivation path.
  * this was tested with electrum (BIPs 44, 49, 84) and mycellium (BIP44) testnet wallets
  */
class DeriveWalletKeysSpec extends FunSuite {
  import DeriveWalletKeysSpec._

  val mnemonics = "gun please vital unable phone catalog explain raise erosion zoo truly exist"
  val seed = MnemonicCode.toSeed(mnemonics, "")
  val master = DeterministicWallet.generate(seed)

  test("restore BIP44 wallet") {
    val account = DeterministicWallet.derivePrivateKey(master, DeterministicWallet.KeyPath("m/44'/2'/0'"))
    val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.Ltub)
    assert(xpub == "Ltub2Yf9yF4GtmXFp876vKFjwCPsRRumEasKgHf7opGEEgCAdXqxMS9546VCWrDDdr9QgvwcqX94QubhQezgsKysPh5scrFr6FiZgT4C1NvZePm")
    assert(deriveAddresses(xpub) == Seq("LVYyx7zGCRMWWRBqqRa9xKyktnJBfimsiZ", "Lf5S33wSwVqRU32XhJNxJP8XEk9ndrd173", "LPGYNS3D2vEoWrGTdD4HFVW1DUcBptXZca", "LYCcybttjrayMs8ty4Lg7YrYkttmcV2xxe", "LKUK3k98Tm7RSiWhd8AoUfdLmvhZZMbuaU"))
  }

  test("restore BIP49 wallet") {
    val account = DeterministicWallet.derivePrivateKey(master, DeterministicWallet.KeyPath("m/49'/2'/0'"))
    val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.Mtub)
    assert(xpub == "Mtub2sWMFje8oFK5p3RtAYKaKPLnGQaz53LqB6AVeTTcq75ntD6VbPvNUZdM4y9WBeSRs4M5U4KuAo6826vTGgbfzqW5enKR1YhWkrsk1GTB1aE")
    assert(deriveAddresses(xpub) == Seq("MD8VfaW8KAYVFwWoS58gfHmJnT7GaaSRrg", "MAqepo9XZSVCCqCRqzh3qHaNBNv1NSHkG6", "MSXDurSto2Yi1Vr2UmW4c5ZZ1NcSt9nuf9", "MKT27Wxtg8BnMDr3u6vP2zV1eZrcuTwFwK", "MGTcMSFFxLu2knEcFW7U8APqnjSJ6BF2iQ"))
  }

  test("restore BIP84 wallet") {
    val account = DeterministicWallet.derivePrivateKey(master, DeterministicWallet.KeyPath("m/84'/2'/0'"))
    // litecoin xpub for BIP84 has not been defined
    val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.xpub)
    assert(xpub == "xpub6CLVqhoT2EVCxNmYcBxrzUjqBy7169wovnSJ2s8t59dWuLZ2vGSHguCJ1g8M8c37kR8WK2sxc94bKzmEDxhneQBicKtjXrjNARgF3aZeBBc")
    assert(deriveAddresses(xpub, Some(BIP84)) == Seq("ltc1qcxlsrf7vgpf02nfqcykstzu0hz8herc5w9f7dk", "ltc1qgnf5dqdte2ls58kaqsz078fuxs9j5alraqyfff", "ltc1qvuwmtqg4xwvlg9nq0wllv7msdpsk7jm8saxrrz", "ltc1qd9tv5x5v08v5m73x7ppmdn0vgke6qc700qcfmv", "ltc1qacgtwhww3t5h7wffkdk0vtwmp6r5gujzr976f6"))
  }
}

object DeriveWalletKeysSpec {
  trait DerivationScheme
  object BIP44 extends DerivationScheme
  object BIP49 extends DerivationScheme
  object BIP84 extends DerivationScheme

  def deriveAddresses(xpub: String, derivationScheme: Option[DerivationScheme] = None) = {
    val (prefix, master) = DeterministicWallet.ExtendedPublicKey.decode(xpub)
    for (i <- 0L until 5L) yield {
      val pub = DeterministicWallet.derivePublicKey(master, 0L :: i :: Nil)
      val address = prefix match {
        case DeterministicWallet.Ltub => computeBIP44Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
        case DeterministicWallet.Mtub => computeBIP49Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
        case DeterministicWallet.xpub if derivationScheme == Some(BIP84) => computeBIP84Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
      }
      address
    }
  }
}
