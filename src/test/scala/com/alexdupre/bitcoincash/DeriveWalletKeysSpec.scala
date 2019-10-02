package com.alexdupre.bitcoincash

import org.scalatest.FunSuite

/**
  * check that we can restore BIP44 wallets and generate valid xpubs and addresses.
  * please note that this test only shows how to derive account keys and addresses. Change keys and addresses can
  * use the same scheme will a different derivation path.
  */
class DeriveWalletKeysSpec extends FunSuite {

  import DeriveWalletKeysSpec._

  val mnemonics = "gun please vital unable phone catalog explain raise erosion zoo truly exist"
  val seed = MnemonicCode.toSeed(mnemonics, "")
  val master = DeterministicWallet.generate(seed)

  test("restore BIP44 wallet") {
    val account = DeterministicWallet.derivePrivateKey(master, DeterministicWallet.KeyPath("m/44'/1'/0'"))
    // some wallets will use tpub instead of upub
    val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.tpub)
    assert(xpub == "tpubDDamug2qVwe94yFJ38MM3ek2LiWiyjMmkQPhYMnHNZz5XHj7bj8xc7pFmyiYnCfqrSy62e1196qcpmKYhcUMcBTGMW4mEWf1v9H8wNtLZku")
    assert(deriveAddresses(xpub) == Seq("bchtest:qpz3f2m6tpkzp7mc3ueamxnzkh7q6wh9ect8fmxs7z", "bchtest:qz8tej8qqm49mck4glprjx94n9e5la2s5ynt67ajgf", "bchtest:qz4rlzr6p0u05m3g3xyws29wwqtfchpg4qj3paqmgw", "bchtest:qp9gs0ph6gqdg246tths4vfvfndzngekvc6qq38nwg", "bchtest:qpj76pa2n03xw48fxfqckycwr6uxra4vavxywhff8x"))
  }
}

object DeriveWalletKeysSpec {

  def deriveAddresses(xpub: String) = {
    val (prefix, master) = DeterministicWallet.ExtendedPublicKey.decode(xpub)
    for (i <- 0L until 5L) yield {
      val pub = DeterministicWallet.derivePublicKey(master, 0L :: i :: Nil)
      val address = prefix match {
        case DeterministicWallet.tpub => computeP2PkhAddress(pub.publicKey, Block.TestnetGenesisBlock.hash)
        case DeterministicWallet.xpub => computeP2PkhAddress(pub.publicKey, Block.LivenetGenesisBlock.hash)
      }
      address
    }
  }
}
