package com.alexdupre.litecoin.samples

import com.alexdupre.litecoin._

object KeysFromXpub extends App {
  /**
    * this is how you would derive pubkeys and addresses from an xpub that someone gave you
    * we currently support BIP22 (p2pkh) and BIP49 (p2sh-of-p2wpkh)
    *
    */

  def deriveAddresses(xpub: String) = {
    val (prefix, master) = DeterministicWallet.ExtendedPublicKey.decode(xpub)
    prefix match {
      case DeterministicWallet.Ltub =>
        for (i <- 0L to 5L) {
          val pub = DeterministicWallet.derivePublicKey(master, 0L :: i :: Nil)
          val address = computeP2PkhAddress(pub.publicKey, Block.LivenetGenesisBlock.hash)
          println(s"$pub $address")
        }
      case DeterministicWallet.Mtub =>
        for (i <- 0L to 5L) {
          val pub = DeterministicWallet.derivePublicKey(master, 0L :: i :: Nil)
          val address = computeP2ShOfP2WpkhAddress(pub.publicKey, Block.LivenetGenesisBlock.hash)
          println(s"$pub $address")
        }
    }
  }

  deriveAddresses("Ltub2ZZJYd2XtS31eoYGHkGa5Q7w7J2UC6e514p3XfBSgySGP2JVjUsuBS1CHp1gzhgBJJ9VRDqnRyfc6r8GDwt8rvHTpQvMVhXv4EPdc8H4bBz")
  deriveAddresses("Mtub2tn1XXJTsCHjpEiA2rh7YhMrQHcdEbTXTkZDMqHMFV6PDuXpmpAkhN1Yu1tuQgoVQV9YQfY1irr3P2gQkfnQPznb5WN1PHEs1dGJcZxQLfg")
}
