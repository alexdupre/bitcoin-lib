package fr.acinq.bitcoincash.samples

import fr.acinq.bitcoincash._

object KeysFromXpub extends App {
  /**
    * this is how you would derive pubkeys and addresses from an xpub that someone gave you
    * we currently support CashAddr (p2pkh and p2sh)
    *
    */

  def deriveAddresses(xpub: String) = {
    val (prefix, master) = DeterministicWallet.ExtendedPublicKey.decode(xpub)
    prefix match {
      case DeterministicWallet.tpub =>
        for (i <- 0L to 5L) {
          val pub = DeterministicWallet.derivePublicKey(master, 0L :: i :: Nil)
          val address = CashAddr.encodeAddress("bchtest", 0, pub.publicKey.hash160)
          println(s"$pub $address")
        }
      case DeterministicWallet.xpub =>
        for (i <- 0L to 5L) {
          val pub = DeterministicWallet.derivePublicKey(master, 0L :: i :: Nil)
          val address = CashAddr.encodeAddress("bitcoincash", 0, pub.publicKey.hash160)
          println(s"$pub $address")
        }
    }
  }

  deriveAddresses("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5e4cp9LB")
  deriveAddresses("tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLNGbhd2pq7ZtDiPYTfJ7iBenLVQpYgSQqPjUsQeJXH8VQ8xA67D")
}
