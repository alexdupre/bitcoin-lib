package com.alexdupre.litecoin

import java.nio.ByteOrder

import com.alexdupre.litecoin
import com.alexdupre.litecoin.Crypto.PrivateKey
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class SegwitSpec extends FunSuite {
  val pversion = Protocol.PROTOCOL_VERSION

  test("tx serialization with witness") {
    // see https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Example
    val bin: BinaryData = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
    val tx = Transaction.read(bin, Protocol.PROTOCOL_VERSION)

    assert(tx.txIn.map(_.witness) == Seq(ScriptWitness.empty, ScriptWitness(
      Seq(
        BinaryData("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"),
        BinaryData("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
      )
    )))
    assert(tx.bin == bin)
  }

  test("tx hash") {
    val tx = Transaction.read("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
    val hash: BinaryData = Transaction.hashForSigning(tx, 1, BinaryData("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"), SIGHASH_ALL, 600000000 satoshi, 1)
    assert(hash == BinaryData("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"))

    val priv = PrivateKey(BinaryData("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb901"))
    val pub = priv.publicKey
    val sig = BinaryData("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee")
    assert(Crypto.verifySignature(hash, sig, pub))

    val sigScript = BinaryData("4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01")
    val tx1 = tx.updateSigScript(0, sigScript)
    val tx2 = tx1.updateWitness(1, ScriptWitness((sig :+ SIGHASH_ALL.toByte) :: pub.toBin :: Nil))
    assert(tx2.toString === "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000")
  }

  test("tx verification") {
    val tx = Transaction.read("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000", Protocol.PROTOCOL_VERSION)
    val priv = PrivateKey(BinaryData("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb901"))
    val pub = priv.publicKey
    val pubKeyScript = Script.write(Script.pay2wpkh(pub))
    val runner = new Script.Runner(new Script.Context(tx, 1, 600000000 satoshi), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(runner.verifyScripts(tx.txIn(1).signatureScript, pubKeyScript, tx.txIn(1).witness))
  }

  test("segwit fixes tx malleability") {
    val tx1 = Transaction.read("010000000001011e0e457f710df0284a75773b5a8785bfde6f81ab6f5cbb81bbffdbd13c93cf3a0000000000ffffffff0180d54302000000001600140f66351d05269952302a607b4d6fb69517387a9702483045022100d1fe26c7e00b37b833c3973e7394d82d09934670e7d3995f6d8584dd7ef113930220700b4ce9195ddc086b0eaceb0cf7f7f1c89c8f6a5b1c11c7c8c02f4b3d0612ab012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac01900000000", pversion)
    assert(tx1.hasWitness)
    assert(tx1.txIn.find(!_.signatureScript.isEmpty).isEmpty)
    val tx2 = tx1.updateWitnesses(Seq(ScriptWitness.empty))
    assert(tx2 != tx1)
    assert(tx2.txid == tx1.txid)
  }

  test("tx p2pkh verification") {
    val tx1 = Transaction.read("01000000016e21b8c625d9955e48de0a6bbcd57b03624620a93536ddacabc19d024c330f04010000006a47304402204d34da42ad349a1c93e2bea2933c0bfb3dae6b06b01fa800315231139d3a8f8002204b5984f64b2564ff4fcdb67ae28ba94172681dead36e2ba64532795e30d4a030012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9700000000", Protocol.PROTOCOL_VERSION)
    val tx2 = Transaction.read("0100000000010146cf03f5df6e9a36b1409e66791dea53b22cb330e51239ebd15f12d269e0adc40000000000ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9702483045022100b2b47d485f897c428b284eefc5f0e0bf854aac0ac9de21d5eb4984eec8bd21d702206ab2c763bf8c95e2aa924c628dd696adff659fed9cff1d7ed2bc617206ab06e5012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac01900000000", Protocol.PROTOCOL_VERSION)
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }

  test("create p2wpkh tx") {
    val priv1 = PrivateKey.fromBase58("cQWAJTf9HLiqLm6bjPViJTGAVc6zWvxmoE1ekjR4WjNZqut1yqrz", Base58.Prefix.SecretKeyTestnet)
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.toBin))

    assert(address1 == "mgvNsRy4AAS6y7tW7A3Exuv6k5cTVtAh4q")

    // this is a standard tx that sends 0.4 LTC to mgvNsRy4AAS6y7tW7A3Exuv6k5cTVtAh4q
    val tx1 = Transaction.read("020000000195accd45da052bdfb4d4886ee871624b8c1657bf686026179a7eb02c4c09bccd000000006b483045022100dbf5e12e7d756d5bf740b1c21973b4ead0801901b8fad2696ffd24909e8ea268022003d4e82cc77204ce2709c4d65c66ff6119e63b450489a02fcd7d1fcad39e77e6012102a8702d9b460b15ac880607922fb34d0c790d8f8a7554798674841140ba3bb09bfeffffff0280f0fa02000000001976a914ce1d75f68aa8a10028cc331e699ced17023310fb88ac005a6202000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ac36d60900", pversion)

    // now let's create a simple tx that spends tx1 and send 0.39 LTC to P2WPK output
    val tx2 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 1), sequence = 0xffffffffL, signatureScript = Nil, witness = ScriptWitness.empty) :: Nil,
        txOut = TxOut(0.39 ltc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      Transaction.sign(tmp, Seq(SignData(tx1.txOut(1).publicKeyScript, priv1)))
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == BinaryData("5e61b8897429c3014bb837c0bac1cc6782b0f7d5281127cef37c1dfad6d2d924"))
    // this tx was published on testnet as 5e61b8897429c3014bb837c0bac1cc6782b0f7d5281127cef37c1dfad6d2d924

    // and now we create a segwit tx that spends the P2WPK output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = Nil, witness = ScriptWitness.empty) :: Nil,
        txOut = TxOut(0.38 ltc, Script.pay2wpkh(pub1)) :: Nil, // we reuse the same output script but if could be anything else
        lockTime = 0
      )
      // mind this: the pubkey script used for signing is not the prevout pubscript (which is just a push
      // of the pubkey hash), but the actual script that is evaluated by the script engine, in this case a PAY2PKH script
      val pubKeyScript = Script.pay2pkh(pub1)
      val sig = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)
      val witness = ScriptWitness(Seq(sig, pub1.toBin))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == BinaryData("6af95097a6157ca1a90fadf4fe417144b5e86247f363990c3fed066ad71038f4"))
    // this tx was published on testnet as 6af95097a6157ca1a90fadf4fe417144b5e86247f363990c3fed066ad71038f4
  }

  test("create p2wsh tx") {
    val priv1 = PrivateKey.fromBase58("cQWAJTf9HLiqLm6bjPViJTGAVc6zWvxmoE1ekjR4WjNZqut1yqrz", Base58.Prefix.SecretKeyTestnet)
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.toBin))

    assert(address1 == "mgvNsRy4AAS6y7tW7A3Exuv6k5cTVtAh4q")

    val priv2 = PrivateKey.fromBase58("cTnvMLGakZXFpsX3st5kJn87YAJtLMNPmoEioUemtiJJgbF6dpHj", Base58.Prefix.SecretKeyTestnet)
    val pub2 = priv2.publicKey

    val priv3 = PrivateKey.fromBase58("cW1EgBmugeNPWdH8xZzohCwkiP965zoy4VCE8UNZqq6epWKeaCu3", Base58.Prefix.SecretKeyTestnet)
    val pub3 = priv3.publicKey

    // this is a standard tx that sends 0.5 LTC to mgvNsRy4AAS6y7tW7A3Exuv6k5cTVtAh4q
    val tx1 = Transaction.read("0200000001e48e3cb131584ce1bc157919e46f00351cb1508f07962cb8212aac8461e7c30c000000006b483045022100c89163c7d9b0639d16b6b06b45d58deb410734642e53dbf100fe871b9ce16c3c022024ade2c7191534ccdaa6e46cd449b7a0c34483e2a647af2095b82bc2fcb66057012102412975093984240a43f052b8e66ea8b1e403f3e5b1ae6667b9a236fa0d94547cfeffffff0280f0fa02000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ac784137e1000000001976a91411ba40021db6657d9c6296305a21fc768d536f9188ac3ad60900", pversion)

    // now let's create a simple tx that spends tx1 and send 0.49 LTC to a P2WSH output
    val tx2 = {
      // our script is a 2-of-2 multisig script
      val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.49 ltc, Script.pay2wsh(redeemScript)) :: Nil,
        lockTime = 0
      )
      Transaction.sign(tmp, Seq(SignData(tx1.txOut(0).publicKeyScript, priv1)))
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == BinaryData("852e99626ab08c8275237c365e4f74db70bb649f1b6b03bc15dd7455f2f0f059"))
    // this tx was published on testnet as 852e99626ab08c8275237c365e4f74db70bb649f1b6b03bc15dd7455f2f0f059

    // and now we create a segwit tx that spends the P2WSH output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.48 ltc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
      val sig2 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv2)
      val sig3 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv3)
      val witness = ScriptWitness(Seq(BinaryData.empty, sig2, sig3, pubKeyScript))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == BinaryData("03b9f14d03b3310dbc6da003aac6e1ac18558770979823b5fc3977821affa125"))
    // this tx was published on testnet as 03b9f14d03b3310dbc6da003aac6e1ac18558770979823b5fc3977821affa125
  }

  test("create p2pkh embedded in p2sh") {
    val priv1 = PrivateKey.fromBase58("cQWAJTf9HLiqLm6bjPViJTGAVc6zWvxmoE1ekjR4WjNZqut1yqrz", Base58.Prefix.SecretKeyTestnet)
    val pub1 = priv1.publicKey

    // p2wpkh script
    val script = Script.write(Script.pay2wpkh(pub1))

    // which we embeed into a standard p2sh script
    val p2shaddress = Base58Check.encode(Base58.Prefix.ScriptAddress2Testnet, Crypto.hash160(script))
    assert(p2shaddress === "QSJCEZ5XH2HjXm6q1oLuiuL8LZysdne6xe")

    // this tx send 0.5 ltc to our p2shaddress
    val tx = Transaction.read("020000000153512bd8673158d1039ed640c907f00b70c82bfef4291c0c1f78ed02bc75685f010000006b483045022100d254fc0154d06d305e8653a932cb3a6f933f75e45b420bacc4d59d0a9f4e577d022054fb3cef7b280d0dffd75672a34b0b216f348494422805a9fd43ced2dfb386c00121034d1701328d5d2aaa8d0fd3209b695eb55b0e4ad96d5ea780f2a2e9eb956a3161feffffff025d845d9d000000001976a9146692e8f801c04912300d739d2e55517220ca2d8f88ac80f0fa020000000017a9143e73638f202bb880a28e8df1946adc3058227d11873ed60900", pversion)

    // let's spend it:

    val tx1 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx.hash, 1), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.49 ltc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1.toBin)) :: Nil) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.pay2pkh(pub1)
      val sig = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx.txOut(1).amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)
      val witness = ScriptWitness(Seq(sig, pub1.toBin))
      tmp.updateSigScript(0, OP_PUSHDATA(script) :: Nil).updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx1, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx1.txid === BinaryData("4b74ab021f51c7af226aebfa10d8b84e2bb4252ea7db93a32b181b50cdd1bd79"))
    // this tx was published on testnet as 4b74ab021f51c7af226aebfa10d8b84e2bb4252ea7db93a32b181b50cdd1bd79
  }

  test("check block witness commitment (segwit block)") {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/000000000001e5cc02215a70dc832f3d66c724ce1f9662f83ef36f1e9e4a0371.block")
    val block = Block.read(stream)
    val coinbase = block.tx.head
    assert(Block.witnessReservedValue(coinbase).isDefined && Block.witnessCommitment(coinbase).isDefined && Block.checkWitnessCommitment(block))
  }

  test("check block witness commitment (non-segwit block)") {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/block413567.raw")
    val block = Block.read(stream)
    val coinbase = block.tx.head
    assert(!Block.witnessReservedValue(coinbase).isDefined && !Block.witnessCommitment(coinbase).isDefined && Block.checkWitnessCommitment(block))
  }
}
