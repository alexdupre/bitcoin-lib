package com.alexdupre.litecoin

import com.alexdupre.litecoin.Base58.Prefix
import com.alexdupre.litecoin.Crypto.PrivateKey
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.{FlatSpec, FunSuite, Matchers}

@RunWith(classOf[JUnitRunner])
class MultisigSpec extends FunSuite with Matchers {
  val key1 = PrivateKey(BinaryData("C0B91A94A26DC9BE07374C2280E43B1DE54BE568B2509EF3CE1ADE5C9CF9E8AA01"))
  val pub1 = key1.publicKey

  val key2 = PrivateKey(BinaryData("5C3D081615591ABCE914D231BA009D8AE0174759E4A9AE821D97E28F122E2F8C01"))
  val pub2 = key2.publicKey

  val key3 = PrivateKey(BinaryData("29322B8277C344606BA1830D223D5ED09B9E1385ED26BE4AD14075F054283D8C01"))
  val pub3 = key3.publicKey

  val redeemScript: BinaryData = Script.write(Script.createMultiSigMofN(2, List(pub1, pub2, pub3)))
  val multisigAddress = Crypto.hash160(redeemScript)

  test("create and sign multisig transactions") {

    // tested with litecoin core client using command: createmultisig 2 "[\"0394D30868076AB1EA7736ED3BDBEC99497A6AD30B25AFD709CDF3804CD389996A\",\"032C58BC9615A6FF24E9132CEF33F1EF373D97DC6DA7933755BC8BB86DBEE9F55C\",\"02C4D72D99CA5AD12C17C9CFE043DC4E777075E8835AF96F46D8E3CCD929FE1926\"]"
    redeemScript should equal(BinaryData("52210394d30868076ab1ea7736ed3bdbec99497a6ad30b25afd709cdf3804cd389996a21032c58bc9615a6ff24e9132cef33f1ef373d97dc6da7933755bc8bb86dbee9f55c2102c4d72d99ca5ad12c17c9cfe043dc4e777075e8835af96f46d8e3ccd929fe192653ae"))

    // 58 = prefix for P2SH adress on testnet
    Base58Check.encode(Prefix.ScriptAddress2Testnet, multisigAddress) should equal("Qc1aKixWxbGTgs4AAzS4v6bMQoSQBG4sCo")

    // we want to redeem the second output of 7c69ae71a68c0b76672ec008bb2d81d79985019609862dee3f807b4c2344f4ef
    // using our private key 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM
    val txIn = TxIn(
      OutPoint(fromHexString("7c69ae71a68c0b76672ec008bb2d81d79985019609862dee3f807b4c2344f4ef").reverse, 1),
      signatureScript = Array.empty[Byte], // empy signature script
      sequence = 0xFFFFFFFFL)

    // and we want to sent the output to our multisig address
    val txOut = TxOut(
      amount = 900000 satoshi, // 0.009 LTC) satoshi, meaning the fee will be 0.01-0.009 = 0.001
      publicKeyScript = Script.write(OP_HASH160 :: OP_PUSHDATA(multisigAddress) :: OP_EQUAL :: Nil))

    // create a tx with empty)put signature scripts
    val tx = Transaction(version = 1L, txIn = List(txIn), txOut = List(txOut), lockTime = 0L)

    val signData = SignData(
      BinaryData("76a914298e5c1e2d2cf22deffd2885394376c7712f9c6088ac"), // PK script of 7c69ae71a68c0b76672ec008bb2d81d79985019609862dee3f807b4c2344f4ef
      PrivateKey.fromBase58("92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM", Base58.Prefix.SecretKeyTestnet))

    val signedTx = Transaction.sign(tx, List(signData))

    //this works because signature is not randomized
    assert(signedTx.toString == "0100000001eff444234c7b803fee2d860996018599d7812dbb08c02e67760b8ca671ae697c010000008a4730440220150cdf1074dd9a9ca227d1317ab7932015791d25b4ab73372735cad1f7b426df02200e7b3fdd75a18bfe48dee848876532ecd5f695432da0ba993144fd6f96f26c590141042adeabf9817a4d34adf1fe8e0fd457a3c0c6378afd63325dbaaaccd4f254002f9cc4148f603beb0e874facd3a3e68f5d002a65c0d3658452a4e55a57f5c3b768ffffffff01a0bb0d000000000017a914a90003b4ddef4be46fc61e7f2167da9d234944e28700000000")

    // the id of this tx on testnet is a6abde4d8a406c56310bc1ac63b888da09a8336d13b12c4896e8b4aa927d8556
  }

  test("spend multisig transaction") {
    //this is the P2SH multisig)put transaction
    val previousTx = Transaction.read("0100000001eff444234c7b803fee2d860996018599d7812dbb08c02e67760b8ca671ae697c010000008a4730440220150cdf1074dd9a9ca227d1317ab7932015791d25b4ab73372735cad1f7b426df02200e7b3fdd75a18bfe48dee848876532ecd5f695432da0ba993144fd6f96f26c590141042adeabf9817a4d34adf1fe8e0fd457a3c0c6378afd63325dbaaaccd4f254002f9cc4148f603beb0e874facd3a3e68f5d002a65c0d3658452a4e55a57f5c3b768ffffffff01a0bb0d000000000017a914a90003b4ddef4be46fc61e7f2167da9d234944e28700000000")

    val dest = "mjJgYFgBNmQtJ2kMEEM3ZnmSJiMNDHwp93"
    //priv: 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM
    // 0.008 LTC) satoshi, meaning the fee will be 0.009-0.008 = 0.001
    val amount = 800000 satoshi

    // create a tx with empty)put signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = List(TxIn(OutPoint(previousTx, 0), Array.empty[Byte], 0xffffffffL)),
      txOut = List(TxOut(
        amount = amount,
        publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(dest)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)),
      lockTime = 0L
    )

    // we only need 2 signatures because this is a 2-on-3 multisig
    val sig1 = Transaction.signInput(tx, 0, redeemScript, SIGHASH_ALL, 0 satoshi, SigVersion.SIGVERSION_BASE, key1)
    val sig2 = Transaction.signInput(tx, 0, redeemScript, SIGHASH_ALL, 0 satoshi, SigVersion.SIGVERSION_BASE, key2)

    // OP_0 because of a bug) OP_CHECKMULTISIG
    val scriptSig = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(redeemScript) :: Nil
    val signedTx = tx.updateSigScript(0, scriptSig)

    //this works because signature is not randomized
    assert(signedTx.toString == "010000000156857d92aab4e896482cb1136d33a809da88b863acc10b31566c408a4ddeaba600000000fdfd000047304402203ba46797cfb144dea95845cf67ceece129b32fd14df6ad19409f79846ab15295022068be4d76cfb3aa597e507383e42162ec67944a4b947b6a26f63fd83d0c8d185101483045022100efb972abb3a38bb67f91f1e7b628866eeac2ee83681180b4d4380f38159deb1602200df7115341e83e11df05e8f7b12368610bdad2ccc658637dd37318361afae644014c6952210394d30868076ab1ea7736ed3bdbec99497a6ad30b25afd709cdf3804cd389996a21032c58bc9615a6ff24e9132cef33f1ef373d97dc6da7933755bc8bb86dbee9f55c2102c4d72d99ca5ad12c17c9cfe043dc4e777075e8835af96f46d8e3ccd929fe192653aeffffffff0100350c00000000001976a914298e5c1e2d2cf22deffd2885394376c7712f9c6088ac00000000")

    // the id of this tx on testnet is 3f4a6df4337caabfa57cb4c96106dc695124057e97f61475e6646eb86e1d226e
    // redeem the tx
    Transaction.correctlySpends(signedTx, List(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
  }
}
