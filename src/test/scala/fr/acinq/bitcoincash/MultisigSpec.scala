package fr.acinq.bitcoincash

import fr.acinq.bitcoincash.Base58.Prefix
import fr.acinq.bitcoincash.Crypto.PrivateKey
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

    // tested with bitcoin core client using command: createmultisig 2 "[\"0394D30868076AB1EA7736ED3BDBEC99497A6AD30B25AFD709CDF3804CD389996A\",\"032C58BC9615A6FF24E9132CEF33F1EF373D97DC6DA7933755BC8BB86DBEE9F55C\",\"02C4D72D99CA5AD12C17C9CFE043DC4E777075E8835AF96F46D8E3CCD929FE1926\"]"
    redeemScript should equal(BinaryData("52210394d30868076ab1ea7736ed3bdbec99497a6ad30b25afd709cdf3804cd389996a21032c58bc9615a6ff24e9132cef33f1ef373d97dc6da7933755bc8bb86dbee9f55c2102c4d72d99ca5ad12c17c9cfe043dc4e777075e8835af96f46d8e3ccd929fe192653ae"))

    // 196 = prefix for P2SH adress on testnet
    Base58Check.encode(Prefix.ScriptAddressTestnet, multisigAddress) should equal("2N8epCi6GwVDNYgJ7YtQ3qQ9vGQzaGu6JY4")
    CashAddr.encodeAddress("bchtest", 8, multisigAddress) should equal("bchtest:pz5sqqa5mhh5her0cc087gt8m2wjxj2yugc32wkgg5")

    // we want to redeem the second output of 80c8d2093c98be31b825d1aaf7827baf5aa5d7de137f3ffaef2871861866c375
    // using our private key 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM
    val txIn = TxIn(
      OutPoint(fromHexString("80c8d2093c98be31b825d1aaf7827baf5aa5d7de137f3ffaef2871861866c375").reverse, 1),
      signatureScript = Array.empty[Byte], // empy signature script
      sequence = 0xFFFFFFFFL)

    // and we want to sent the output to our multisig address
    val txOut = TxOut(
      amount = 900000 satoshi, // 0.009 BTC) satoshi, meaning the fee will be 0.01-0.009 = 0.001
      publicKeyScript = Script.write(OP_HASH160 :: OP_PUSHDATA(multisigAddress) :: OP_EQUAL :: Nil))

    // create a tx with empty)put signature scripts
    val tx = Transaction(version = 1L, txIn = List(txIn), txOut = List(txOut), lockTime = 0L)

    val signData = SignData(
      BinaryData("76a9149cf68a4a7491eba10c977e073baa7dc35d62393788ac"), // PK script of 80c8d2093c98be31b825d1aaf7827baf5aa5d7de137f3ffaef2871861866c375
      Btc(0.01),
      PrivateKey.fromBase58("cRSkzQQkMg2hGMnMq4fDmz3ztqsfjtBgfP5WJ8REFUXmu4ZExCgG", Base58.Prefix.SecretKeyTestnet))

    val signedTx = Transaction.sign(tx, List(signData))

    //this works because signature is not randomized
    assert(signedTx.toString == "010000000175c36618867128effa3f7f13ded7a55aaf7b82f7aad125b831be983c09d2c880010000006a47304402205e7e7f056fa2081ada34640711116545ed197391bff2a5406cd15bdb08bfe7430220209c734b999272ed27c434ba7ab12153fd3b841ae99290b37e34805da3973c434121022adeabf9817a4d34adf1fe8e0fd457a3c0c6378afd63325dbaaaccd4f254002fffffffff01a0bb0d000000000017a914a90003b4ddef4be46fc61e7f2167da9d234944e28700000000")

    // the id of this tx on testnet is 2c99798a8726cd36c27b0bc9c7d760c78913805e82f3975e6a1548430f616070
  }

  test("spend multisig transaction") {
    //this is the P2SH multisig)put transaction
    val previousTx = Transaction.read("010000000175c36618867128effa3f7f13ded7a55aaf7b82f7aad125b831be983c09d2c880010000006a47304402205e7e7f056fa2081ada34640711116545ed197391bff2a5406cd15bdb08bfe7430220209c734b999272ed27c434ba7ab12153fd3b841ae99290b37e34805da3973c434121022adeabf9817a4d34adf1fe8e0fd457a3c0c6378afd63325dbaaaccd4f254002fffffffff01a0bb0d000000000017a914a90003b4ddef4be46fc61e7f2167da9d234944e28700000000")

    val dest = "msCMyGGJ5eRcUgM5SQkwirVQGbGcr9oaYv"
    //priv: 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM
    // 0.008 BTC) satoshi, meaning the fee will be 0.009-0.008 = 0.001
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
    val sig1 = Transaction.signInput(tx, 0, redeemScript, SIGHASH_ALL | SIGHASH_FORKID, previousTx.txOut(0).amount, key1)
    val sig2 = Transaction.signInput(tx, 0, redeemScript, SIGHASH_ALL | SIGHASH_FORKID, previousTx.txOut(0).amount, key2)

    // OP_0 because of a bug) OP_CHECKMULTISIG
    val scriptSig = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(redeemScript) :: Nil
    val signedTx = tx.updateSigScript(0, scriptSig)

    //this works because signature is not randomized
    assert(signedTx.toString == "01000000017060610f4348156a5e97f3825e801389c760d7c7c90b7bc236cd26878a79992c00000000fdfd0000483045022100ee9bf4290bd3233e39d2336ef0bdf9e8d4c40279d0cc57fdd50fde8f3de02d4602200464570453b612859d7400a7ba90a55ae2952455098aaaa92cccbfe103c1c6ad4147304402202d7e006738f8fe39aafb19f44f141be9071513f98287dc3e036df5cd6c61b42a02200f8a30a248c3e7bba34fefa21224fa8a47fa039e937955ad289131a54541b860414c6952210394d30868076ab1ea7736ed3bdbec99497a6ad30b25afd709cdf3804cd389996a21032c58bc9615a6ff24e9132cef33f1ef373d97dc6da7933755bc8bb86dbee9f55c2102c4d72d99ca5ad12c17c9cfe043dc4e777075e8835af96f46d8e3ccd929fe192653aeffffffff0100350c00000000001976a914801d5eb10d2c1513ba1960fd8893f0ddbbe33bb388ac00000000")

    // the id of this tx on testnet is 57eca52cc29953454a5a6b7418de89d6db96f782de2fcf33cc5dda6c8e071c31
    // redeem the tx
    Transaction.correctlySpends(signedTx, List(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
  }
}
