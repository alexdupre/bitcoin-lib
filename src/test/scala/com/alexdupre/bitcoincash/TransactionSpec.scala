package com.alexdupre.bitcoincash

import java.io.ByteArrayOutputStream

import com.alexdupre.bitcoincash.Crypto._
import com.alexdupre.bitcoincash.Protocol._
import org.scalatest.{FunSuite, Matchers}

class TransactionSpec extends FunSuite with Matchers {
  test("create and sign transaction") {
    val srcTx = fromHexString("dcd82df7b26f0eacd226b8fbd366672c854284ba8080f79e1307138c7f1a1f6d".sliding(2, 2).toList.reverse.mkString(""))
    // for some reason it has to be reversed
    val amount = 9000000
    // amount) satoshi
    val vout = 0
    // output)dex
    val destAdress = fromHexString("76a914c622640075eaeda95a5ac26fa05a0b894a3def8c88ac")
    val out = new ByteArrayOutputStream()
    writeUInt32(1, out) //version
    writeVarint(1, out) // nb of)puts
    out.write(srcTx) // tx) id
    writeUInt32(vout, out)
    writeScript(fromHexString("76a914ea2902457015b386bd2323b2b99591b96138d62a88ac"), out) //scriptPubKey of prev tx for signing
    writeUInt32(0xffffffff, out) // sequence
    writeVarint(1, out) // number of outputs
    writeUInt64(amount, out)
    writeScript(destAdress, out) //output script
    writeUInt32(0, out)
    writeUInt32(1, out)
    // hash code type
    val serialized = out.toByteArray
    val hashed = Crypto.hash256(serialized)
    val pkey_encoded = Base58.decode("92f9274aR3s6zd1vuAgxquv4KP5S5thJadF3k54NHuTV4fXL1vW")
    val pkey = PrivateKey(pkey_encoded.slice(1, pkey_encoded.size - 4))
    val (r, s) = Crypto.sign(hashed, pkey)
    val sig = Crypto.encodeSignature(r, s)
    // DER encoded
    val sigOut = new ByteArrayOutputStream()
    writeUInt8(sig.length + 1, sigOut) // +1 because of the hash code
    sigOut.write(sig.toArray)
    writeUInt8(1, sigOut)
    // hash code type
    val pub = pkey.publicKey
    writeUInt8(pub.length, sigOut)
    sigOut.write(pub.toBin)
    val sigScript = sigOut.toByteArray

    val signedOut = new ByteArrayOutputStream()
    writeUInt32(1, signedOut) //version
    writeVarint(1, signedOut) // nb of)puts
    signedOut.write(srcTx) // tx) id
    writeUInt32(vout, signedOut) // output)dex
    writeScript(sigScript, signedOut)
    writeUInt32(0xffffffff, signedOut) // sequence
    writeVarint(1, signedOut) // number of outputs
    writeUInt64(amount, signedOut) // amount) satoshi
    writeScript(destAdress, signedOut) //output script
    writeUInt32(0, signedOut)
    assert(toHexString(signedOut.toByteArray) === "01000000016d1f1a7f8c1307139ef78080ba8442852c6766d3fbb826d2ac0e6fb2f72dd8dc000000008b483045022100bdd23d0f98a4173a64fa432b8bf4ac41261a671f2c6c690d57ac839866d78bb202207bddb87ca95c9cef45de30a75144e5513571aa7938635b9e051b1c20f01088a60141044aec194c55c97f4519535f50f5539c6915045ecb79a36281dee6db55ffe1ad2e55f4a1c0e0950d3511e8f205b45cafa348a4a2ab2359246cb3c93f6532c4e8f5ffffffff0140548900000000001976a914c622640075eaeda95a5ac26fa05a0b894a3def8c88ac00000000")
  }
  test("read and write transactions") {
    val hex = BinaryData("0100000003864d5e5ec82c9e6f4ac52b8fa47b77f8616bbc26fcf668432c097c5add169584010000006a47304402203be0cff1faacadce3b02d615a8ac15532f9a90bd30e109eaa3e01bfa3a97d90b0220355f3bc382e35b9cae24e5d674f200b289bb948675ce1b5c931029ccb23ae836012102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffffd587b10688e6d56225dd4dc488b74229a353e4613cbe1deadaef52b56616baa9000000008b483045022100ab98145e8526b32e821beeaed41a98da68c3c75ee13c477ee0e3d66a626217e902204d015af2e7dba834bbe421dd0b1353a1060dafee58c284dd763e07639858f9340141043ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87d53dfcba3525369fdb248e60233fdf6df0a8183a6dd5699c9a6f5c537367c627ffffffff94a162b4aab080a09fa982a5d7f586045ba2a4c653c98ff47b952d43c25b45fd000000008a47304402200e0c0223d169282a48731b58ff0673c00205deb3f3f4f28d99b50730ada1571402202fa9f051762d8e0199791ea135df1f393578c1eea530bec00fa16f6bba7e3aa3014104626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c21364ed5dbe97c9c6e2be40fff40c31f8561a9dee015146fe59ecf68b8a377292c72ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000")
    val tx = Transaction.read(hex)
    assert(tx.bin === hex)
  }
  test("create and verify pay2pk transactions with 1)put/1 output using helper method") {
    val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
    val (Base58.Prefix.PubkeyAddressTestnet, pubkeyHash) = Base58Check.decode(to)
    val amount = 10000 satoshi

    val privateKey = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)
    val publicKey = privateKey.publicKey

    val previousTx = Transaction.read("0100000001b021a77dcaad3a2da6f1611d2403e1298a902af8567c25d6e65073f6b52ef12d000000006a473044022056156e9f0ad7506621bc1eb963f5133d06d7259e27b13fcb2803f39c7787a81c022056325330585e4be39bcf63af8090a2deff265bc29a3fb9b4bf7a31426d9798150121022dfb538041f111bb16402aa83bd6a3771fa8aa0e5e9b0b549674857fafaf4fe0ffffffff0210270000000000001976a91415c23e7f4f919e9ff554ec585cb2a67df952397488ac3c9d1000000000001976a9148982824e057ccc8d4591982df71aa9220236a63888ac00000000")

    // create a transaction where the sig script is the pubkey script of the tx we want to redeem
    // the pubkey script is just a wrapper around the pub key hash
    // what it means is that we will sign a block of data that contains txid + from + to + amount

    // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
    val tx1 = Transaction(
      version = 1L,
      txIn = List(
        TxIn(OutPoint(previousTx, 0), signatureScript = Nil, sequence = 0xFFFFFFFFL)
      ),
      txOut = List(
        TxOut(amount = amount, publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(pubkeyHash) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)
      ),
      lockTime = 0L
    )

    // step #2: sign the tx
    val sig = Transaction.signInput(tx1, 0, previousTx.txOut(0).publicKeyScript, SIGHASH_ALL | SIGHASH_FORKID, previousTx.txOut(0).amount, privateKey)
    val tx2 = tx1.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKey) :: Nil)

    // redeem the tx
    Transaction.correctlySpends(tx2, Seq(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
  }
  test("create and verify sign pay2pk transactions with multiple)puts and outputs") {
    val destAddress = "moKHwpsxovDtfBJyoXpof21vvWooBExutV"
    val destAmount = 3000000 satoshi

    val changeAddress = "mvHPesWqLXXy7hntNa7vbAoVwqN5PnrwJd"
    val changeAmount = 1700000 satoshi

    val previousTx = List(
      Transaction.read("010000000185ed8465b8557e289d3a8a2d3341fba3c92c9919a2b44d7f5f5bcfcfbbd1e674010000006b483045022100f4d1c1ab04ce0933aa18f498bf1abbf685dc5976a28e2260265ad8c18be48f26022054883edf665f4471a51770718ab9ef4aaadcd3c4190ae5910356a4739febe9f6412102634ebfb0857320917adc0d0446661ff02d3b0d5e91a10f3365b62e2e3a45e892ffffffff0200093d00000000001976a9145dbf52b8d7af4fb5f9b75b808f0a8284493531b388ac79e7284d000000001976a914183f7d4f7485ea41a140c0f32fa564457041f24288ac00000000"),
      Transaction.read("010000000175c36618867128effa3f7f13ded7a55aaf7b82f7aad125b831be983c09d2c880000000006b483045022100b8824205e7d1285050ee13e102c29ab03d7adfbb673a3b347af812ac8660f09402207e44ae58ebc5f0e22891649d330c2621d77586b4402d2101f917e7949756892e412102634ebfb0857320917adc0d0446661ff02d3b0d5e91a10f3365b62e2e3a45e892ffffffff0200350c00000000001976a9145fc793d82edae38c515d5d850adb9bc3bb4a7b8488ac3cc20947000000001976a914183f7d4f7485ea41a140c0f32fa564457041f24288ac00000000")
    )

    val keys = List(
      SignData(previousTx(0).txOut(0), PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)),
      SignData(previousTx(1).txOut(0), PrivateKey.fromBase58("cVT1dyeGzwS91dZyz5Y8K7zZRKNdRSf2ommiUcJEMFX2dTUMxZAs", Base58.Prefix.SecretKeyTestnet))
    )

    // create a tx with empty)put signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = previousTx.map(tx => TxIn(OutPoint(tx, 0), sequence = 0xFFFFFFFFL, signatureScript = Array.empty[Byte])),
      txOut = List(
        TxOut(
          amount = destAmount,
          publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(destAddress)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
        TxOut(
          amount = changeAmount,
          publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(changeAddress)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)),
      lockTime = 0L
    )

    val tx1 = Transaction.sign(tx, keys)
    assert(tx1.toString == "0100000002add043418d241be9cd7e56f00e4a54adb4109db979b92f80e2482a8460bd44de000000006b483045022100a04bcf1a022f28a8e2cb575dc475a22345b71a54eae737d0b923ef5bde93472502200fdd6dcb13f0cb46a3eae5c3944b3b924ce59dfd04967b693dd1bda2c587972b4121030533e1d2e9b7576fef26de1f34d67887158b7af1b040850aab6024b07925d70affffffff133ad6f9b785d47c70b3d22a63f3d082fd9dfca47500211ce1def22fa50cebcf000000006b4830450221009c5b787074e6c45a60b193f53e9c027fa6f8044e4cf3141f3e971902055c5ac3022062d6f56924d3d07b55ee2c34a682ef7a4c942925da0084cb366dad3aa4825dbd4121020081a4cce4c497d51d2f9be2d2109c00cbdef252185ca23074889604ace3504dffffffff02c0c62d00000000001976a914558c6b340f5abd22bf97b15cbc1483f8f1b54f5f88aca0f01900000000001976a914a1f93b5b00f9f5e8ade5549b58ed06cdc5c8203e88ac00000000")

    // now check that we can redeem this tx
    Transaction.correctlySpends(tx1, previousTx, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
    // the id of this tx on testnet is d63afc1b466e459dabc5ff8968022493eca4d261aad545cb8002fdf954a91242
  }

  test("create and sign p2sh transactions") {

    val key1 = PrivateKey(BinaryData("C0B91A94A26DC9BE07374C2280E43B1DE54BE568B2509EF3CE1ADE5C9CF9E8AA01"))
    val pub1 = key1.publicKey
    val key2 = PrivateKey(BinaryData("5C3D081615591ABCE914D231BA009D8AE0174759E4A9AE821D97E28F122E2F8C01"))
    val pub2 = key2.publicKey
    val key3 = PrivateKey(BinaryData("29322B8277C344606BA1830D223D5ED09B9E1385ED26BE4AD14075F054283D8C01"))
    val pub3 = key3.publicKey

    // we want to spend the first output of this tx
    val previousTx = Transaction.read("0100000001bf9007c6413c46242795a6a5c2aa93dfea7010a30e717a94840198a238390d2e000000006b483045022100ffbc45efce03a48d7ee7eaf822c15578b2a1ee0a8834b27bde0e28c146da047e022054a970f6e3b77251d9192cf3953d22f9cc25e3f04b2c74e337d69ebea47a613a412102634ebfb0857320917adc0d0446661ff02d3b0d5e91a10f3365b62e2e3a45e892ffffffff020b101647000000001976a914183f7d4f7485ea41a140c0f32fa564457041f24288ac40420f00000000001976a9149cf68a4a7491eba10c977e073baa7dc35d62393788ac00000000")
    val privateKey = PrivateKey.fromBase58("cRSkzQQkMg2hGMnMq4fDmz3ztqsfjtBgfP5WJ8REFUXmu4ZExCgG", Base58.Prefix.SecretKeyTestnet)
    val publicKey = privateKey.publicKey

    // create and serialize a "2 out of 3" multisig script
    val redeemScript = Script.write(Script.createMultiSigMofN(2, Seq(pub1, pub2, pub3)))

    // the multisig adress is just that hash of this script
    val multisigAddress = Crypto.hash160(redeemScript)

    // we want to send money to our multisig adress by redeeming the second output
    // of 80c8d2093c98be31b825d1aaf7827baf5aa5d7de137f3ffaef2871861866c375
    // using our private key 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM

    // create a tx with empty)put signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = TxIn(OutPoint(previousTx.hash, 1), signatureScript = Nil, sequence = 0xFFFFFFFFL) :: Nil,
      txOut = TxOut(
        amount = 900000 satoshi, // 0.009 BTC) satoshi, meaning the fee will be 0.01-0.009 = 0.001
        publicKeyScript = OP_HASH160 :: OP_PUSHDATA(multisigAddress) :: OP_EQUAL :: Nil) :: Nil,
      lockTime = 0L)

    // and sign it
    val sig = Transaction.signInput(tx, 0, previousTx.txOut(1).publicKeyScript, SIGHASH_ALL | SIGHASH_FORKID, previousTx.txOut(1).amount, privateKey)
    val signedTx = tx.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(privateKey.publicKey) :: Nil)
    Transaction.correctlySpends(signedTx, previousTx :: Nil, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // how to spend our tx ? let's try to sent its output to our public key
    val spendingTx = Transaction(version = 1L,
      txIn = TxIn(OutPoint(signedTx.hash, 0), signatureScript = Array.emptyByteArray, sequence = 0xFFFFFFFFL) :: Nil,
      txOut = TxOut(
        amount = 900000 satoshi,
        publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Crypto.hash160(publicKey.toBin)) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil) :: Nil,
      lockTime = 0L)

    // we need at least 2 signatures
    val sig1 = Transaction.signInput(spendingTx, 0, redeemScript, SIGHASH_ALL | SIGHASH_FORKID, spendingTx.txOut(0).amount, key1)
    val sig2 = Transaction.signInput(spendingTx, 0, redeemScript, SIGHASH_ALL | SIGHASH_FORKID, spendingTx.txOut(0).amount, key2)

    // update our tx with the correct sig script
    val sigScript = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(redeemScript) :: Nil
    val signedSpendingTx = spendingTx.updateSigScript(0, sigScript)
    Transaction.correctlySpends(signedSpendingTx, signedTx :: Nil, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }

  test("sign a 3-to-2 transaction with helper method") {

    val previousTx = List(
      Transaction.read("0100000001133ad6f9b785d47c70b3d22a63f3d082fd9dfca47500211ce1def22fa50cebcf010000006b48304502210095b708c2c0c51aa67bf287cc30cd189ce7307a95a89afe092db555969b4248ee022071dd7a0c32c647010de96c29bc13978c108ef3515ea9a3080b87b2bc0e8c121f412102634ebfb0857320917adc0d0446661ff02d3b0d5e91a10f3365b62e2e3a45e892ffffffff022d67fa46000000001976a914183f7d4f7485ea41a140c0f32fa564457041f24288ac40420f00000000001976a9148c9648cab53a1fb8861daff0f2378c7b9e81a3ab88ac00000000"),
      Transaction.read("0100000001add043418d241be9cd7e56f00e4a54adb4109db979b92f80e2482a8460bd44de010000006a47304402203f135ec6706412e0856928c0e39568a911a1ab61824fc5a83d08b59a104db549022059f369ba3f62847c3bd0ae2f562fde5db0622ea61ef6123561222ea7471d915b412102634ebfb0857320917adc0d0446661ff02d3b0d5e91a10f3365b62e2e3a45e892ffffffff026ac1254d000000001976a914183f7d4f7485ea41a140c0f32fa564457041f24288ac400d0300000000001976a9148c50ea26715c99286a6a1f254f6a85a13a04641088ac00000000"),
      Transaction.read("010000000102c1e4aaea5bdb754920f73374c2585cd57648522d101bbf73a54b279704cc62000000006b483045022100c4c009e3bbc06c01a3b068219de6c7d79287029b56372a6002fdb8a9fd9d118c022011e3ded444792496a2dfe445ce634c91e242be81d8db19a0f099b59c63800f85412102634ebfb0857320917adc0d0446661ff02d3b0d5e91a10f3365b62e2e3a45e892ffffffff0240548900000000001976a9146df6231fb2939e34a0163a3101e4dcabc99a90c888ac1efa7046000000001976a914183f7d4f7485ea41a140c0f32fa564457041f24288ac00000000")
    )
    val keys = List(
      SignData(previousTx(0).txOut(1), PrivateKey.fromBase58("cW6bSKtH3oMPA18cXSMR8ASHztrmbwmCyqvvN8x3Tc7WG6TyrJDg", Base58.Prefix.SecretKeyTestnet)),
      SignData(previousTx(1).txOut(1), PrivateKey.fromBase58("cUZhjne5TueaNvkBEKjVRpQmWcZ6hTQwghGcCNmqJp7zgQbUTUZg", Base58.Prefix.SecretKeyTestnet)),
      SignData(previousTx(2).txOut(0), PrivateKey.fromBase58("cPV6PecF7PAAekYR3FvkCUGL1MXBiWfujh1AUeFazLgvAV9YXZW8", Base58.Prefix.SecretKeyTestnet))
    )

    val dest1 = "n2Jrcf7cJH7wMJdhKZGVi2jaSnV2BwYE9m"
    //priv: 926iWgQDq5dN84BJ4q2fu4wjSSaVWFxwanE8EegzMh3vGCUBJ94
    val dest2 = "mk6kmMF5EEXksBkZxi7FniwwRgWuZuwDpo"
    //priv: 91r7coHBdzfgfm2p3ToJ3Bu6kcqL3BvSo5m4ENzMZzsimRKH8aq
    // 0.03 and 0.07 BTC) satoshi, meaning the fee will be (0.01+0.002+0.09)-(0.03+0.07) = 0.002
    val amount1 = 3000000 satoshi
    val amount2 = 7000000 satoshi

    // create a tx with empty)put signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = List(
        TxIn(OutPoint(previousTx(0), 1), Array.empty[Byte], 0xffffffffL),
        TxIn(OutPoint(previousTx(1), 1), Array.empty[Byte], 0xffffffffL),
        TxIn(OutPoint(previousTx(2), 0), Array.empty[Byte], 0xffffffffL)
      ),
      txOut = List(TxOut(
        amount = amount1,
        publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(dest1)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
        TxOut(
          amount = amount2,
          publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(dest2)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)),
      lockTime = 0L
    )

    val signedTx = Transaction.sign(tx, keys)

    //this works because signature is not randomized
    assert(signedTx.toString == "010000000302c1e4aaea5bdb754920f73374c2585cd57648522d101bbf73a54b279704cc62010000006a4730440220612ea271d3a7fdd6fc997bf3417c7764852f78697bdb41f835c9260c0b894438022049ca9fd20be8537d60ba79311e16c3e0312cff8dc96778c93017698fd01ae49d412102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffff392a94c979f97d9c85f05a94dc8dcc066326a5023e66fc47df41ec2f411f6520010000006b483045022100e9c93e3a6249c580782efdbe124839bbcf075e4c74d7ccb5fc0fb8370d5d7457022076afe4501bc403b4019ecf14c9701944dff028e7d68abb4bc6231373b69e83ca4121033ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87ffffffff62bd55624ac17b1fdc5484a1157fd3485407740cede4f55e3493f9296ffa6075000000006a473044022007615fe76ecb10d7128ed9429f40c1365a3f68d73b05075368681400228c0ef102204de0111c7f03fb3431c0cb9d00446d93e50f8264b80abdc7d12dedc256d754ea412102626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c2136ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000")

    // the id of this tx on testnet is fc3e5f07486fbab1dc48c6b45c0a0693639ee85648ad545624744ffb581fb233

    // redeem tx
    Transaction.correctlySpends(signedTx, previousTx, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
  }

  test("compute tx size") {
    val tx = Transaction.read("01000000165500dbb434eb379a2fb76e1922ef11d6c549b11a5b0eabb7e473dd2ce23819da000000006b483045022100f3370f3d42d03fe58fefe84719cb71752b48469b02f8d8e46af01c6ca6e6ed9b02200a1cd4aac5d46b21682c1dc28bdc7adc680f76054a2030a4c2903ebadbfa1b05412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7fffffffffafdcb0133fd92e9ac6ad80865abff89a957919af30719cba66af1dd07ad7f11000000006b483045022100cff295d1ece77600b0bb0ee514a3f0885346ce6cb0c8fbd759284816fb99c23002203b329861f1fff6982309625c02f2c4c2fc296991af33ef743bfc8db9ae583395412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffd8941303a505121b71f59ef9d35aacd68b708505db5348008d6373e7c01b1691000000006a47304402201c868e0596fcaf7a4b47127af8dd4238188a2840de7b84c94caf232c7162e815022016281baa2e658ce8935b46d599881d9231e1158b8421ec97b40046343227c021412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff1837d504165fb22b8595f511f93ee7d350700f9ea26cd7b1f7d382a6b7a39462000000006b483045022100f61c84d47de37d46a9e10cd402b30c4c081bdb1b3368f158aa39182c9359038602207a1c0be4a0fafa451ef122f385dc82badf670afc61f2f9c91f0088eb57791ae7412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff2b1bff5816c1af1e8290116d30cda55a5e310bf643250d33277523e595981f49030000006b48304502210091ed3b6fa2c5ae987a77d0a77796d9528e16b9a26f208162ad49247cc395344202206299b3d7bc3204383c06b39a2518cb34c74ea028a30fa12c4bae0a37476e4574412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffe182622da4d54e516600166ee7536182fb9316dcd963b74d650c096eb5f0e3c7010000006a473044022020ee6964460a406f8801d32e9bbbfc8c895eebc9ec4ccae3b96e3aca8e00026f0220790c8670565f62f660a0a7d2ac262d38b651c16006be71851cf46086a1ccaf58412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff00ff725dd9a8dbb5b2ab4ffe953e996f00e9d4347b0aff00e2292e67fc93f96b000000006b483045022100c6e7a395668ae361e01a3754f6ff4daef2775f501b60a06d03d858a10d07ebc802206df79d38f222bb8af7998505bc99a5aa0ab6a28f0767f9a8220f9ac636324874412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffb2e2c3b13f9721c8c60b72cf79f81e9060ef40f2ea726b2ba2490ca8e71495b1010000006b4830450221008208186bdbc63d26b48ef86690e82362d43ea0f99af3b46ad8f1da4ca89ec185022022f4126755c278f6e3b424f516fbb9aeb6120edb8f0141fb5da9f3e747b19597412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffbd50c003a6a28e8dda70bfb4ba68fb014f62cd76b0a37f510d9d895b556ccb38000000006b483045022100b64f24af0474bf877bfa861db111dff844163d8ce57f650fff5090e5f993033b022049678552c5c264ec226cf655ea3419374586a4017ef6df6b47a6a28a09e838e1412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7fffffffff15dea08352229973c4794c1cc0de017a593dd28aadd5310fea2d24cc5fa2c09000000006b483045022100eda5233ea86d7e06dcbc6f2a057c8aefaf80362b471be1e4a149fca7cd4e39dc022049f7e220e95dd56107ceafa069396c01df78a218109d90e67c21d94f671510b8412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffb16a377d0d030db569378421d2c7766878aa2cac858878a652d9e1909e1be6ce000000006a47304402202fca4bdd154729440a896dd34682ef2757a5881399a30566463d3dce640e365f02206864872f9dfbcbc4b3325cda6a03440f3dc45523ad37d3597c825f06bc42ce6d412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff74d08d4abe0fa731c99ae19d4a50a590bf3b2e62e9fa42898e8bc92fbc55fb6a000000006a473044022055d22fcbc5b225d9f7bd78ebfaef0dc31ba76aafe8db3c8c80c0c6256bfb7f070220119850adddf47bd482cbdc63be4f223a47c23c430766ad299b103a9f45acc2cf412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff9d6e32b0a857cad2605294a525b7d034794c6cbabd951863427feaf951ada039000000006a4730440220654985ebbe9bd31be3275e725f58dc21eb674fbb89be37006ad364e4f6bbbc010220272765c71871aca7d18a894c1b481d1da15faae8673d9c6672293b5d9906ef1c412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff6e5cd771c1e2a914828978224e039cf0dc4a140e1bf719328b198b159e5865a3010000006b483045022100b464432621ea5a4509a556bbe96314470079634bb3db6698926f200750aa8b1a0220205666048bd891256fa22f68efb2675f78f0ca00a17a2c8a6195af5a13ac3512412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff97fed84869901155a2313023fced231f91fe2613be832083700316dcdddf1dce000000006b483045022100de0bb8499bf83d7084847f13bb05a36bd258e953e27ac394a4eb835671821e0602201aba030c6db1bdcf18a0cc74d1eedb0cac7c3fee2cb67b86664ec27657393245412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffe2940b6a182d7704ebe845b1ed7fc9b632e5d9b8b7d51e2bc7dc47cc2de55d5e000000006b48304502210080a3b75e6a220179b060549a035106653461a7fb7906723036a7166522a4ecc102201ef2283108b5b6e9539a644aa85284d2ca5506286b0abf00b617f0a6077003b0412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffc177b9cfa62eef7b38bb6e26dc139693f98b98532c0c63a909164425dc4b3a71000000006a4730440220588698066b7ec466e55c0986f88599c9871a91517c0559e9b8cfbb514969dd4a02201addd7b2d7f808b453ce86edc82132eaf9c087f15b913f82ab945a4e2af74dc9412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffb2b0d6c1da61f0210ac54d63e3156cee2d932cdfc22b853d28504a4ce63a6779030000006a47304402204bdde87595ff7b4202900ab950de94babdf44a472f551ba8414cba5fa796c9a6022042c3933c0d9218401a879ef4aaf38ae5481e04738f82ec575f6c2598ca3ba69d412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff12851c2d883734d7dda168c8bea5729de12a4475c5df8561af9c2323bd10335f000000006b483045022100836aa24a82d3b2f4ec275f426b71f2e01f070308b7c85cf4f0404816e83f70680220519cf2fb1d12f37ba0b79060e6e76b3d13de227b60ad1226117a76525bc0aecd412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff89932c925fe2edda9bd8fdd3fb1431f7ad5c4e68ea11f8a1a1eeb65eb36ccb7b000000006b483045022100f1066779a6c27790f70f73ceb56b0b85ed7cb4f4906c8afb3ec75f8056f21051022020eacc3c57f1139aedd720122a912ce9acf5a9e46b92823b27111415958fd3b6412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffe5045f56a836f20f9f2c347317581ef9bfa4428457947af60c284e256f2f6e91010000006a473044022074949e838130077ea80ebdfc2f13d62b3a64abdd2e85b5b811d69ec51b64e6de02203f83bb7e2e772124c537de69c1976070da6952cd2f3565c6c19b3dc2099f21c4412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff425584e796c9837173eec9d70853558c3a9b92af9cd24e0bad86de73be149b75010000006a4730440220742142899231ebbcfab59b51e6fe7b0fbdd894cd2176908549039ba3b7a102f202204795dd2987a36e706f6d820b83cbfcf01e9648d9a2c7f03d6f310c3d26f64e02412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff01ac1eeb76050000001976a914e0ab6ffdabb11a5e7e8d86e21be6e7e4d3a6744f88ac00000000")

    assert(tx.size() == 3291)
  }

  test("compute toString") {
    val hex = "01000000165500dbb434eb379a2fb76e1922ef11d6c549b11a5b0eabb7e473dd2ce23819da000000006b483045022100f3370f3d42d03fe58fefe84719cb71752b48469b02f8d8e46af01c6ca6e6ed9b02200a1cd4aac5d46b21682c1dc28bdc7adc680f76054a2030a4c2903ebadbfa1b05412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7fffffffffafdcb0133fd92e9ac6ad80865abff89a957919af30719cba66af1dd07ad7f11000000006b483045022100cff295d1ece77600b0bb0ee514a3f0885346ce6cb0c8fbd759284816fb99c23002203b329861f1fff6982309625c02f2c4c2fc296991af33ef743bfc8db9ae583395412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffd8941303a505121b71f59ef9d35aacd68b708505db5348008d6373e7c01b1691000000006a47304402201c868e0596fcaf7a4b47127af8dd4238188a2840de7b84c94caf232c7162e815022016281baa2e658ce8935b46d599881d9231e1158b8421ec97b40046343227c021412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff1837d504165fb22b8595f511f93ee7d350700f9ea26cd7b1f7d382a6b7a39462000000006b483045022100f61c84d47de37d46a9e10cd402b30c4c081bdb1b3368f158aa39182c9359038602207a1c0be4a0fafa451ef122f385dc82badf670afc61f2f9c91f0088eb57791ae7412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff2b1bff5816c1af1e8290116d30cda55a5e310bf643250d33277523e595981f49030000006b48304502210091ed3b6fa2c5ae987a77d0a77796d9528e16b9a26f208162ad49247cc395344202206299b3d7bc3204383c06b39a2518cb34c74ea028a30fa12c4bae0a37476e4574412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffe182622da4d54e516600166ee7536182fb9316dcd963b74d650c096eb5f0e3c7010000006a473044022020ee6964460a406f8801d32e9bbbfc8c895eebc9ec4ccae3b96e3aca8e00026f0220790c8670565f62f660a0a7d2ac262d38b651c16006be71851cf46086a1ccaf58412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff00ff725dd9a8dbb5b2ab4ffe953e996f00e9d4347b0aff00e2292e67fc93f96b000000006b483045022100c6e7a395668ae361e01a3754f6ff4daef2775f501b60a06d03d858a10d07ebc802206df79d38f222bb8af7998505bc99a5aa0ab6a28f0767f9a8220f9ac636324874412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffb2e2c3b13f9721c8c60b72cf79f81e9060ef40f2ea726b2ba2490ca8e71495b1010000006b4830450221008208186bdbc63d26b48ef86690e82362d43ea0f99af3b46ad8f1da4ca89ec185022022f4126755c278f6e3b424f516fbb9aeb6120edb8f0141fb5da9f3e747b19597412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffbd50c003a6a28e8dda70bfb4ba68fb014f62cd76b0a37f510d9d895b556ccb38000000006b483045022100b64f24af0474bf877bfa861db111dff844163d8ce57f650fff5090e5f993033b022049678552c5c264ec226cf655ea3419374586a4017ef6df6b47a6a28a09e838e1412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7fffffffff15dea08352229973c4794c1cc0de017a593dd28aadd5310fea2d24cc5fa2c09000000006b483045022100eda5233ea86d7e06dcbc6f2a057c8aefaf80362b471be1e4a149fca7cd4e39dc022049f7e220e95dd56107ceafa069396c01df78a218109d90e67c21d94f671510b8412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffb16a377d0d030db569378421d2c7766878aa2cac858878a652d9e1909e1be6ce000000006a47304402202fca4bdd154729440a896dd34682ef2757a5881399a30566463d3dce640e365f02206864872f9dfbcbc4b3325cda6a03440f3dc45523ad37d3597c825f06bc42ce6d412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff74d08d4abe0fa731c99ae19d4a50a590bf3b2e62e9fa42898e8bc92fbc55fb6a000000006a473044022055d22fcbc5b225d9f7bd78ebfaef0dc31ba76aafe8db3c8c80c0c6256bfb7f070220119850adddf47bd482cbdc63be4f223a47c23c430766ad299b103a9f45acc2cf412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff9d6e32b0a857cad2605294a525b7d034794c6cbabd951863427feaf951ada039000000006a4730440220654985ebbe9bd31be3275e725f58dc21eb674fbb89be37006ad364e4f6bbbc010220272765c71871aca7d18a894c1b481d1da15faae8673d9c6672293b5d9906ef1c412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff6e5cd771c1e2a914828978224e039cf0dc4a140e1bf719328b198b159e5865a3010000006b483045022100b464432621ea5a4509a556bbe96314470079634bb3db6698926f200750aa8b1a0220205666048bd891256fa22f68efb2675f78f0ca00a17a2c8a6195af5a13ac3512412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff97fed84869901155a2313023fced231f91fe2613be832083700316dcdddf1dce000000006b483045022100de0bb8499bf83d7084847f13bb05a36bd258e953e27ac394a4eb835671821e0602201aba030c6db1bdcf18a0cc74d1eedb0cac7c3fee2cb67b86664ec27657393245412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffe2940b6a182d7704ebe845b1ed7fc9b632e5d9b8b7d51e2bc7dc47cc2de55d5e000000006b48304502210080a3b75e6a220179b060549a035106653461a7fb7906723036a7166522a4ecc102201ef2283108b5b6e9539a644aa85284d2ca5506286b0abf00b617f0a6077003b0412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffc177b9cfa62eef7b38bb6e26dc139693f98b98532c0c63a909164425dc4b3a71000000006a4730440220588698066b7ec466e55c0986f88599c9871a91517c0559e9b8cfbb514969dd4a02201addd7b2d7f808b453ce86edc82132eaf9c087f15b913f82ab945a4e2af74dc9412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffb2b0d6c1da61f0210ac54d63e3156cee2d932cdfc22b853d28504a4ce63a6779030000006a47304402204bdde87595ff7b4202900ab950de94babdf44a472f551ba8414cba5fa796c9a6022042c3933c0d9218401a879ef4aaf38ae5481e04738f82ec575f6c2598ca3ba69d412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff12851c2d883734d7dda168c8bea5729de12a4475c5df8561af9c2323bd10335f000000006b483045022100836aa24a82d3b2f4ec275f426b71f2e01f070308b7c85cf4f0404816e83f70680220519cf2fb1d12f37ba0b79060e6e76b3d13de227b60ad1226117a76525bc0aecd412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff89932c925fe2edda9bd8fdd3fb1431f7ad5c4e68ea11f8a1a1eeb65eb36ccb7b000000006b483045022100f1066779a6c27790f70f73ceb56b0b85ed7cb4f4906c8afb3ec75f8056f21051022020eacc3c57f1139aedd720122a912ce9acf5a9e46b92823b27111415958fd3b6412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffffe5045f56a836f20f9f2c347317581ef9bfa4428457947af60c284e256f2f6e91010000006a473044022074949e838130077ea80ebdfc2f13d62b3a64abdd2e85b5b811d69ec51b64e6de02203f83bb7e2e772124c537de69c1976070da6952cd2f3565c6c19b3dc2099f21c4412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff425584e796c9837173eec9d70853558c3a9b92af9cd24e0bad86de73be149b75010000006a4730440220742142899231ebbcfab59b51e6fe7b0fbdd894cd2176908549039ba3b7a102f202204795dd2987a36e706f6d820b83cbfcf01e9648d9a2c7f03d6f310c3d26f64e02412103d812dbb76f1bf5b0a06121dc1704a6534f604e7bf7c429924f8fa546cda9b6d7ffffffff01ac1eeb76050000001976a914e0ab6ffdabb11a5e7e8d86e21be6e7e4d3a6744f88ac00000000"
    val tx = Transaction.read(hex)
    assert(tx.toString == hex)
  }
}
