# Simple Scala Litecoin Library

Simple litecoin library written in Scala.

[![Build Status](https://travis-ci.org/alexdupre/bitcoincash-lib.png?branch=ltc)](https://travis-ci.org/alexdupre/bitcoincash-lib)

## Overview

This is a simple scala library which implements most of the litecoin protocol:

* base58 encoding/decoding
* block headers, block and tx parsing
* tx creation, signature and verification
* script parsing and execution (including OP_CLTV and OP_CSV)
* pay to public key tx
* pay to script tx / multisig tx
* BIP 32 (deterministic wallets)
* BIP 39 (mnemonic code for generating deterministic keys)
* BIP 173 (Base32 address format for native v0-16 witness outputs)

## Objectives

Our goal is not to re-implement a full Litecoin node but to build a library that can be used to build applications that rely on litecoind to interface with the Litecoin network (to retrieve and index transactions and blocks, for example...). We use it very often to build quick prototypes and test new ideas. Besides, some parts of the protocole are fairly simple and "safe" to re-implement (BIP32/BIP39 for example), especially for indexing/analysis purposes. And, of course, we use it for our own work on Lightning (see https://github.com/ACINQ/eclair).

## Status
- [X] Message parsing (blocks, transactions, inv, ...)
- [X] Building transactions (P2PK, P2PKH, P2SH, P2WPK, P2WSH)
- [X] Signing transactions
- [X] Verifying signatures
- [X] Passing core reference tests (scripts & transactions)
- [X] Passing core reference segwit tests

## Configuring sbt

* releases and milestones are pushed to maven central
* snapshots are pushed to the sonatype snapshot repository

```xml
libraryDependencies += "com.alexdupre" %% "litecoin-lib" % "0.15"
```

The latest released version is 0.9.18

The latest snapshot (development) version is 0.16-SNAPSHOT, the latest released version is 0.15
>>>>>>> btc

## Segwit support

Litecoin-lib fully supports segwit (see below for more information) and is on par with the segwit code in Litecoin Core 0.16.0.

## libscp256k1 support

bitcoin-lib embeds JNI bindings for libsecp256k1, which is must faster than BouncyCastle. It will extract and load native bindings for your operating system
in a temporary directory. If this process fails it will fallback to BouncyCastle.

JNI libraries are included for:
- Linux 64 bits
- Windows 64 bits
- Osx 64 bits

You can use your own library native library by specifying its path with `-Dfr.acinq.secp256k1.lib.path` and optionally its name with `-Dfr.acinq.secp256k1.lib.name` (if unspecified
bitcoin-lib will use the standard name for your OS i.e. libsecp256k1.so on Linux, secp256k1.dll on Windows, ...)

You can also specify the temporary directory where the library will be extracted with `-Djava.io.tmpdir` or `-Dfr.acinq.secp256k1.tmpdir` (if you want to use a different
directory from `-Djava.io.tmpdir`).

## Usage

Please have a look at unit tests, more samples will be added soon.

### Basic type: public keys, private keys, addresses

We defined only a limited set of specific types (private keys, public keys). There is a simple BinaryData type
that can be used to convert to/from Array[Byte], Seq[Byte], and hexadecimal Strings.

As much as possible, the library uses and produces raw binary data, without fancy wrapper types and encoding. This should
make importing/exporting data from/to other libraries easy. It also makes it easy to use binary data used in examples, books,
or produced by debugging tools.

The following REPL session shows how to create and use keys and addresses:

```shell
sbt console

scala> import com.alexdupre.litecoin._
import com.alexdupre.litecoin._

scala> import com.alexdupre.litecoin.Crypto._
import com.alexdupre.litecoin.Crypto._

scala> val priv = PrivateKey(BinaryData("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd"), compressed = true)
priv: com.alexdupre.litecoin.Crypto.PrivateKey = 1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd01

scala> val priv = PrivateKey(BinaryData("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd"), compressed = false)
priv: com.alexdupre.litecoin.Crypto.PrivateKey = 1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd

scala> val pubUncompressed = priv.publicKey
pubUncompressed: com.alexdupre.litecoin.Crypto.PublicKey = 04f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a07cf33da18bd734c600b96a72bbc4749d5141c90ec8ac328ae52ddfe2e505bdb

scala> Base58Check.encode(Base58.Prefix.PubkeyAddress, pubUncompressed.hash160)
res0: String = LNF1TEYtfrPMyS4tubTrUcYj8Jor8rMuho

scala> val pubCompressed = priv.publicKey.copy(compressed = true)
pubCompressed: com.alexdupre.litecoin.Crypto.PublicKey = 03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a

scala> Base58Check.encode(Base58.Prefix.PubkeyAddress, pubCompressed.hash160)
res1: String = LcLittPgg5DXY34hp62SnWa5KtEcvWHUsr

scala> Base58Check.encode(Base58.Prefix.SecretKey, priv.toBin)
res2: String = 6uMVeihoyYfgsRRvwC6nFiAQ3VzsHh7eh9RUXnonNS2HZK53ihe

scala> Base58Check.encode(Base58.Prefix.SecretKey, priv.copy(compressed = true).toBin)
res3: String = T45TTV58LamkyYq34BzWjvgUi2zQxg4MNCB2WuBVFbSg5a7Dqx4L
```

### Building and verifying transactions

The Transaction class can be used to create, serialize, deserialize, sign and validate litecoin transactions.

#### P2PKH transactions

A P2PKH transactions sends litecoins to a public key hash, using a standard P2PKH script:
``` scala
val pkh = pubKey.hash160
val pubKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(pkh) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil
```
To spend it, just provide a signature and the public key:
```scala
val sigScript = OP_PUSHDATA(sig) :: OP_PUSHDATA(pubKey.toBin) :: Nil
```
This sample demonstrates how to serialize, create and verify simple P2PKH transactions.

```scala
  // simple pay to PK tx

  // we have a tx that was sent to a public key that we own
  val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
  val (Base58.Prefix.PubkeyAddressTestnet, pubkeyHash) = Base58Check.decode(to)
  val amount = 10000 sat

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
  val sig = Transaction.signInput(tx1, 0, previousTx.txOut(0).publicKeyScript, SIGHASH_ALL, 0 satoshi, SigVersion.SIGVERSION_BASE, privateKey)
  val tx2 = tx1.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKey) :: Nil)

  // redeem the tx
  Transaction.correctlySpends(tx2, Seq(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
```

#### P2SH transactions

A P2SH transactions sends litecoins to a script hash:
```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub1, pub2, pub3 ))
val multisigAddress = Crypto.hash160(redeemScript)
val publicKeyScript = OP_HASH160 :: OP_PUSHDATA(multisigAddress) :: OP_EQUAL :: Nil
```
To spend it, you must provide data that will match the public key script, and the actual public key script. In our case,
we need 2 valid signatures:
```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub1, pub2, pub3 ))
val sigScript = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(redeemScript) :: Nil
```

This sample demonstrates how to serialize, create and verify a multisig P2SH transaction

```scala
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
```

#### P2WPK transactions

This is the simplest segwit transaction, equivalent to standard P2PKH transactions but more compact:

```scala
val pkh = pubKey.hash160
val pubKeyScript = OP_0 :: OP_PUSHDATA(pkh) :: Nil
```

To spend them, you provide a witness that is just a push of a signature and the actual public key:
```scala
val witness = ScriptWitness(sig :: pubKey :: Nil))
```

This sample demonstrates how to serialize, create and verify a P2WPK transaction

```scala
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
```

#### P2WSH transactions

P2WSH transactions are the segwit version of P2SH transactions:
```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
val pubKeyScript = OP_0 :: OP_PUSHDATA(Crypto.sha256(redeemScript)) :: Nil) :: Nil,
```
To spend them, you provide data that wil match the publick key script, and the actual public key script:
```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
val witness = ScriptWitness(Seq(BinaryData.empty, sig2, sig3, redeemScript))
```

This sample demonstrates how to serialize, create and verify a P2WPSH transaction

```scala
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
```

#### Segwit transactions embedded in standard P2SH transactions

```scala
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
```

### Wallet features

Litecoin-lib provides and simple and complete implementation of BIP32 and BIP39.

#### HD Wallet (BIP32)

Let's play with the scala console and the first test vector from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

```shell
sbt console

scala> import com.alexdupre.litecoin._
import com.alexdupre.litecoin._

scala> import com.alexdupre.litecoin.DeterministicWallet
DeterministicWallet   DeterministicWalletSpec

scala> import com.alexdupre.litecoin.DeterministicWallet._
import com.alexdupre.litecoin.DeterministicWallet._

scala> val m = generate(fromHexString("000102030405060708090a0b0c0d0e0f"))
m: com.alexdupre.litecoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(m, xprv)
res1: String = xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi

scala> publicKey(m)
res2: com.alexdupre.litecoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(publicKey(m), xpub)
res3: String = xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

scala> val priv = derivePrivateKey(m, hardened(0) :: 1L :: hardened(2) :: 2L :: Nil)
priv: com.alexdupre.litecoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4,cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd,4,m/0h/1/2h/2,4001020172)

scala> encode(priv, xprv)
res4: String = xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334

scala> encode(publicKey(priv), xpub)
res5: String = xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV

scala> val k2 = derivePrivateKey(m, hardened(0) :: 1L :: hardened(2) :: Nil)
k2: com.alexdupre.litecoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(cbce0d719ecf7431d88e6a89fa1483e02e35092
af60c042b1df2ff59fa424dca,04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0h/1/2h,3203769081)

scala> val K2 = publicKey(k2)
K2: com.alexdupre.litecoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(0357bfe1e341d01c69fe5654309956cbea516822f
ba8a601743a012a7896ee8dc2,04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0h/1/2h,3203769081)

scala> derivePublicKey(K2, 2L :: 1000000000L :: Nil)
res6: com.alexdupre.litecoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011,c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e,5,m/0h/1/2h/2/1000000000,3632322520)

scala> encode(derivePublicKey(K2, 2L :: 1000000000L :: Nil), xpub)
res7: String = xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy

```

#### Mnemonic code (BIP39)

```shell
sbt console

scala> import com.alexdupre.litecoin._
import com.alexdupre.litecoin._

scala> import MnemonicCode._
import MnemonicCode._

scala> val mnemonics = toMnemonics(fromHexString("77c2b00716cec7213839159e404db50d"))
mnemonics: List[String] = List(jelly, better, achieve, collect, unaware, mountain, thought, cargo, oxygen, act, hood, bridge)

scala> val key:BinaryData = toSeed(mnemonics, "TREZOR")
key: com.alexdupre.litecoin.BinaryData = b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43
897fc4e51a6ff
```
