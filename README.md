# Simple Scala Bitcoin Cash Library

Simple bitcoin cash library written in Scala.

[![Build Status](https://travis-ci.org/alexdupre/bitcoincash-lib.png?branch=bch)](https://travis-ci.org/alexdupre/bitcoincash-lib)

## Overview

This is a simple scala library which implements most of the bitcoin cash protocol:

* base58 encoding/decoding
* block headers, block and tx parsing
* tx creation, signature and verification
* script parsing and execution (including OP codes added on the May 15 2018 fork and OP_CHECKDATASIG)
* pay to public key tx
* pay to script tx / multisig tx
* BIP 32 (deterministic wallets)
* BIP 39 (mnemonic code for generating deterministic keys)
* BIP 70
* CashAddr address format

## Objectives

Our goal is not to re-implement a full Bitcoin Cash node but to build a library that can be used to build applications that rely on bitcoind to interface with the Bitcoin Cash network (to retrieve and index transactions and blocks, for example...). We use it very often to build quick prototypes and test new ideas. Besides, some parts of the protocole are fairly simple and "safe" to re-implement (BIP32/BIP39 for example), especially for indexing/analysis purposes.

## Status
- [X] Message parsing (blocks, transactions, inv, ...)
- [X] Building transactions (P2PK, P2PKH, P2SH)
- [X] Signing transactions
- [X] Verifying signatures
- [X] Passing core reference tests (scripts & transactions)

## Configuring sbt

* releases and milestones are pushed to maven central

```scala
libraryDependencies += "com.alexdupre" %% "bitcoincash-lib" % "0.9.19"
```

The latest released version is 0.9.18

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

scala> import com.alexdupre.bitcoincash._
import com.alexdupre.bitcoincash._

scala> import com.alexdupre.bitcoincash.Crypto._
import com.alexdupre.bitcoincash.Crypto._

scala> val priv = PrivateKey(BinaryData("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd"), compressed = true)
priv: com.alexdupre.bitcoincash.Crypto.PrivateKey = 1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd01

scala> val pub = priv.publicKey
pub: com.alexdupre.bitcoincash.Crypto.PublicKey = 03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a

scala> Base58Check.encode(Base58.Prefix.PubkeyAddress, pub.hash160)
res0: String = 1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy

scala> CashAddr.encodeAddress("bitcoincash", CashAddr.Type.PubKey, pub.hash160)
res1: String = bitcoincash:qzaurep288g95nxxzafdd93m0a5apxaj0vua73mjlc

scala> Base58Check.encode(Base58.Prefix.SecretKey, priv.toBin)
res2: String = KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ
```

### Building and verifying transactions

The Transaction class can be used to create, serialize, deserialize, sign and validate bitcoin transactions.

#### P2PKH transactions

A P2PKH transactions sends bitcoins to a public key hash, using a standard P2PKH script:
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
  val to = "qqd4h24jfqnpg3gaqyxenzkerhyzy76kmglydcjql7"
  val ("bchtest", CashAddr.Type.PubKey, pubkeyHash) = CashAddr.decodeAddressTolerant(to)
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
  Transaction.correctlySpends(tx2, Seq(previousTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
```

#### P2SH transactions

A P2SH transactions sends bitcoins to a script hash:
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
  val priv1 = PrivateKey.fromBase58("Kz9AqYfHrH2aBKdLLygaw8m6sNoarUs5jBsBeJxZ1ciZbAt1yZQF", Base58.Prefix.SecretKey)
  val pub1 = priv1.publicKey
  val address1 = CashAddr.encodeAddress("bitcoincash", CashAddr.Type.PubKey, pub1.hash160)

  assert(address1 == "bitcoincash:qq8kvdgaq5nfj53s9fs8knt0k623wwr6jugt8k3crk")

  val priv2 = PrivateKey.fromBase58("L3RvtRGjKVpzfS3nVUGcwTd3uw1UfuGhhm6Fh4CGPbeJRrCGcrQy", Base58.Prefix.SecretKey)
  val pub2 = priv2.publicKey

  val priv3 = PrivateKey.fromBase58("L5eFDGn4Fag8MBosaABgKtSh69qgRYiGzT3m23v4LiSeZmEaw9Vf", Base58.Prefix.SecretKey)
  val pub3 = priv3.publicKey

  // this is a standard tx that sends 0.5 BTC to bitcoincash:qq8kvdgaq5nfj53s9fs8knt0k623wwr6jugt8k3crk
  val tx1 = Transaction.read("010000000240b4f27534e9d5529e67e52619c7addc88eff64c8e7afc9b41afe9a01c6e2aea010000006b48304502210091aed7fe956c4b2471778bfef5a323a96fee21ec6d73a9b7f363beaad135c5f302207f63b0ffc08fd905cdb87b109416c2d6d8ec56ca25dd52529c931aa1154277f30121037cb5789f1ca6c640b6d423ef71390e0b002da81db8fad4466bf6c2fdfb79a24cfeffffff6e21b8c625d9955e48de0a6bbcd57b03624620a93536ddacabc19d024c330f04010000006a47304402203fb779df3ae2bf8404e6d89f83af3adee0d0a0c4ec5a01a1e88b3aa4313df6490220608177ca82cf4f7da9820a8e8bf4266ccece9eb004e73926e414296d0635d7c1012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019feffffff0280f0fa02000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ace06d9800000000001976a91457572594090c298721e8dddcec3ac1ec593c6dcc88ac205a0000")

  val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))

  // now let's create a simple tx that spends tx1 and send 0.5 BTC to a P2WSH output
  val tx2 = {
    // our script is a 2-of-2 multisig script
    val tmp = Transaction(version = 1,
      txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = Nil) :: Nil,
      txOut = TxOut(0.49 btc, Script.pay2sh(redeemScript)) :: Nil,
      lockTime = 0
    )
    Transaction.sign(tmp, Seq(SignData(tx1.txOut(0), priv1)))
  }
  Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

  // and now we create a tx that spends the P2SH output
  val tx3 = {
    val tmp: Transaction = Transaction(version = 1,
      txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = Nil) :: Nil,
      txOut = TxOut(0.48 btc, Script.pay2pkh(pub1)) :: Nil,
      lockTime = 0
    )
    val pubKeyScript = Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
    val sig2 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL | SIGHASH_FORKID, tx2.txOut(0).amount, priv2)
    val sig3 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL | SIGHASH_FORKID, tx2.txOut(0).amount, priv3)
    val scriptSig = OP_0 :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(sig3) :: OP_PUSHDATA(Script.write(redeemScript)) :: Nil
    tmp.updateSigScript(0, scriptSig)
  }

  Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
```

### Wallet features

bitcoincash-lib provides and simple and complete implementation of BIP32 and BIP39.

#### HD Wallet (BIP32)

Let's play with the scala console and the first test vector from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

```shell
sbt console

scala> import com.alexdupre.bitcoincash._
import com.alexdupre.bitcoincash._

scala> import com.alexdupre.bitcoincash.DeterministicWallet
import com.alexdupre.bitcoincash.DeterministicWallet

scala> import com.alexdupre.bitcoincash.DeterministicWallet._
import com.alexdupre.bitcoincash.DeterministicWallet._

scala> val m = generate(fromHexString("000102030405060708090a0b0c0d0e0f"))
m: com.alexdupre.bitcoincash.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(m, xprv)
res0: String = xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi

scala> publicKey(m)
res1: com.alexdupre.bitcoincash.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(publicKey(m), xpub)
res2: String = xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

scala> val priv = derivePrivateKey(m, hardened(0) :: 1L :: hardened(2) :: 2L :: Nil)
priv: com.alexdupre.bitcoincash.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4,cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd,4,m/0'/1/2'/2,4001020172)

scala> encode(priv, xprv)
res3: String = xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334

scala> encode(publicKey(priv), xpub)
res4: String = xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV

scala> val k2 = derivePrivateKey(m, hardened(0) :: 1L :: hardened(2) :: Nil)
k2: com.alexdupre.bitcoincash.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca,04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0'/1/2',3203769081)

scala> val K2 = publicKey(k2)
K2: com.alexdupre.bitcoincash.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2,04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0'/1/2',3203769081)

scala> derivePublicKey(K2, 2L :: 1000000000L :: Nil)
res5: com.alexdupre.bitcoincash.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011,c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e,5,m/0'/1/2'/2/1000000000,3632322520)

scala> encode(derivePublicKey(K2, 2L :: 1000000000L :: Nil), xpub)
res6: String = xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy

```

#### Mnemonic code (BIP39)

```shell
sbt console

scala> import com.alexdupre.bitcoincash._
import com.alexdupre.bitcoincash._

scala> import MnemonicCode._
import MnemonicCode._

scala> val mnemonics = toMnemonics(fromHexString("77c2b00716cec7213839159e404db50d"))
mnemonics: List[String] = List(jelly, better, achieve, collect, unaware, mountain, thought, cargo, oxygen, act, hood, bridge)

scala> val key:BinaryData = toSeed(mnemonics, "TREZOR")
key: com.alexdupre.bitcoincash.BinaryData = b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff
```
