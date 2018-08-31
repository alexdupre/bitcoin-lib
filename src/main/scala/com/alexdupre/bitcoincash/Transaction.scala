package com.alexdupre.bitcoincash

import java.io.{ByteArrayOutputStream, InputStream, OutputStream}

import com.alexdupre.bitcoincash.Crypto.PrivateKey
import com.alexdupre.bitcoincash.Protocol._
import com.alexdupre.bitcoincash.Script.Runner

object OutPoint extends BtcSerializer[OutPoint] {
  def apply(tx: Transaction, index: Int) = new OutPoint(tx.hash, index)

  override def read(input: InputStream, protocolVersion: Long): OutPoint = OutPoint(hash(input), uint32(input))

  override def write(input: OutPoint, out: OutputStream, protocolVersion: Long) = {
    out.write(input.hash)
    writeUInt32(input.index.toInt, out)
  }

  def isCoinbase(input: OutPoint) = input.index == 0xffffffffL && input.hash == Hash.Zeroes

  def isNull(input: OutPoint) = isCoinbase(input)

}

/**
  * an out point is a reference to a specific output in a specific transaction that we want to claim
  *
  * @param hash  reversed sha256(sha256(tx)) where tx is the transaction we want to refer to
  * @param index index of the output in tx that we want to refer to
  */
case class OutPoint(hash: BinaryData, index: Long) extends BtcSerializable[OutPoint] {
  require(hash.length == 32)
  require(index >= -1)

  /**
    *
    * @return the id of the transaction this output belongs to
    */
  val txid: BinaryData = hash.data.reverse

  override def serializer: BtcSerializer[OutPoint] = OutPoint
}

object TxIn extends BtcSerializer[TxIn] {
  def apply(outPoint: OutPoint, signatureScript: Seq[ScriptElt], sequence: Long): TxIn = new TxIn(outPoint, Script.write(signatureScript), sequence)

  /* Setting nSequence to this value for every input in a transaction disables nLockTime. */
  val SEQUENCE_FINAL = 0xffffffffL

  /* Below flags apply in the context of BIP 68*/
  /* If this flag set, CTxIn::nSequence is NOT interpreted as a relative lock-time. */
  val SEQUENCE_LOCKTIME_DISABLE_FLAG = (1L << 31)

  /* If CTxIn::nSequence encodes a relative lock-time and this flag
   * is set, the relative lock-time has units of 512 seconds,
   * otherwise it specifies blocks with a granularity of 1. */
  val SEQUENCE_LOCKTIME_TYPE_FLAG = (1L << 22)

  /* If CTxIn::nSequence encodes a relative lock-time, this mask is
   * applied to extract that lock-time from the sequence field. */
  val SEQUENCE_LOCKTIME_MASK = 0x0000ffffL

  /* In order to use the same number of bits to encode roughly the
   * same wall-clock duration, and because blocks are naturally
   * limited to occur every 600s on average, the minimum granularity
   * for time-based relative lock-time is fixed at 512 seconds.
   * Converting from CTxIn::nSequence to seconds is performed by
   * multiplying by 512 = 2^9, or equivalently shifting up by
   * 9 bits. */
  val SEQUENCE_LOCKTIME_GRANULARITY = 9

  override def read(input: InputStream, protocolVersion: Long): TxIn = TxIn(outPoint = OutPoint.read(input), signatureScript = script(input), sequence = uint32(input))

  override def write(input: TxIn, out: OutputStream, protocolVersion: Long) = {
    OutPoint.write(input.outPoint, out)
    writeScript(input.signatureScript, out)
    writeUInt32(input.sequence.toInt, out)
  }

  override def validate(input: TxIn): Unit = {
    require(input.signatureScript.length <= MaxScriptElementSize, s"signature script is ${input.signatureScript.length} bytes, limit is $MaxScriptElementSize bytes")
  }

  def coinbase(script: BinaryData): TxIn = {
    require(script.length >= 2 && script.length <= 100, "coinbase script length must be between 2 and 100")
    TxIn(OutPoint(new Array[Byte](32), 0xffffffffL), script, sequence = 0xffffffffL)
  }

  def coinbase(script: Seq[ScriptElt]): TxIn = coinbase(Script.write(script))
}

/**
  * Transaction input
  *
  * @param outPoint        Previous output transaction reference
  * @param signatureScript Signature script which should match the public key script of the output that we want to spend
  * @param sequence        Transaction version as defined by the sender. Intended for "replacement" of transactions when
  *                        information is updated before inclusion into a block. Repurposed for OP_CSV (see BIPs 68 & 112)
  */
case class TxIn(outPoint: OutPoint, signatureScript: BinaryData, sequence: Long) extends BtcSerializable[TxIn] {
  def isFinal: Boolean = sequence == TxIn.SEQUENCE_FINAL

  override def serializer: BtcSerializer[TxIn] = TxIn
}

object TxOut extends BtcSerializer[TxOut] {
  def apply(amount: Satoshi, publicKeyScript: Seq[ScriptElt]): TxOut = new TxOut(amount, Script.write(publicKeyScript))

  override def read(input: InputStream, protocolVersion: Long): TxOut = TxOut(Satoshi(uint64(input)), script(input))

  override def write(input: TxOut, out: OutputStream, protocolVersion: Long) = {
    writeUInt64(input.amount.amount, out)
    writeScript(input.publicKeyScript, out)
  }

  override def validate(input: TxOut): Unit = {
    import input._
    require(amount.amount >= 0, s"invalid txout amount: $amount")
    require(amount.amount <= MaxMoney, s"invalid txout amount: $amount")
    require(publicKeyScript.length < MaxScriptElementSize, s"public key script is ${publicKeyScript.length} bytes, limit is $MaxScriptElementSize bytes")
  }
}

/**
  * Transaction output
  *
  * @param amount          amount in Satoshis
  * @param publicKeyScript public key script which sets the conditions for spending this output
  */
case class TxOut(amount: Satoshi, publicKeyScript: BinaryData) extends BtcSerializable[TxOut] {
  override def serializer: BtcSerializer[TxOut] = TxOut
}

object Transaction extends BtcSerializer[Transaction] {
  // if lockTime >= LOCKTIME_THRESHOLD it is a unix timestamp otherwise it is a block height
  val LOCKTIME_THRESHOLD = 500000000L

  override def read(input: InputStream, protocolVersion: Long): Transaction =
    Transaction(uint32(input), readCollection[TxIn](input, protocolVersion), readCollection[TxOut](input, protocolVersion), uint32(input))

  override def write(tx: Transaction, out: OutputStream, protocolVersion: Long) = {
    writeUInt32(tx.version.toInt, out)
    writeCollection(tx.txIn, out, protocolVersion)
    writeCollection(tx.txOut, out, protocolVersion)
    writeUInt32(tx.lockTime.toInt, out)
  }

  override def validate(input: Transaction): Unit = {
    require(input.txIn.nonEmpty, "input list cannot be empty")
    require(input.txOut.nonEmpty, "output list cannot be empty")
    require(size(input) <= MAX_TX_SIZE)
    require(input.txOut.map(_.amount.amount).sum >= 0, "sum of outputs amount is invalid")
    require(input.txOut.map(_.amount.amount).sum <= MaxMoney, "sum of outputs amount is invalid")
    input.txIn.foreach(TxIn.validate)
    input.txOut.foreach(TxOut.validate)
    val sigOpCountWithoutP2SH = (input.txIn.map(_.signatureScript) ++ input.txOut.map(_.publicKeyScript)).foldLeft(0) {
      case (n, script) => Script.getSigOpCount(Script.parse(script), ScriptFlags.STANDARD_CHECKDATASIG_VERIFY_FLAGS, false)
    }
    require(sigOpCountWithoutP2SH <= MAX_TX_SIGOPS_COUNT, "number of signature operations is invalid")
    val outPoints = input.txIn.map(_.outPoint)
    require(outPoints.size == outPoints.toSet.size, "duplicate inputs")
    if (Transaction.isCoinbase(input)) {
      require(input.txIn(0).signatureScript.size >= 2, "coinbase script size")
      require(input.txIn(0).signatureScript.size <= MAX_COINBASE_SCRIPTSIG_SIZE, "coinbase script size")
    } else {
      require(input.txIn.forall(in => !OutPoint.isCoinbase(in.outPoint)), "prevout is null")
    }
  }

  def size(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = write(tx, protocolVersion).length

  def isCoinbase(input: Transaction) = input.txIn.size == 1 && OutPoint.isCoinbase(input.txIn(0).outPoint)

  /**
    * prepare a transaction for signing a specific input
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type
    * @return a new transaction with proper inputs and outputs according to SIGHASH_TYPE rules
    */
  def prepareForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: BinaryData, sighashType: Int): Transaction = {
    val filteredScript = Script.write(Script.parse(previousOutputScript).filterNot(_ == OP_CODESEPARATOR))

    def removeSignatureScript(txin: TxIn): TxIn = txin.copy(signatureScript = Array.empty[Byte])

    def removeAllSignatureScripts(tx: Transaction): Transaction = tx.copy(txIn = tx.txIn.map(removeSignatureScript))

    def updateSignatureScript(tx: Transaction, index: Int, script: Array[Byte]): Transaction = tx.copy(txIn = tx.txIn.updated(index, tx.txIn(index).copy(signatureScript = script)))

    def resetSequence(txins: Seq[TxIn], inputIndex: Int): Seq[TxIn] = for (i <- txins.indices) yield {
      if (i == inputIndex) txins(i)
      else txins(i).copy(sequence = 0)
    }

    val txCopy = {
      // remove all signature scripts, and replace the sig script for the input that we are processing with the
      // pubkey script of the output that we are trying to claim
      val tx1 = removeAllSignatureScripts(tx)
      val tx2 = updateSignatureScript(tx1, inputIndex, filteredScript)

      val tx3 = if (isHashNone(sighashType)) {
        // hash none: remove all outputs
        val inputs = resetSequence(tx2.txIn, inputIndex)
        tx2.copy(txIn = inputs, txOut = List())
      }
      else if (isHashSingle(sighashType)) {
        // hash single: remove all outputs but the one that we are trying to claim
        val inputs = resetSequence(tx2.txIn, inputIndex)
        val outputs = for (i <- 0 to inputIndex) yield {
          if (i == inputIndex) tx2.txOut(inputIndex)
          else TxOut(Satoshi(-1), Array.empty[Byte])
        }
        tx2.copy(txIn = inputs, txOut = outputs)
      }
      else tx2
      // anyone can pay: remove all inputs but the one that we are processing
      val tx4 = if (isAnyoneCanPay(sighashType)) tx3.copy(txIn = List(tx3.txIn(inputIndex))) else tx3
      tx4
    }
    txCopy
  }

  /**
    * hash a tx for signing (pre-segwit)
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type
    * @return a hash which can be used to sign the referenced tx input
    */
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: BinaryData, sighashType: Int): Seq[Byte] = {
    if (inputIndex >= tx.txIn.length) {
      Hash.One
    } else if (isHashSingle(sighashType) && inputIndex >= tx.txOut.length) {
      Hash.One
    } else {
      val txCopy = prepareForSigning(tx, inputIndex, previousOutputScript, sighashType)
      Crypto.hash256(Transaction.write(txCopy) ++ writeUInt32(sighashType))
    }
  }

  /**
    * hash a tx for signing (pre-segwit)
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type
    * @return a hash which can be used to sign the referenced tx input
    */
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int): Seq[Byte] =
    hashForSigning(tx, inputIndex, Script.write(previousOutputScript), sighashType)

  /**
    * hash a tx for signing
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sigHashType          signature hash type
    * @param amount               amount of the output claimed by this input
    * @return a hash which can be used to sign the referenced tx input
    */
  def hashForSigning(tx: Transaction, inputIndex: Int, previousOutputScript: BinaryData, sigHashType: Int, amount: Satoshi, flags: Int = ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID): Seq[Byte] = {
    val sighashType = if ((flags & ScriptFlags.SCRIPT_ENABLE_REPLAY_PROTECTION) != 0) {
      // Legacy chain's value for fork id must be of the form 0xffxxxx.
      // By xoring with 0xdead, we ensure that the value will be different
      // from the original one, even if it already starts with 0xff.
      val newForkValue = (sigHashType >> 8) ^ 0xdead
      ((0xff0000 | newForkValue) << 8) | (sigHashType & 0xff)
    } else sigHashType

    if (isForkId(sighashType) && (flags & ScriptFlags.SCRIPT_ENABLE_SIGHASH_FORKID) != 0) {
      val hashPrevOut: BinaryData = if (!isAnyoneCanPay(sighashType)) {
        Crypto.hash256(tx.txIn.map(_.outPoint).flatMap(OutPoint.write(_, Protocol.PROTOCOL_VERSION)))
      } else Hash.Zeroes

      val hashSequence: BinaryData = if (!isAnyoneCanPay(sighashType) && !isHashSingle(sighashType) && !isHashNone(sighashType)) {
        Crypto.hash256(tx.txIn.map(_.sequence).flatMap(s => Protocol.writeUInt32(s.toInt)))
      } else Hash.Zeroes

      val hashOutputs: BinaryData = if (!isHashSingle(sighashType) && !isHashNone(sighashType)) {
        Crypto.hash256(tx.txOut.flatMap(TxOut.write(_, Protocol.PROTOCOL_VERSION)))
      } else if (isHashSingle(sighashType) && inputIndex < tx.txOut.size) {
        Crypto.hash256(TxOut.write(tx.txOut(inputIndex), Protocol.PROTOCOL_VERSION))
      } else Hash.Zeroes

      val out = new ByteArrayOutputStream()
      Protocol.writeUInt32(tx.version.toInt, out)
      out.write(hashPrevOut)
      out.write(hashSequence)
      out.write(OutPoint.write(tx.txIn(inputIndex).outPoint, Protocol.PROTOCOL_VERSION))
      Protocol.writeScript(previousOutputScript, out)
      Protocol.writeUInt64(amount.toLong, out)
      Protocol.writeUInt32(tx.txIn(inputIndex).sequence.toInt, out)
      out.write(hashOutputs)
      Protocol.writeUInt32(tx.lockTime.toInt, out)
      Protocol.writeUInt32(sighashType, out)
      val preimage: BinaryData = out.toByteArray
      Crypto.hash256(preimage)
    } else {
      hashForSigning(tx, inputIndex, previousOutputScript, sighashType)
    }
  }

  /**
    * sign a tx input
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type, which will be appended to the signature
    * @param amount               amount of the output claimed by this tx input
    * @param privateKey           private key
    * @return the encoded signature of this tx for this specific tx input
    */
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: BinaryData, sighashType: Int, amount: Satoshi, privateKey: PrivateKey): BinaryData = {
    require(privateKey.compressed, "private key must be compressed")
    val hash = hashForSigning(tx, inputIndex, previousOutputScript, sighashType, amount)
    val (r, s) = Crypto.sign(hash, privateKey)
    val sig = Crypto.encodeSignature(r, s)
    sig :+ (sighashType.toByte)
  }

  /**
    * sign a tx input
    *
    * @param tx                   input transaction
    * @param inputIndex           index of the tx input that is being processed
    * @param previousOutputScript public key script of the output claimed by this tx input
    * @param sighashType          signature hash type, which will be appended to the signature
    * @param amount               amount of the output claimed by this tx input
    * @param privateKey           private key
    * @return the encoded signature of this tx for this specific tx input
    */
  def signInput(tx: Transaction, inputIndex: Int, previousOutputScript: Seq[ScriptElt], sighashType: Int, amount: Satoshi, privateKey: PrivateKey): BinaryData =
    signInput(tx, inputIndex, Script.write(previousOutputScript), sighashType, amount, privateKey)

  /**
    * Sign a transaction. Cannot partially sign. All the input are signed with SIGHASH_ALL
    *
    * @param input    transaction to sign
    * @param signData list of data for signing: previous tx output script and associated private key
    * @return a new signed transaction
    */
  def sign(input: Transaction, signData: Seq[SignData]): Transaction = {

    require(signData.length == input.txIn.length, "There should be signing data for every transaction")

    // sign each input
    val signedInputs = for (i <- input.txIn.indices) yield {
      val sig = signInput(input, i, signData(i).prevPubKeyScript, SIGHASH_ALL | SIGHASH_FORKID, signData(i).amount, signData(i).privateKey)

      // this is the public key that is associated with the private key we used for signing
      val publicKey = signData(i).privateKey.publicKey

      // signature script: push signature and public key
      val sigScript = Script.write(OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKey) :: Nil)
      input.txIn(i).copy(signatureScript = sigScript)
    }

    input.copy(txIn = signedInputs)
  }

  def correctlySpends(tx: Transaction, previousOutputs: Map[OutPoint, TxOut], scriptFlags: Int, callback: Option[Runner.Callback]): Unit = {
    for (i <- tx.txIn.indices if !OutPoint.isCoinbase(tx.txIn(i).outPoint)) {
      val prevOutput = previousOutputs(tx.txIn(i).outPoint)
      val prevOutputScript = prevOutput.publicKeyScript
      val amount = prevOutput.amount
      val ctx = Script.Context(tx, i, amount)
      val runner = new Script.Runner(ctx, scriptFlags, callback)
      if (!runner.verifyScripts(tx.txIn(i).signatureScript, prevOutputScript)) throw new RuntimeException(s"tx ${tx.txid} does not spend its input # $i")
    }
  }

  def correctlySpends(tx: Transaction, previousOutputs: Map[OutPoint, TxOut], scriptFlags: Int): Unit =
    correctlySpends(tx, previousOutputs, scriptFlags, None)

  def correctlySpends(tx: Transaction, inputs: Seq[Transaction], scriptFlags: Int, callback: Option[Runner.Callback]): Unit = {
    val prevouts = tx.txIn.map(_.outPoint).map(outpoint => {
      val prevTx = inputs.find(_.txid == outpoint.txid).get
      val prevOutput = prevTx.txOut(outpoint.index.toInt)
      outpoint -> prevOutput
    }).toMap
    correctlySpends(tx, prevouts, scriptFlags, callback)
  }

  def correctlySpends(tx: Transaction, inputs: Seq[Transaction], scriptFlags: Int): Unit =
    correctlySpends(tx, inputs, scriptFlags, None)
}

object SignData {
  def apply(txOut: TxOut, privateKey: PrivateKey): SignData = new SignData(txOut.publicKeyScript, txOut.amount, privateKey)
}

/**
  * data for signing pay2pk transaction
  *
  * @param prevPubKeyScript previous output public key script
  * @param privateKey       private key associated with the previous output public key
  */
case class SignData(prevPubKeyScript: BinaryData, amount: Satoshi, privateKey: PrivateKey)

/**
  * Transaction
  *
  * @param version  Transaction data format version
  * @param txIn     Transaction inputs
  * @param txOut    Transaction outputs
  * @param lockTime The block number or timestamp at which this transaction is locked
  */
case class Transaction(version: Long, txIn: Seq[TxIn], txOut: Seq[TxOut], lockTime: Long) extends BtcSerializable[Transaction] {

  import Transaction._

  // standard transaction hash, used to identify transactions (in transactions outputs for example)
  lazy val hash: BinaryData = Crypto.hash256(Transaction.write(this))
  lazy val txid: BinaryData = hash.reverse
  lazy val bin: BinaryData = Transaction.write(this)

  // this is much easier to use than Scala's default toString
  override def toString: String = bin.toString

  /**
    *
    * @param blockHeight current block height
    * @param blockTime   current block time
    * @return true if the transaction is final
    */
  def isFinal(blockHeight: Long, blockTime: Long): Boolean = lockTime match {
    case 0 => true
    case value if value < LOCKTIME_THRESHOLD && value < blockHeight => true
    case value if value >= LOCKTIME_THRESHOLD && value < blockTime => true
    case _ if txIn.exists(!_.isFinal) => false
    case _ => true
  }

  /**
    *
    * @param i         index of the tx input to update
    * @param sigScript new signature script
    * @return a new transaction that is of copy of this one but where the signature script of the ith input has been replace by sigscript
    */
  def updateSigScript(i: Int, sigScript: BinaryData): Transaction = this.copy(txIn = txIn.updated(i, txIn(i).copy(signatureScript = sigScript)))

  /**
    *
    * @param i         index of the tx input to update
    * @param sigScript new signature script
    * @return a new transaction that is of copy of this one but where the signature script of the ith input has been replace by sigscript
    */
  def updateSigScript(i: Int, sigScript: Seq[ScriptElt]): Transaction = updateSigScript(i, Script.write(sigScript))

  /**
    *
    * @param input input to add the tx
    * @return a new transaction which includes the newly added input
    */
  def addInput(input: TxIn): Transaction = this.copy(txIn = this.txIn :+ input)

  /**
    *
    * @param output output to add to the tx
    * @return a new transaction which includes the newly added output
    */
  def addOutput(output: TxOut): Transaction = this.copy(txOut = this.txOut :+ output)

  def size(protocolVersion: Long = PROTOCOL_VERSION): Int = Transaction.size(this, protocolVersion)

  override def serializer: BtcSerializer[Transaction] = Transaction
}
