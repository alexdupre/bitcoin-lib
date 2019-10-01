package com.alexdupre.litecoin

import java.io.{InputStream, OutputStream}
import java.math.BigInteger
import java.nio.ByteOrder

import com.alexdupre.litecoin.Protocol._
import org.spongycastle.crypto.generators.SCrypt
import scodec.bits._

object BlockHeader extends LtcSerializer[BlockHeader] {
  override def read(input: InputStream, protocolVersion: Long): BlockHeader = {
    val version = uint32(input)
    val hashPreviousBlock = hash(input)
    val hashMerkleRoot = hash(input)
    val time = uint32(input)
    val bits = uint32(input)
    val nonce = uint32(input)
    BlockHeader(version, hashPreviousBlock, hashMerkleRoot, time, bits, nonce)
  }

  override def write(input: BlockHeader, out: OutputStream, protocolVersion: Long) = {
    writeUInt32(input.version.toInt, out)
    writeBytes(input.hashPreviousBlock.toArray, out)
    writeBytes(input.hashMerkleRoot.toArray, out)
    writeUInt32(input.time.toInt, out)
    writeUInt32(input.bits.toInt, out)
    writeUInt32(input.nonce.toInt, out)
  }

  def getDifficulty(header: BlockHeader): BigInteger = {
    val nsize = header.bits >> 24
    val isneg = header.bits & 0x00800000
    val nword = header.bits & 0x007fffff
    val result = if (nsize <= 3)
      BigInteger.valueOf(nword).shiftRight(8 * (3 - nsize.toInt))
    else
      BigInteger.valueOf(nword).shiftLeft(8 * (nsize.toInt - 3))
    if (isneg != 0) result.negate() else result
  }

  /**
    *
    * @param bits difficulty target
    * @return the amount of work represented by this difficulty target, as displayed
    *         by litecoin core
    */
  def blockProof(bits: Long): Double = {
    val (target, negative, overflow) = decodeCompact(bits)
    if (target == BigInteger.ZERO || negative || overflow) 0.0 else {
      val work = BigInteger.valueOf(2).pow(256).divide(target.add(BigInteger.ONE))
      work.doubleValue()
    }
  }

  def blockProof(header: BlockHeader): Double = blockProof(header.bits)

  /**
    * Proof of work: hash(header) <= target difficulty
    *
    * @param header block header
    * @return true if the input block header validates its expected proof of work
    */
  def checkProofOfWork(header: BlockHeader): Boolean = {
    val (target, _, _) = decodeCompact(header.bits)
    val hash = new BigInteger(1, header.powHash.toArray)
    hash.compareTo(target) <= 0
  }

  def calculateNextWorkRequired(lastHeader: BlockHeader, lastRetargetTime: Long): Long = {
    var actualTimespan = lastHeader.time - lastRetargetTime
    val targetTimespan = (3.5 * 24 * 60 * 60).toInt // 3.5 days
    if (actualTimespan < targetTimespan / 4) actualTimespan = targetTimespan / 4
    if (actualTimespan > targetTimespan * 4) actualTimespan = targetTimespan * 4

    var (target, false, false) = decodeCompact(lastHeader.bits)
    val powLimit = new BigInteger(1, hex"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".toArray)
    val shift = target.bitLength() > powLimit.bitLength() - 1
    if (shift) target = target.shiftRight(1)
    target = target.multiply(BigInteger.valueOf(actualTimespan))
    target = target.divide(BigInteger.valueOf(targetTimespan))
    if (shift) target = target.shiftLeft(1)

    target = target.min(powLimit)
    encodeCompact(target)
  }
}

/**
  *
  * @param version           Block version information, based upon the software version creating this block
  * @param hashPreviousBlock The hash value of the previous block this particular block references. Please not that
  *                          this hash is not reversed (as opposed to Block.hash)
  * @param hashMerkleRoot    The reference to a Merkle tree collection which is a hash of all transactions related to this block
  * @param time              A timestamp recording when this block was created (Will overflow in 2106[2])
  * @param bits              The calculated difficulty target being used for this block
  * @param nonce             The nonce used to generate this block… to allow variations of the header and compute different hashes
  */
case class BlockHeader(version: Long, hashPreviousBlock: ByteVector32, hashMerkleRoot: ByteVector32, time: Long, bits: Long, nonce: Long) extends LtcSerializable[BlockHeader] {
  lazy val hash: ByteVector32 = Crypto.hash256(BlockHeader.write(this))

  lazy val powHash: ByteVector32 = {
    val input = serializer.write(this)
    ByteVector32(ByteVector(SCrypt.generate(input.toArray, input.toArray, 1024, 1, 1, 32).reverse))
  }

  // hash is reversed here (same as tx id)
  lazy val blockId = hash.reverse

  def blockProof = BlockHeader.blockProof(this)

  override def serializer: LtcSerializer[BlockHeader] = BlockHeader
}

object Block extends LtcSerializer[Block] {
  override def read(input: InputStream, protocolVersion: Long): Block = {
    val raw = bytes(input, 80)
    val header = BlockHeader.read(raw.toArray)
    Block(header, readCollection[Transaction](input, protocolVersion))
  }

  override def write(input: Block, out: OutputStream, protocolVersion: Long) = {
    BlockHeader.write(input.header, out)
    writeCollection(input.tx, out, protocolVersion)
  }

  override def validate(input: Block): Unit = {
    BlockHeader.validate(input.header)
    require(input.header.hashMerkleRoot === MerkleTree.computeRoot(input.tx.map(_.hash)), "invalid block:  merkle root mismatch")
    require(input.tx.map(_.txid).toSet.size == input.tx.size, "invalid block: duplicate transactions")
    input.tx.foreach(Transaction.validate)
  }

  def blockProof(block: Block): Double = BlockHeader.blockProof(block.header)

  // genesis blocks
  val LivenetGenesisBlock = {
    val script = OP_PUSHDATA(writeUInt32(486604799L)) :: OP_PUSHDATA(hex"04") :: OP_PUSHDATA(ByteVector("NY Times 05/Oct/2011 Steve Jobs, Apple’s Visionary, Dies at 56".getBytes("UTF-8"))) :: Nil
    val scriptPubKey = OP_PUSHDATA(hex"040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") :: OP_CHECKSIG :: Nil
    Block(
      BlockHeader(version = 1, hashPreviousBlock = ByteVector32.Zeroes, hashMerkleRoot = ByteVector32(hex"d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97"), time = 1317972665, bits = 0x1e0ffff0, nonce = 2084524493),
      List(
        Transaction(version = 1,
          txIn = List(TxIn.coinbase(script)),
          txOut = List(TxOut(amount = 50 ltc, publicKeyScript = scriptPubKey)),
          lockTime = 0))
    )
  }

  val TestnetGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(time = 1486949366, nonce = 293345))

  val RegtestGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(bits = 0x207fffffL, nonce = 0, time = 1296688602))

  val SegnetGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(bits = 503447551, time = 1452831101, nonce = 0))

  /**
    * Proof of work: hash(block) <= target difficulty
    *
    * @param block
    * @return true if the input block validates its expected proof of work
    */
  def checkProofOfWork(block: Block): Boolean = BlockHeader.checkProofOfWork(block.header)

  /**
    *
    * @param tx coinbase transaction
    * @return the witness reserved value included in the input of this tx if any
    */
  def witnessReservedValue(tx: Transaction): Option[ByteVector] = tx.txIn(0).witness match {
    case ScriptWitness(Seq(nonce)) if nonce.length == 32 => Some(nonce)
    case _ => None
  }

  /**
    *
    * @param tx coinbase transaction
    * @return the witness commitment included in this transaction, if any
    */
  def witnessCommitment(tx: Transaction): Option[ByteVector32] = tx.txOut.map(o => Script.parse(o.publicKeyScript)).reverse.collectFirst {
    // we've reversed the outputs because if there are more than one scriptPubKey matching the pattern, the one with
    // the highest output index is assumed to be the commitment.
    case OP_RETURN :: OP_PUSHDATA(commitmentHeader, _) :: Nil if commitmentHeader.length == 36 && Protocol.uint32(commitmentHeader.take(4).toArray, ByteOrder.BIG_ENDIAN) == 0xaa21a9edL => ByteVector32(commitmentHeader.takeRight(32))
  }

  /**
    * Checks the witness commitment of a block
    *
    * @param block block
    * @return true if the witness commitment for this block is valid, or if this block does not contain a witness commitment
    *         nor any segwit transactions.
    */
  def checkWitnessCommitment(block: Block): Boolean = {
    val coinbase = block.tx.head
    (witnessReservedValue(coinbase), witnessCommitment(coinbase)) match {
      case (Some(nonce), Some(commitment)) =>
        val rootHash = MerkleTree.computeRoot(ByteVector32.Zeroes +: block.tx.tail.map(tx => tx.whash))
        val commitmentHash = Crypto.hash256(rootHash ++ nonce)
        commitment == commitmentHash
      case _ if block.tx.exists(_.hasWitness) => false // block has segwit transactions but no witness commitment
      case _ => true
    }
  }
}

/**
  * Litecoin block
  *
  * @param header block header
  * @param tx     transactions
  */
case class Block(header: BlockHeader, tx: Seq[Transaction]) extends LtcSerializable[Block] {
  lazy val hash = header.hash

  lazy val powHash = header.powHash

  lazy val blockId = header.blockId

  override def serializer: LtcSerializer[Block] = Block
}

