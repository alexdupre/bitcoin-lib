package com.alexdupre.bitcoincash.reference

import java.io.InputStreamReader

import com.alexdupre.bitcoincash._
import com.alexdupre.bitcoincash.ScriptFlags._
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JInt, JString, JValue}
import org.json4s.jackson.JsonMethods
import org.scalatest.FlatSpec
import scodec.bits.ByteVector

class SighashSpec extends FlatSpec {
  implicit val format = DefaultFormats

  "bitcoincash-lib" should "pass reference client sighash tests" in {
    val stream = classOf[SighashSpec].getResourceAsStream("/data/sighash.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))
    // use tail to skip the first line of the .json file
    json.extract[List[List[JValue]]].tail.map(_ match {
      case JString(raw_transaction) :: JString(script) :: JInt(input_index) :: JInt(hashType) :: JString(signature_hash_regular) :: JString(signature_hash_no_forkid) :: JString(signature_hash_replay_protected) :: Nil => {
        val tx = Transaction.read(raw_transaction)
        val hashReg = Transaction.hashForSigning(tx, input_index.intValue, ByteVector.fromValidHex(script), hashType.intValue, 0 sat)
        assert(hashReg.reverse === ByteVector32(ByteVector.fromValidHex(signature_hash_regular)))
        val hashOld = Transaction.hashForSigning(tx, input_index.intValue, ByteVector.fromValidHex(script), hashType.intValue, 0 sat, 0)
        assert(hashOld.reverse === ByteVector32(ByteVector.fromValidHex(signature_hash_no_forkid)))
        val hashRep = Transaction.hashForSigning(tx, input_index.intValue, ByteVector.fromValidHex(script), hashType.intValue, 0 sat, SCRIPT_ENABLE_SIGHASH_FORKID | SCRIPT_ENABLE_REPLAY_PROTECTION)
        assert(hashRep.reverse === ByteVector32(ByteVector.fromValidHex(signature_hash_replay_protected)))
      }
      case _ => println("warning: could not parse sighash.json properly!")
    })
  }
}
