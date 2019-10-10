package com.alexdupre.bitcoincash.reference

import java.io.InputStreamReader

import com.alexdupre.bitcoincash.Crypto.PrivateKey
import com.alexdupre.bitcoincash.{Base58, Base58Check, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA, Script}
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JBool, JString, JValue}
import org.json4s.jackson.JsonMethods
import org.scalatest.FunSuite
import scodec.bits.ByteVector

import scala.util.Try

class KeyEncodingSpec extends FunSuite {
  implicit val format = DefaultFormats

  test("valid keys") {
    val stream = classOf[KeyEncodingSpec].getResourceAsStream("/data/key_io_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].map(KeyEncodingSpec.check)
  }

  test("invalid keys") {
    val stream = classOf[KeyEncodingSpec].getResourceAsStream("/data/key_io_invalid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].foreach {
      _ match {
        case JString(value) :: Nil =>
          assert(!KeyEncodingSpec.isValidBase58(value))
        case unexpected => throw new IllegalArgumentException(s"don't know how to parse $unexpected")
      }
    }
  }
}

object KeyEncodingSpec {
  def isValidBase58(input: String): Boolean = Try {
    val (prefix, bin) = Base58Check.decode(input)
    prefix match {
      case Base58.Prefix.SecretKey | Base58.Prefix.SecretKeyTestnet => Try(PrivateKey.fromBin(bin)).isSuccess
      case Base58.Prefix.PubkeyAddress | Base58.Prefix.PubkeyAddressTestnet => bin.length == 20
      case _ => false
    }
  } getOrElse (false)

  def check(data: List[JValue]): Unit = {
    data match {
      case JString(encoded) :: JString(hex) :: obj :: Nil => {
        val bin = ByteVector.fromValidHex(hex)
        val JBool(isPrivkey) = obj \ "isPrivkey"
        val isCompressed = obj \ "isCompressed" match {
          case JBool(value) => value
          case _ => false
        }
        val JString(chain) = obj \ "chain"
        if (isPrivkey) {
          val (version, data) = Base58Check.decode(encoded)
          assert((isCompressed && data.length == 33 && data.last == 0x01) || (!isCompressed && data.length == 32))
          assert((chain == "main" && version == Base58.Prefix.SecretKey) || (chain != "main" && version == Base58.Prefix.SecretKeyTestnet))
          assert(data.take(32) == bin)
        } else {
          encoded.head match {
            case '1' | 'm' | 'n' =>
              val (version, data) = Base58Check.decode(encoded)
              assert((chain == "main" && version == Base58.Prefix.PubkeyAddress) || (chain != "main" && version == Base58.Prefix.PubkeyAddressTestnet))
              assert(Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(data) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil) == bin)
            case '2' | '3' =>
              val (version, data) = Base58Check.decode(encoded)
              assert((chain == "main" && version == Base58.Prefix.ScriptAddress) || (chain != "main" && version == Base58.Prefix.ScriptAddressTestnet))
              assert(Script.write(OP_HASH160 :: OP_PUSHDATA(data) :: OP_EQUAL :: Nil) == bin)
          }
        }
      }
      case unexpected => throw new IllegalArgumentException(s"don't know how to parse $unexpected")
    }
  }
}
