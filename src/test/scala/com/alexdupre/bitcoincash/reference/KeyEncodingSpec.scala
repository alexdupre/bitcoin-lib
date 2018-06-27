package com.alexdupre.bitcoincash.reference

import java.io.InputStreamReader

import com.alexdupre.bitcoincash.Crypto.PrivateKey
import com.alexdupre.bitcoincash.{Base58, Base58Check, BinaryData}
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JBool, JString, JValue}
import org.json4s.jackson.JsonMethods
import org.scalatest.FunSuite

import scala.util.Try

class KeyEncodingSpec extends FunSuite {
  implicit val format = DefaultFormats

  test("valid keys") {
    val stream = classOf[KeyEncodingSpec].getResourceAsStream("/data/base58_keys_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].map(KeyEncodingSpec.check)
  }

  test("invalid keys") {
    val stream = classOf[KeyEncodingSpec].getResourceAsStream("/data/base58_keys_invalid.json")
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
      case Base58.Prefix.SecretKey | Base58.Prefix.SecretKeyTestnet => Try(PrivateKey(bin)).isSuccess
      case Base58.Prefix.PubkeyAddress | Base58.Prefix.PubkeyAddressTestnet => bin.length == 20
      case _ => false
    }
  } getOrElse (false)

  def check(data: List[JValue]): Unit = {
    data match {
      case JString(encoded) :: JString(hex) :: obj :: Nil => {
        val JBool(isPrivkey) = obj \ "isPrivkey"
        val isCompressed = obj \ "isCompressed" match {
          case JBool(value) => value
          case _ => None
        }
        val JBool(testNet) = obj \ "isTestnet"
        if (isPrivkey) {
          val (version, data) = Base58Check.decode(encoded)
          assert(version == Base58.Prefix.SecretKey || version == Base58.Prefix.SecretKeyTestnet)
          assert(BinaryData(data.take(32)) == BinaryData(hex))
        } else {
          val JString(addrType) = obj \ "addrType"
          encoded.head match {
            case '1' | 'm' | 'n' =>
              val (version, data) = Base58Check.decode(encoded)
              assert(version == Base58.Prefix.PubkeyAddress || version == Base58.Prefix.PubkeyAddressTestnet)
              assert(data == BinaryData(hex))
            case '2' | '3' =>
              val (version, data) = Base58Check.decode(encoded)
              assert(version == Base58.Prefix.ScriptAddress || version == Base58.Prefix.ScriptAddressTestnet)
              assert(data == BinaryData(hex))
          }
        }
      }
      case unexpected => throw new IllegalArgumentException(s"don't know how to parse $unexpected")
    }
  }
}
