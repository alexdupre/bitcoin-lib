package com.alexdupre.bitcoincash

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.math.BigInteger

import org.bitcoin.{NativeSecp256k1, Secp256k1Context}
import org.slf4j.LoggerFactory
import org.spongycastle.asn1.sec.SECNamedCurves
import org.spongycastle.asn1.{ASN1Integer, DERSequenceGenerator}
import org.spongycastle.crypto.Digest
import org.spongycastle.crypto.digests.{RIPEMD160Digest, SHA1Digest, SHA256Digest, SHA512Digest}
import org.spongycastle.crypto.macs.HMac
import org.spongycastle.crypto.params.{ECDomainParameters, ECPrivateKeyParameters, ECPublicKeyParameters, KeyParameter}
import org.spongycastle.crypto.signers.{ECDSASigner, HMacDSAKCalculator}
import org.spongycastle.math.ec.{ECCurve, ECPoint}
import scodec.bits.ByteVector

import scala.util.Try

object Crypto {
  val params = SECNamedCurves.getByName("secp256k1")
  val curve = new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
  val halfCurveOrder = params.getN().shiftRight(1)
  val zero = BigInteger.valueOf(0)
  val one = BigInteger.valueOf(1)

  private val logger = LoggerFactory.getLogger(classOf[Secp256k1Context])
  if (Secp256k1Context.isEnabled) {
    logger.info("secp256k1 library successfully loaded")
  } else {
    logger.info("couldn't find secp256k1 library, defaulting to spongycastle")
  }

  def fixSize(data: ByteVector): ByteVector32 = ByteVector32(data.padLeft(32))

  /**
    * Secp256k1 private key, which a 32 bytes value
    * We assume that private keys are compressed i.e. that the corresponding public key is compressed
    *
    * @param value value to initialize this key with
    */
  case class PrivateKey(value: ByteVector32) {
    def add(that: PrivateKey): PrivateKey = if (Secp256k1Context.isEnabled)
      PrivateKey(ByteVector.view(NativeSecp256k1.privKeyTweakAdd(value.toArray, that.value.toArray)))
    else
      PrivateKey(bigInt.add(that.bigInt).mod(Crypto.curve.getN))

    def subtract(that: PrivateKey): PrivateKey = if (Secp256k1Context.isEnabled)
      PrivateKey(ByteVector.view(NativeSecp256k1.privKeyTweakAdd(value.toArray, NativeSecp256k1.privKeyNegate(that.value.toArray))))
    else
      PrivateKey(bigInt.subtract(that.bigInt).mod(Crypto.curve.getN))

    def multiply(that: PrivateKey): PrivateKey = if (Secp256k1Context.isEnabled)
      PrivateKey(ByteVector.view(NativeSecp256k1.privKeyTweakMul(value.toArray, that.value.toArray)))
    else
      PrivateKey(bigInt.multiply(that.bigInt).mod(Crypto.curve.getN))

    def +(that: PrivateKey): PrivateKey = add(that)

    def -(that: PrivateKey): PrivateKey = subtract(that)

    def *(that: PrivateKey): PrivateKey = multiply(that)

    def isZero: Boolean = bigInt == BigInteger.ZERO

    // used only if secp256k1 is not available
    lazy val bigInt = new BigInteger(1, value.toArray)

    def publicKey: PublicKey = if (Secp256k1Context.isEnabled) {
      PublicKey.fromBin(ByteVector.view(NativeSecp256k1.computePubkey(value.toArray)))
    } else {
      PublicKey(ByteVector.view(params.getG().multiply(bigInt).getEncoded(true)))
    }

    /**
      *
      * @param prefix Private key prefix
      * @return the private key in Base58 (WIF) compressed format
      */
    def toBase58(prefix: Byte) = Base58Check.encode(prefix, value.bytes :+ 1.toByte)
  }

  object PrivateKey {
    def apply(data: ByteVector): PrivateKey = new PrivateKey(ByteVector32(data.take(32)))

    def apply(data: BigInteger): PrivateKey = {
      new PrivateKey(fixSize(ByteVector.view(data.toByteArray.dropWhile(_ == 0.toByte))))
    }

    /**
      *
      * @param data serialized private key in bitcoin format
      * @return the de-serialized key
      */
    def fromBin(data: ByteVector): (PrivateKey, Boolean) = {
      val compressed = data.length match {
        case 32 => false
        case 33 if data.last == 1.toByte => true
      }
      (PrivateKey(data.take(32)), compressed)
    }

    def fromBase58(value: String, prefix: Byte): (PrivateKey, Boolean) = {
      require(Set(Base58.Prefix.SecretKey, Base58.Prefix.SecretKeyTestnet).contains(prefix), "invalid base 58 prefix for a private key")
      val (`prefix`, data) = Base58Check.decode(value)
      fromBin(data)
    }
  }

  /**
    * Secp256k1 Public key
    * We assume that public keys are always compressed
    *
    * @param value serialized public key, in compressed format (33 bytes)
    */
  case class PublicKey(value: ByteVector) {
    require(value.length == 33)
    require(isPubKeyValidLax(value))


    def hash160: ByteVector = Crypto.hash160(value)

    def isValid: Boolean = isPubKeyValidStrict(this.value)

    def add(that: PublicKey): PublicKey = if (Secp256k1Context.isEnabled) {
      PublicKey.fromBin(ByteVector.view(NativeSecp256k1.pubKeyAdd(value.toArray, that.value.toArray)))
    } else {
      PublicKey(ecpoint.add(that.ecpoint).normalize())
    }

    def add(that: PrivateKey): PublicKey = if (Secp256k1Context.isEnabled) {
      PublicKey.fromBin(ByteVector.view(NativeSecp256k1.privKeyTweakAdd(value.toArray, that.value.toArray)))
    } else {
      add(that.publicKey)
    }

    def subtract(that: PublicKey): PublicKey = if (Secp256k1Context.isEnabled) {
      PublicKey.fromBin(ByteVector.view(NativeSecp256k1.pubKeyAdd(value.toArray, NativeSecp256k1.pubKeyNegate(that.value.toArray))))
    } else {
      PublicKey(ecpoint.subtract(that.ecpoint).normalize())
    }

    def multiply(that: PrivateKey): PublicKey = if (Secp256k1Context.isEnabled) {
      PublicKey.fromBin(ByteVector.view(NativeSecp256k1.pubKeyTweakMul(value.toArray, that.value.toArray)))
    } else {
      PublicKey(ecpoint.multiply(that.bigInt).normalize())
    }

    def +(that: PublicKey): PublicKey = add(that)

    def -(that: PublicKey): PublicKey = subtract(that)

    def *(that: PrivateKey): PublicKey = multiply(that)

    def toUncompressedBin: ByteVector = if (Secp256k1Context.isEnabled) {
      ByteVector.view(NativeSecp256k1.parsePubkey(value.toArray))
    } else {
      ByteVector.view(ecpoint.getEncoded(false))
    }

    override def toString = value.toHex

    // used only if secp256k1 is not available
    lazy val ecpoint = curve.getCurve.decodePoint(value.toArray)
  }

  object PublicKey {
    def apply(data: ECPoint): PublicKey = new PublicKey(ByteVector.view(data.getEncoded(true)))

    /**
      * @param raw        serialized value of this public key (a point)
      * @param checkValid indicates whether or not we check that this is a valid public key; this should be used
      *                   carefully for optimization purposes
      * @return
      */
    def apply(raw: ByteVector, checkValid: Boolean): PublicKey = fromBin(raw, checkValid)

    def fromBin(input: ByteVector, checkValid: Boolean = true): PublicKey = {
      if (checkValid) require(isPubKeyValidStrict(input))

      input.length match {
        case 33 => PublicKey(input)
        case 65 => toCompressedUnsafe(input.toArray)
      }
    }

    /**
      * This function initializes a public key from a compressed/uncompressed representation without doing validity checks.
      *
      * This will always convert the key to its compressed representation
      *
      * Note that this mutates the input array!
      *
      * @param key 33 or 65 bytes public key (will be mutated)
      * @return an immutable compressed public key
      */
    private def toCompressedUnsafe(key: Array[Byte]): PublicKey = {
      key.length match {
        case 65 if key(0) == 4 || key(0) == 6 || key(0) == 7 =>
          key(0) = if ((key(64) & 0x01) != 0) 0x03.toByte else 0x02.toByte
          new PublicKey(ByteVector(key, 0, 33))
        case 33 if key(0) == 2 || key(0) == 3 =>
          new PublicKey(ByteVector(key, 0, 33))
        case _ =>
          throw new IllegalArgumentException(s"key must be 33 or 65 bytes")
      }
    }
  }


  /**
    * Computes ecdh using secp256k1's variant: sha256(priv * pub serialized in compressed format)
    *
    * @param priv private value
    * @param pub  public value
    * @return ecdh(priv, pub) as computed by libsecp256k1
    */
  def ecdh(priv: PrivateKey, pub: PublicKey): ByteVector32 = {
    if (Secp256k1Context.isEnabled)
      ByteVector32(ByteVector.view(NativeSecp256k1.createECDHSecret(priv.value.toArray, pub.value.toArray)))
    else
      Crypto.sha256(ByteVector.view(pub.multiply(priv).ecpoint.getEncoded(true)))
  }

  def hmac512(key: ByteVector, data: ByteVector): ByteVector = {
    val mac = new HMac(new SHA512Digest())
    mac.init(new KeyParameter(key.toArray))
    mac.update(data.toArray, 0, data.length.toInt)
    val out = new Array[Byte](64)
    mac.doFinal(out, 0)
    ByteVector.view(out)
  }

  def hash(digest: Digest)(input: ByteVector): ByteVector = {
    digest.update(input.toArray, 0, input.length.toInt)
    val out = new Array[Byte](digest.getDigestSize)
    digest.doFinal(out, 0)
    ByteVector.view(out)
  }

  def sha1 = hash(new SHA1Digest) _

  def sha256 = (x: ByteVector) => ByteVector32(hash(new SHA256Digest)(x))

  def ripemd160 = hash(new RIPEMD160Digest) _

  /**
    * 160 bits bitcoin hash, used mostly for address encoding
    * hash160(input) = RIPEMD160(SHA256(input))
    *
    * @param input array of byte
    * @return the 160 bits BTC hash of input
    */
  def hash160(input: ByteVector): ByteVector = ripemd160(sha256(input))

  /**
    * 256 bits bitcoin hash
    * hash256(input) = SHA256(SHA256(input))
    *
    * @param input array of byte
    * @return the 256 bits BTC hash of input
    */
  def hash256(input: ByteVector): ByteVector32 = ByteVector32(sha256(sha256(input)))

  private def encodeSignatureCompact(r: BigInteger, s: BigInteger): ByteVector64 = {
    ByteVector64(ByteVector.view(r.toByteArray.dropWhile(_ == 0)).padLeft(32) ++ ByteVector.view(s.toByteArray.dropWhile(_ == 0)).padLeft(32))
  }

  private def encodeSignatureCompact(t: (BigInteger, BigInteger)): ByteVector = encodeSignatureCompact(t._1, t._2)

  def isValidDERSignatureEncoding(sig: ByteVector): Boolean = {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.

    // Minimum and maximum size constraints.
    if (sig.size < 8) return false
    if (sig.size > 72) return false

    // A signature is of type 0x30 (compound).
    if (sig(0) != 0x30.toByte) return false

    // Make sure the length covers the entire signature.
    if (sig(1) != sig.size - 2) return false

    // Check whether the R element is an integer.
    if (sig(2) != 0x02.toByte) return false

    // Extract the length of the R element.
    val lenR = sig(3)

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false

    // Negative numbers are not allowed for R.
    if ((sig(4) & 0x80.toByte) != 0) return false

    // Make sure the length of the R element is consistent with the signature
    // size.
    // Remove:
    // * 1 byte for the coumpound type.
    // * 1 byte for the length of the signature.
    // * 2 bytes for the integer type of R and S.
    // * 2 bytes for the size of R and S.
    // * 1 byte for S itself.
    if (lenR > sig.size - 7) return false

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig(4) == 0x00) && (sig(5) & 0x80) == 0) return false

    // S's definition starts after R's definition:
    // * 1 byte for the coumpound type.
    // * 1 byte for the length of the signature.
    // * 1 byte for the size of R.
    // * lenR bytes for R itself.
    // * 1 byte to get to S.
    val startS = lenR + 4

    // Check whether the S element is an integer.
    if (sig(startS) != 0x02.toByte) return false

    // Extract the length of the S element.
    val lenS = sig(startS + 1)

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false

    // Negative numbers are not allowed for S.
    if ((sig(startS + 2) & 0x80) != 0) return false

    // Verify that the length of S is consistent with the size of the signature
    // including metadatas:
    // * 1 byte for the integer type of S.
    // * 1 byte for the size of S.
    if (startS + lenS + 2 != sig.size) return false

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig(startS + 2) == 0x00) && (sig(startS + 3) & 0x80) == 0) return false

    return true
  }

  def isLowDERSignature(sig: ByteVector): Boolean = isValidDERSignatureEncoding(sig) && {
    val (_, s) = decodeSignatureFromDER(sig)
    s.compareTo(halfCurveOrder) <= 0
  }

  private def normalizeSignature(r: BigInteger, s: BigInteger): (BigInteger, BigInteger) = {
    val s1 = if (s.compareTo(halfCurveOrder) > 0) curve.getN().subtract(s) else s
    (r, s1)
  }

  def normalizeSignature(sig: ByteVector): ByteVector = {
    val (r, s) = decodeSignatureFromDER(sig)
    encodeSignatureCompact(normalizeSignature(r, s))
  }

  def checkDataSignatureEncoding(sig: ByteVector, flags: Int): Boolean = {
    if (sig.isEmpty) true
    else checkRawSignatureEncoding(sig, flags)
  }

  def checkTransactionSignatureEncodingImpl(sig: ByteVector, flags: Int, verifyFunction: ByteVector => Boolean): Boolean = {
    import ScriptFlags._
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (sig.isEmpty) true
    else if (!verifyFunction(sig.dropRight(1))) false
    else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0) {
      if (!isDefinedHashtypeSignature(sig)) false
      else {
        val usesForkId = isForkId(getHashType(sig))
        val forkIdEnabled = (flags & SCRIPT_ENABLE_SIGHASH_FORKID) != 0
        if (!forkIdEnabled && usesForkId) false
        else if (forkIdEnabled && !usesForkId) false
        else true
      }
    }
    else true
  }

  def checkTransactionSignatureEncoding(sig: ByteVector, flags: Int): Boolean = {
    checkTransactionSignatureEncodingImpl(sig, flags, checkRawSignatureEncoding(_, flags))
  }

  def checkTransactionECDSASignatureEncoding(sig: ByteVector, flags: Int): Boolean = {
    checkTransactionSignatureEncodingImpl(sig, flags, checkRawECDSASignatureEncoding(_, flags))
  }

  def checkTransactionSchnorrSignatureEncoding(sig: ByteVector, flags: Int): Boolean = {
    checkTransactionSignatureEncodingImpl(sig, flags, checkRawSchnorrSignatureEncoding(_, flags))
  }

  def isSchnorrSig(sig: ByteVector): Boolean = sig.size == 64

  def checkRawECDSASignatureEncoding(sig: ByteVector, flags: Int): Boolean = {
    import ScriptFlags._
    if (isSchnorrSig(sig)) {
      // In an ECDSA-only context, 64-byte signatures are banned when
      // Schnorr flag set.
      false
    } else if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !isValidDERSignatureEncoding(sig)) false
    else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !isLowDERSignature(sig)) false
    else true
  }

  def checkRawSchnorrSignatureEncoding(sig: ByteVector, flags: Int): Boolean = {
    if (isSchnorrSig(sig)) true
    else false
  }

  def checkRawSignatureEncoding(sig: ByteVector, flags: Int): Boolean = {
    if (isSchnorrSig(sig)) {
      // In a generic-signature context, 64-byte signatures are interpreted
      // as Schnorr signatures (always correctly encoded).
      true
    } else checkRawECDSASignatureEncoding(sig, flags)
  }

  def checkPubKeyEncoding(key: ByteVector, flags: Int): Boolean = {
    if ((flags & ScriptFlags.SCRIPT_VERIFY_STRICTENC) != 0) require(isPubKeyCompressedOrUncompressed(key), "invalid public key")
    // Only compressed keys are accepted when SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE is enabled.
    if ((flags & ScriptFlags.SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE) != 0) require(isPubKeyCompressed(key), "public key must be compressed")
    true
  }

  /**
    *
    * @param key serialized public key
    * @return true if the key is valid. Please not that this performs very basic tests and does not check that the
    *         point represented by this key is actually valid.
    */
  def isPubKeyValidLax(key: ByteVector): Boolean = key.length match {
    case 65 if key(0) == 4 || key(0) == 6 || key(0) == 7 => true
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _ => false
  }

  /**
    *
    * @param key serialized public key
    * @return true if the key is valid. This check is much more expensive than its lax version since here we check that
    *         the public key is a valid point on the secp256k1 curve
    */
  def isPubKeyValidStrict(key: ByteVector): Boolean = isPubKeyValidLax(key) && {
    if (Secp256k1Context.isEnabled)
      NativeSecp256k1.parsePubkey(key.toArray).length == 65
    else
      curve.getCurve.decodePoint(key.toArray).normalize().isValid
  }

  def isPubKeyCompressedOrUncompressed(key: ByteVector): Boolean = key.length match {
    case 65 if key(0) == 4 => true
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _ => false
  }

  def isPubKeyCompressed(key: ByteVector): Boolean = key.length match {
    case 33 if key(0) == 2 || key(0) == 3 => true
    case _ => false
  }

  def getHashType(sig: ByteVector): Int = if (sig.isEmpty) 0 else sig.last & 0xff

  def isDefinedHashtypeSignature(sig: ByteVector): Boolean = if (sig.isEmpty) false
  else {
    val hashType = getHashType(sig) & (~(SIGHASH_ANYONECANPAY | SIGHASH_FORKID))
    if (hashType < SIGHASH_ALL || hashType > SIGHASH_SINGLE) false else true
  }

  /**
    * An ECDSA signature is a (r, s) pair. Bitcoin uses DER encoded signatures
    *
    * @param blob sigbyte data
    * @return the decoded (r, s) signature
    */
  private def decodeSignatureFromDER(blob: ByteVector): (BigInteger, BigInteger) = {
    decodeSignatureFromDERLax(blob)
  }

  private def decodeSignatureFromDERLax(input: ByteArrayInputStream): (BigInteger, BigInteger) = {
    require(input.read() == 0x30)

    def readLength: Int = {
      val len = input.read()
      if ((len & 0x80) == 0) len else {
        var n = len - 0x80
        var len1 = 0
        while (n > 0) {
          len1 = (len1 << 8) + input.read()
          n = n - 1
        }
        len1
      }
    }

    readLength
    require(input.read() == 0x02)
    val lenR = readLength
    val r = new Array[Byte](lenR)
    input.read(r)
    require(input.read() == 0x02)
    val lenS = readLength
    val s = new Array[Byte](lenS)
    input.read(s)
    (new BigInteger(1, r), new BigInteger(1, s))
  }

  private def decodeSignatureFromDERLax(input: ByteVector): (BigInteger, BigInteger) = decodeSignatureFromDERLax(new ByteArrayInputStream(input.toArray))

  private def decodeSignatureCompact(signature: ByteVector64): (BigInteger, BigInteger) = {
    val r = new BigInteger(1, signature.take(32).toArray)
    val s = new BigInteger(1, signature.takeRight(32).toArray)
    (r, s)
  }

  def compact2der(signature: ByteVector64): ByteVector = {
    val r = new BigInteger(1, signature.take(32).toArray)
    val s = new BigInteger(1, signature.takeRight(32).toArray)
    val (r1, s1) = normalizeSignature(r, s)
    val bos = new ByteArrayOutputStream(73)
    val seq = new DERSequenceGenerator(bos)
    seq.addObject(new ASN1Integer(r1))
    seq.addObject(new ASN1Integer(s1))
    seq.close()
    ByteVector.view(bos.toByteArray)
  }

  def der2compact(signature: ByteVector): ByteVector64 = {
    val (r, s) = decodeSignatureFromDERLax(signature)
    val (r1, s1) = normalizeSignature(r, s)
    ByteVector64(ByteVector.view(r1.toByteArray.dropWhile(_ == 0)).padLeft(32) ++ ByteVector.view(s1.toByteArray.dropWhile(_ == 0)).padLeft(32))
  }

  /**
    * @param data      data
    * @param signature signature
    * @param publicKey public key
    * @return true is signature is valid for this data with this public key
    */
  def verifySignature(data: ByteVector, signature: ByteVector, publicKey: PublicKey, flags: Int): Boolean = {
    if (signature.size == 64) {
      verifySchnorrSignature(data, signature, publicKey)
    } else {
      verifyECDSASignature(data, signature, publicKey)
    }
  }

  def verifyECDSASignature(data: ByteVector, signature: ByteVector, publicKey: PublicKey): Boolean = Try {
    if (Secp256k1Context.isEnabled) {
      val signature1 = normalizeSignature(signature)
      NativeSecp256k1.verify(data.toArray, signature1.toArray, publicKey.value.toArray)
    } else {
      val (r, s) = decodeSignatureFromDER(signature)
      require(r.compareTo(one) >= 0, "r must be >= 1")
      require(r.compareTo(curve.getN) < 0, "r must be < N")
      require(s.compareTo(one) >= 0, "s must be >= 1")
      require(s.compareTo(curve.getN) < 0, "s must be < N")

      val signer = new ECDSASigner
      val params = new ECPublicKeyParameters(publicKey.ecpoint, curve)
      signer.init(false, params)
      signer.verifySignature(data.toArray, r, s)
    }
  }.toOption.getOrElse(false)

  def verifySchnorrSignature(data: ByteVector, signature: ByteVector, publicKey: PublicKey): Boolean = Try {
    require(signature.size == 64, "signature size must be 64")
    require(data.size == 32, "data size must be 32")
    val (rx, s) = signature.splitAt(32)
    require(new BigInteger(1, rx.toArray).compareTo(curve.getCurve.getField.getCharacteristic) < 0, "r must be < P")
    require(new BigInteger(1, s.toArray).compareTo(curve.getN) < 0, "s must be < N")
    // Compute e = int(hash(bytes(r) || bytes(P) || m)) mod n
    val e = new BigInteger(1, sha256(rx ++ publicKey.value ++ data).toArray).mod(curve.getN)
    require(e.compareTo(one) >= 0, "e must be >= 1")
    // Let R = sG - eP.
    val R = PrivateKey(s).publicKey.ecpoint subtract publicKey.ecpoint.multiply(e)
    val p = params.getCurve.getField.getCharacteristic
    def jacobi(n: BigInteger) = n.modPow(p.shiftRight(1), p)
    val jacobiY = R.getCurve.getCoordinateSystem match {
      case ECCurve.COORD_JACOBIAN | ECCurve.COORD_JACOBIAN_MODIFIED =>
        jacobi(R.getYCoord.toBigInteger.multiply(R.getZCoord(0).toBigInteger).mod(p))
      case _ =>
        jacobi(R.normalize.getYCoord.toBigInteger)
    }
    val rxMatches = R.getCurve.getCoordinateSystem match {
      case ECCurve.COORD_JACOBIAN | ECCurve.COORD_JACOBIAN_MODIFIED =>
        R.getXCoord.toBigInteger.compareTo(new BigInteger(1, rx.toArray).multiply(R.getZCoord(0).toBigInteger.pow(2)).mod(p)) == 0
      case _ =>
        R.normalize().getXCoord.toBigInteger.compareTo(new BigInteger(1, rx.toArray)) == 0
    }
    // Fail if infinite(R) or jacobi(y(R)) ≠ 1 or x(R) ≠ r.
    if (R.isInfinity || jacobiY.compareTo(BigInteger.ONE) != 0 || !rxMatches) false else true
  }.toOption.getOrElse(false)

  /**
    *
    * @param privateKey private key
    * @return the corresponding public key
    */
  def publicKeyFromPrivateKey(privateKey: ByteVector) = PrivateKey(privateKey).publicKey

  /**
    * Sign data with a private key, using RCF6979 deterministic signatures
    *
    * @param data       data to sign
    * @param privateKey private key. If you are using bitcoin "compressed" private keys make sure to only use the first 32 bytes of
    *                   the key (there is an extra "1" appended to the key)
    * @return a signature in compact format (64 bytes)
    */
  def sign(data: Array[Byte], privateKey: PrivateKey): ByteVector64 = {
    if (Secp256k1Context.isEnabled) {
      val bin = NativeSecp256k1.signCompact(data, privateKey.value.toArray)
      ByteVector64(ByteVector.view(bin))
    } else {
      val signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest))
      val privateKeyParameters = new ECPrivateKeyParameters(privateKey.bigInt, curve)
      signer.init(true, privateKeyParameters)
      val Array(r, s) = signer.generateSignature(data)
      val (r1, s1) = if (s.compareTo(halfCurveOrder) > 0) {
        (r, curve.getN().subtract(s)) // if s > N/2 then s = N - s
      } else {
        (r, s)
      }
      encodeSignatureCompact(r1, s1)
    }
  }

  def sign(data: ByteVector, privateKey: PrivateKey): ByteVector64 = sign(data.toArray, privateKey)

  /**
    *
    * @param x x coordinate
    * @return a tuple (p1, p2) where p1 and p2 are points on the curve and p1.x = p2.x = x
    *         p1.y is even, p2.y is odd
    */
  private def recoverPoint(x: BigInteger): (ECPoint, ECPoint) = {
    val x1 = Crypto.curve.getCurve.fromBigInteger(x)
    val square = x1.square().add(Crypto.curve.getCurve.getA).multiply(x1).add(Crypto.curve.getCurve.getB)
    val y1 = square.sqrt()
    val y2 = y1.negate()
    val R1 = Crypto.curve.getCurve.createPoint(x1.toBigInteger, y1.toBigInteger).normalize()
    val R2 = Crypto.curve.getCurve.createPoint(x1.toBigInteger, y2.toBigInteger).normalize()
    if (y1.testBitZero()) (R2, R1) else (R1, R2)
  }

  /**
    * Recover public keys from a signature and the message that was signed. This method will return 2 public keys, and the signature
    * can be verified with both, but only one of them matches that private key that was used to generate the signature.
    *
    * @param signature signature
    * @param message   message that was signed
    * @return a (pub1, pub2) tuple where pub1 and pub2 are candidates public keys. If you have the recovery id  then use
    *         pub1 if the recovery id is even and pub2 if it is odd
    */
  def recoverPublicKey(signature: ByteVector64, message: ByteVector): (PublicKey, PublicKey) = {
    val (r, s) = decodeSignatureCompact(signature)
    val m = new BigInteger(1, message.toArray)

    val (p1, p2) = recoverPoint(r)
    val Q1 = (p1.multiply(s).subtract(Crypto.curve.getG.multiply(m))).multiply(r.modInverse(Crypto.curve.getN))
    val Q2 = (p2.multiply(s).subtract(Crypto.curve.getG.multiply(m))).multiply(r.modInverse(Crypto.curve.getN))
    (PublicKey(Q1), PublicKey(Q2))
  }
}
