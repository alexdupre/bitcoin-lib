package com.alexdupre.litecoin.reference

import com.alexdupre.litecoin.{BinaryData, BlockHeader}
import org.scalatest.FunSuite

class PowSpec extends FunSuite {
  test("calculate next work required") {
    val header = BlockHeader(version = 2, hashPreviousBlock = BinaryData("00" * 32), hashMerkleRoot = BinaryData("00" * 32), time = 0L, bits = 0L, nonce = 0L)

    assert(BlockHeader.calculateNextWorkRequired(header.copy(time = 1262152739, bits = 0x1d00ffff), 1261130161) === 0x1d0361a9L)
    assert(BlockHeader.calculateNextWorkRequired(header.copy(time = 1233061996, bits = 0x1d00ffff), 1231006505) === 0x1d03fffcL)
    assert(BlockHeader.calculateNextWorkRequired(header.copy(time = 1279297671, bits = 0x1c05a3f4), 1279008237) === 0x1c05660aL)
  }
}
