import sphincs/shake256_128f
import sphincs/shake256_128s
import sphincs/shake256_192f
import sphincs/shake256_192s
import sphincs/shake256_256f
import sphincs/shake256_256s

import parseutils, strutils, strtabs, unittest
import ./hex

{.compile: "rng.c".}
{.passL: "-lcrypto".}

proc randombytes_init(entropy_input, personalization_string: ptr cuchar;
                      security_strength: cint) {.importc, header:"rng.h".}
  ## Initialize the reference RNG.

proc randombytes(x: ptr cuchar; xlen: culonglong): cint {.importc, header:"rng.h".}
  ## Collect entropy from the reference RNG.

proc randomBytes(p: pointer; size: Natural) =
  let r = randombytes(cast[ptr cuchar](p), (culonglong)size)
  doAssert(r == 0, "reference randombytes failed")

proc zeroBytes(p: pointer; size: Natural) =
  zeroMem(p, size)

proc parseHex(result: var string; val: string) =
  result.setLen(val.len div 2)
  hex.decode(val, result)

proc parseHex(result: var seq[byte]; val: string) =
  result.setLen(val.len div 2)
  hex.decode(val, result)

template katTest(path: string; keyGen: untyped) =
  ## Use the keyGen procedure to select the scheme implementation.
  suite path:
    var
      count, mlen, smlen: int
      key = ""
      val = ""
      msg = ""
      sm = ""
      buf = newSeq[byte]()
      pair = keyGen(zeroBytes)
    for line in lines(path):
      if line == "":
        key.setLen(0)
        val.setLen(0)
        buf.setLen(0)
        pair = keyGen(zeroBytes)
      else:
        key.setLen(0)
        let off = line.parseUntil(key, " = ")
        if not key.validIdentifier:
          continue
        discard line.parseWhile(val, HexDigits, off+3)
        case key
        of "count":
          count = parseInt val
        of "seed":
          buf.parseHex(val)
          doAssert(buf.len == 48)
          randombytes_init(cast[ptr cuchar](buf[0].addr), nil, 256)
          pair = keyGen(randombytes)
        of "pk":
          buf.parseHex(val)
          doAssert(equalMem(pair.pk.addr, buf[0].addr, buf.len))
        of "sk":
          buf.parseHex(val)
          doAssert(equalMem(pair.sk.addr, buf[0].addr, buf.len))
        of "mlen":
          mlen = parseInt val
        of "msg":
          msg.parseHex(val)
          doAssert(msg.len == mlen)
        of "smlen":
          smlen = parseInt val
        of "sm":
          # verification is faster than signing, so do that first
          sm.parseHex(val)
          doAssert(sm.len == smlen)
          test "verify " & $count:
            let (valid, M) = pair.pk.verify(sm)
            doAssert(valid)
            doAssert(M == msg)
          test "sign " & $count:
            let sig = pair.sign(msg, randombytes)
            doAssert(sig == sm)
        else:
          discard

katTest("tests/shake256-128f/PQCsignKAT_64.rsp", shake256_128f.generateKeypair)
katTest("tests/shake256-128s/PQCsignKAT_64.rsp", shake256_128s.generateKeypair)
katTest("tests/shake256-192f/PQCsignKAT_96.rsp", shake256_192f.generateKeypair)
katTest("tests/shake256-192s/PQCsignKAT_96.rsp", shake256_192s.generateKeypair)
katTest("tests/shake256-256f/PQCsignKAT_128.rsp", shake256_256f.generateKeypair)
katTest("tests/shake256-256s/PQCsignKAT_128.rsp", shake256_256s.generateKeypair)
