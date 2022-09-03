{.push checks: off.} # painfully slow

include ./sphincsbase.nim

import sha3

proc sha3_update(ctx: var SHA3; adrs: Address) =
  var buf: array[4, byte]
  for w in adrs.items:
    w.toByte(buf)
    sha3_update(ctx, buf)

proc F(pk: PK; adrs: Address; M1: Nbytes): Nbytes =
  var ctx: SHA3
  sha3_init(ctx, SHA3_SHAKE256, n)
  sha3_update(ctx, pk.seed)
  sha3_update(ctx, adrs)
  sha3_final(ctx, result)
    # create a bitmask in result space
  for i in 0..<n:
    result[i] = result[i] xor M1[i]
    # apply bitmask to message
  sha3_init(ctx, SHA3_SHAKE256, n)
  sha3_update(ctx, pk.seed)
  sha3_update(ctx, adrs)
  sha3_update(ctx, result)
    # hash again with bitmasked message
  sha3_final(ctx, result)

proc H(pk: PK; adrs: Address; M1, M2: Nbytes): Nbytes =
  var
    bitmasked: array[2*n, byte]
    ctx: SHA3
  sha3_init(ctx, SHA3_SHAKE256, n*2)
  sha3_update(ctx, pk.seed)
  sha3_update(ctx, adrs)
  sha3_final(ctx, bitmasked)
    # create bitmask
  for i in 0..<n:
    bitmasked[i] = bitmasked[i] xor M1[i]
  for i in n..<n*2:
    bitmasked[i] = bitmasked[i] xor M2[i-n]
    # apply bitmask to messages
  sha3_init(ctx, SHA3_SHAKE256, n)
  sha3_update(ctx, pk.seed)
  sha3_update(ctx, adrs)
  sha3_update(ctx, bitmasked)
    # hash again with bitmasked message
  sha3_final(ctx, result)

proc T_k(pk: PK; adrs: Address; M: array[k, Nbytes]): Nbytes =
  var
    bitmasked: array[M.len*n, byte]
    ctx: SHA3
  sha3_init(ctx, SHA3_SHAKE256, M.len*n)
  sha3_update(ctx, pk.seed)
  sha3_update(ctx, adrs)
  sha3_final(ctx, bitmasked)
    # create bitmask
  var off: int
  for i in 0..<M.len:
    for j in 0..<n:
      bitmasked[off] = bitmasked[off] xor M[i][j]
      inc off
    # apply bitmask to messages
  sha3_init(ctx, SHA3_SHAKE256, n)
  sha3_update(ctx, pk.seed)
  sha3_update(ctx, adrs)
  sha3_update(ctx, bitmasked)
    # hash again with bitmasked message
  sha3_final(ctx, result)

proc T_len(pk: PK; adrs: Address; M: array[wotsLen, Nbytes]): Nbytes =
  var
    bitmasked: array[M.len*n, byte]
    ctx: SHA3
  sha3_init(ctx, SHA3_SHAKE256, M.len*n)
  sha3_update(ctx, pk.seed)
  sha3_update(ctx, adrs)
  sha3_final(ctx, bitmasked)
    # create bitmask
  var off: int
  for i in 0..<M.len:
    for j in 0..<n:
      bitmasked[off] = bitmasked[off] xor M[i][j]
      inc off
    # apply bitmask to messages
  sha3_init(ctx, SHA3_SHAKE256, n)
  sha3_update(ctx, pk.seed)
  sha3_update(ctx, adrs)
  sha3_update(ctx, bitmasked)
    # hash again with bitmasked message
  sha3_final(ctx, result)

proc PRFmsg(sk: SK; optRand: Nbytes; M: string|openArray[byte]|seq[byte]): Nbytes =
  ## Pseudorandom function to generate randomness for message compression.
  var ctx: SHA3
  sha3_init(ctx, SHA3_SHAKE256, n)
  sha3_update(ctx, sk.prf)
  sha3_update(ctx, optRand)
  sha3_update(ctx, M, M.len)
  sha3_final(ctx, result)

proc Hmsg(R: Nbytes; pk: PK; M: string|openArray[byte]|seq[byte]): (array[partialDigestBytes,byte], int64, int32) =
  ## Keyed hash funcion for compression messages to be signed.
  var
    digest: array[m, byte]
    ctx: SHA3
  sha3_init(ctx, SHA3_SHAKE256, m)
  sha3_update(ctx, R)
  sha3_update(ctx, pk.seed)
  sha3_update(ctx, pk.root)
  sha3_update(ctx, M, M.len)
  sha3_final(ctx, digest)

  copyMem(result[0].addr, digest.addr, partialDigestBytes)

  # take the last bits from the tree and leaf index regions
  bigEndian64(result[1].addr, digest[digest.len-8-leafIndexBytes].addr)
  when h - h div d < 64:
    result[1] = result[1] and (not(int64.high shl (h - h div d)))
  bigEndian32(result[2].addr, digest[digest.len-4].addr)
  result[2] = result[2] and (not(int32.high shl (h div d)))

proc PRF(sk: SK; adrs: Address): Nbytes =
  ## Pseudorandom function for key generation.
  var ctx: SHA3
  sha3_init(ctx, SHA3_SHAKE256, n)
  sha3_update(ctx, sk.seed)
  sha3_update(ctx, adrs)
  sha3_final(ctx, result)

include ./sphincsinstantiate.nim
