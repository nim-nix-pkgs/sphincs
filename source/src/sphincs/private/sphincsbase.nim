import endians, math

proc lg(x: Natural): int =
  ## For x a non-negative real number returns the logarithm to base 2 of x.
  var x = x
  while x > 1:
    inc result
    x = x shr 1

proc toByte(x: Natural; result: var openArray[byte]) =
  ## 2.4. Integer to Byte Conversion
  ## For x and y non-negative integers, we define Z = toByte(x, y) to be the y-byte string
  ## containing the binary representation of x in big-endian byte-order.
  for i in countdown(result.high, 0):
    result[result.high-i] = byte((x shr (8*i)) and 0xff)

proc base_w(result: var openArray[int]; x: openarray[byte]; w: Natural) =
  ## 2.5. Strings of Base-w Numbers (Function base_w)
  ## A byte string can be considered as a string of base w numbers, i.e. integers in the set {0, . . . , w−
  ## 1}. The correspondence is defined by the function base_w(X, w, out_len) as follows. Let X be
  ## a len_X- byte string, and w is an element of the set {4, 16, 256}, then base_w(X, w, out_len)
  ## outputs an array of out_len integers between 0 and w − 1 (Figure 1). The length out_len is
  ## REQUIRED to be less than or equal to 8 ∗ len_X/ log(w).
  assert(w in {4, 16, 256})
  assert(result.len <= (8 * x.len div lg(w)))
  var
    bytesIn, bytesOut, bits: int
    total: uint
  for i in 0..result.high:
    if bits == 0:
      total = (uint)x[bytesIn]
      inc bytesIn
      bits.inc 8
    bits.dec lg(w)
    result[bytesOut] = (int)(total shr bits) and (w-1)
    inc bytesOut

proc bits(M: openArray[byte]; start, count: int): int64 =
  let
    A = start
    B = start + count
  for i in (A div 8)..(B div 8):
    result = (result shl 8) or M[i].int64
  let b = B mod 8
  if b != 0: result = result shr (8-b)
  let mask = not (result.high shl (B-A))
  result = result and mask

type
  AddressWord = uint32
  Address = array[8, AddressWord]
    ## SPHINCS⁺ tree address
  AddressType = enum
    WOTS_HASH = 0, WOTS_PK = 1, TREE = 2, FORS_TREE = 3, FORS_ROOTS = 4.AddressWord

proc initAdrs(t: AddressType): Address =
  result[4] = t.AddressWord

proc getLayerAddress(a: Address): int = a[0].int
proc setLayerAddress(a: var Address; i: int) = a[0] = i.AddressWord

proc getTreeAddress(a: Address): int = a[3].int
proc setTreeAddress(a: var Address; i: int64) =
  a[2] = (AddressWord)i shr 32
  a[3] = (AddressWord)i

proc getType(adrs: Address): AddressType = adrs[4].AddressType

proc setType(adrs: var Address; t: AddressType) =
  ## Change the type word of an address.
  adrs[4] = t.AddressWord
  adrs[5] = 0
  adrs[6] = 0
  adrs[7] = 0

proc setChainAddress(a: var Address; address: int) =
  assert(a.getType == WOTS_HASH)
  a[6] = (AddressWord)address

proc getKeyPairAddress(a: Address): int =
  assert(a.getType != TREE)
  a[5].int

proc setKeyPairAddress(a: var Address; keyPair: SomeInteger) =
  assert(a.getType != TREE)
  a[5] = (AddressWord)keyPair

proc setHashAddress(a: var Address; i: int) =
  assert(a.getType == WOTS_HASH)
  a[7] = i.AddressWord

proc getTreeHeight(a: Address): int =
  assert(a.getType() in {TREE, FORS_TREE})
  a[6].int

proc setTreeHeight(a: var Address; i : int) =
  assert(a.getType() in {TREE, FORS_TREE})
  a[6] = i.AddressWord

proc getTreeIndex(a: var Address): int =
  assert(a.getType() in {TREE, FORS_TREE})
  a[7].int

proc setTreeIndex(a: var Address; i: int) =
  assert(a.getType() in {TREE, FORS_TREE})
  a[7] = i.AddressWord

proc copySubTree(x: var Address; y: Address) =
  for i in 0..3:
    x[i] = y[i]

proc copyKeyPair(x: var Address; y: Address) =
  for i in 0..3:
    x[i] = y[i]
  x[5] = y[5]

type
  Nbytes* = array[n, byte]

  SK* = object {.packed.}
    seed*: Nbytes
    prf*: Nbytes
      ## Secret key

  PK* = object {.packed.}
    seed*: Nbytes
    root*: Nbytes
      ## Public key

  KeyPair* = object {.packed.}
    sk*: SK
    pk*: PK
      ## Secret and public Keypair.
      ## Both keys need to be retained for signing,
      ## the public key is not fully derived from the secret.

const
  wotsLen1 = (int)ceil(8*n / lg(w))
  wotsLen2 = (int)floor(lg(wotsLen1*(w-1)) / lg(w)) + 1
  wotsLen = wotsLen1+wotsLen2

  partialDigestBytes = (int)floor((k*a + 7) / 8)
  treeIndexBytes = (int)floor((h - h/d + 7) / 8)
  leafIndexBytes = (int)floor((h/d + 7) / 8)

  m = partialDigestBytes + treeIndexBytes + leafIndexBytes
    ## Output length of Hmsg in bytes.
