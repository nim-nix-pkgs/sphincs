#
# WOTS + One-Time Signatures
#

proc chain(input: Nbytes, i, s: int; pk: PK; adrs: Address): Nbytes =
  ## Compute an iteration of F on a n-byte input using
  ## a WOTS+ hash address and a public seed.
  var adrs = adrs
  assert((i+s) <= (w-1))
  result = input
  for j in i..<min(i+s, w):
    adrs.setHashAddress(j)
    result = F(pk, adrs, result)

proc wots_SKgen(sk: SK; adrs: Address): Nbytes =
  var adrs = adrs
  adrs.setHashAddress(0)
  PRF(sk, adrs)

proc wots_PKgen(sk: Sk; pk: PK; adrs: Address): array[wotsLen, Nbytes] =
  ## Generate a WOTS+ public key.
  var adrs = adrs
  for i in 0..<wotsLen:
    adrs.setChainAddress(i)
    let sk = wots_SKgen(sk, adrs)
    result[i] = chain(sk, 0, w - 1, pk, adrs)

proc wots_checksum(lengths: openArray[int]): array[wotsLen2, int] =
  var csum = 0

  for i in 0..<wotsLen1:
    csum = csum + w - 1 - lengths[i]
    # compute checksum

  csum = csum shl (8 - ((wotsLen2 * lg(w) ) mod 8))
    # convert csum to base w

  const len2Bytes = (int)ceil( float( wotsLen2 * lg(w) ) / 8)
  var b: array[len2Bytes, byte]
  csum.toByte(b)
  base_w(result, b, w)

proc wots_sign(M: Nbytes; sk: SK; pk: PK; adrs: Address): array[wotsLen, Nbytes] =
  ## Generate a WOTS+ signature on message M.
  var
    adrs = adrs
    lengths: array[wotsLen1, int]
  base_w(lengths, M, w)
    # convert message to base w

  for i in 0..<wotsLen1:
    adrs.setChainAddress(i)
    let prf = PRF(sk, adrs)
    result[i] = chain(prf, 0, lengths[i], pk, adrs)

  let csum = lengths.wots_checksum
  for i in wotsLen1..<wotsLen:
    adrs.setChainAddress(i)
    let prf = PRF(sk, adrs)
    result[i] = chain(prf, 0, csum[i-wotsLen1], pk, adrs)

proc wots_pkFromSig(sig: array[wotsLen,Nbytes]; M: Nbytes; pk: PK; adrs: var Address): array[wotsLen, Nbytes] =
  ## Compute a WOTS+ public key from a message and its signature.
  var lengths: array[wotsLen1, int]
  base_w(lengths, M, w)
    # convert message to base w

  for i in 0..<wotsLen1:
    adrs.setChainAddress(i)
    result[i] = chain(sig[i], lengths[i], w - 1 - lengths[i], pk, adrs)

  let csum = lengths.wots_checksum
  for i in wotsLen1..<wotsLen:
    adrs.setChainAddress(i)
    result[i] = chain(sig[i], csum[i-wotsLen1], w - 1 - csum[i-wotsLen1], pk, adrs)

#
# The SPHINCS + Hypertree
#

type GenLeafProc = proc(sk: SK; pk: PK; idx: int; adrs: Address): Nbytes

proc isOdd(x: int): bool {.inline.} = bool(x and 1)

type
  TreeNode = tuple[node: Nbytes; height: int]

proc treeHash(root: var Nbytes; authPath: var openArray[Nbytes];
              stack: var openArray[TreeNode];
              sk: SK; pk: PK, leafIdx, idxOffset: int;
              genLeaf: GenLeafProc; adrs: Address) =
  ## For a given leaf index, computes the authentication path and
  ## the resulting root node using Merkle's TreeHash algorithm.
  var
    treeAdrs = adrs
    offset, idx, treeIdx: int

  for idx in 0..<(1 shl (stack.len-1)):
    stack[offset].node = genLeaf(sk, pk, idx+idxOffset, treeAdrs)
      # Add the next leaf node to the stack
    stack[offset].height = 0
    inc offset
    if (leafIdx xor 0x1) == idx:
      # if this is a node we need it for the auth path
      authPath[0] = stack[offset-1].node
    while (1 < offset) and (stack[offset-1].height == stack[offset-2].height):
      # while the top-most nodes are of equal height...
      treeIdx = idx shr (stack[offset-1].height+1)
        # compute index of the new node, in the new layer

      treeAdrs.setTreeHeight(stack[offset-1].height + 1)
      treeAdrs.setTreeIndex(treeIdx + (idxOffset shr (stack[offset-1].height + 1)))
        # set the address of the node we're creating
      stack[offset-2].node = H(pk, treeAdrs, stack[offset-2].node, stack[offset-1].node)
        # hash the top-most nodes from the stack together
      dec offset
      inc stack[offset-1].height
        # note that the top-most node is now one layer higher
      if ((leafIdx shr stack[offset-1].height) xor 0x1) == treeIdx:
        # if this is a node we need for the auth path...
        authPath[stack[offset - 1].height] = stack[offset-1].node
  root = stack[0].node

proc wotsGenLeaf(sk: SK; pk: PK; adrsIdx: int; treeAdrs: Address): Nbytes =
  ## Computes the leaf at a given address. First generates the WOTS
  ## key pair, then computes leaf by hashing horizontally.
  var
    wotsAdrs = initAdrs(WOTS_HASH)
    wotsPkAdrs = initAdrs(WOTS_PK)
  wotsAdrs.copySubTree(treeAdrs)
  wotsAdrs.setKeyPairAddress(adrsIdx)
  wotsPkAdrs.copyKeyPair(wotsAdrs)
  let wotsPk = wots_PKgen(sk, pk, wotsAdrs)
  T_len(pk, wotsPkAdrs, wotsPk)

proc xmss_PKgen(sk: SK; pk: PK; adrs: Address): Nbytes =
  ## Generate an XMSS public key.
  # 4.1.4. XMSS Public Key Generation
  const height = h div d
  var auth: array[height, Nbytes]
    # not used, but `treeHash` computes both a root and authPath
  var treeStack: array[height+1, TreeNode]
  treeHash(result, auth, treeStack, sk, pk, 0, 0, wotsGenLeaf, adrs)

type XmssSignature = object {.packed.}
  # 4.1.5. XMSS Signature
  sig: array[wotsLen, Nbytes]
  auth: array[h div d, Nbytes]

# HT: The Hypertee (sic)

proc ht_PKgen(sk: SK; pk: PK): Nbytes =
  ## Generate an HT public key.
  var adrs = initAdrs(TREE)
  adrs.setLayerAddress(d-1)
  xmss_PKgen(sk, pk, adrs)

type HtSignature = array[d, XmssSignature]

#
# FORS: Forest Of Random Subsets
#

proc computeRoot(leaf: Nbytes; leafIdx, idxOffset: int;
                 authPath: openArray[Nbytes],
                 height: int;
                 pk: PK; adrs: Address): Nbytes =
  var
    nodes: (Nbytes, Nbytes)
    adrs = adrs
    leafIdx = leafIdx
    idxOffset = idxOffset

  if leafIdx.isOdd:
    # If leafIdx is odd, current path element is a right child
    # and authPath has to go left. 
    nodes[1] = leaf
    nodes[0] = authPath[0]
  else:
    # Otherwise it is the other way around.
    nodes[0] = leaf
    nodes[1] = authPath[0]

  for i in 0..(height-2):
    leafIdx = leafIdx shr 1
    idxOffset = idxOffset shr 1
    adrs.setTreeHeight(i+1)
    adrs.setTreeIndex(leafIdx+idxOffset)
    if leafIdx.isOdd:
      nodes[1] = H(pk, adrs, nodes[0], nodes[1])
      nodes[0] = authPath[i+1]
    else:
      nodes[0] = H(pk, adrs, nodes[0], nodes[1])
      nodes[1] = authPath[i+1]
  leafIdx = leafIdx shr 1
  idxOffset = idxOffset shr 1
  adrs.setTreeHeight(height)
  adrs.setTreeIndex(leafIdx+idxOffset)
  H(pk, adrs, nodes[0], nodes[1])
    # the last iteration is exceptional; we do not copy an authPath node

const
  forsHeight = a
  forsTrees = k
  forsMsgBytes = (forsHeight*forsTrees+7) div 8

proc fors_SKgen(sk: SK; adrs: Address): Nbytes =
  ## Compute a FORS private key value
  # 5.2. FORS Private Key
  PRF(sk, adrs)

proc messageIndices(msg: openArray[byte]): array[forsTrees, int] =
  #assert(msg.len > forsHeight*forsTrees div 8)
  var offset: int
  for i in 0..<forsTrees:
    for _ in 1..forsHeight:
      result[i] =  (result[i] shl 1) xor ((msg[offset shr 3].int shr (offset and 0x7)) and 0x1)
      inc offset

type ForsSignature = array[k, tuple[
  key: Nbytes,
  auth: array[a, Nbytes]]]

proc fors_SKtoLeaf(pk: PK, adrs: var Address; sk: Nbytes): Nbytes =
  F(pk, adrs, sk)

proc forsGenLeaf(sk: SK; pk: PK; addrIdx: int; adrs: Address): Nbytes =
  ## Procedure for generating leaves of FORS tree.
  var forsLeafAdrs = adrs
  forsLeafAdrs.setType(FORS_TREE)
  forsLeafAdrs.setTreeIndex(addrIdx)
  forsLeafAdrs.setKeyPairAddress(adrs.getKeyPairAddress)
  result = fors_SKtoLeaf(pk, forsLeafAdrs, fors_SKgen(sk, forsLeafAdrs))

proc forsSign(sig: var ForsSignature; public: var Nbytes; msg: openArray[byte]; sk: SK; pk: PK; adrs: Address) =
  ## Generate a FORS signature and public key on n-byte string M.
  let indices = messageIndices msg
  var
    roots: array[forsTrees, Nbytes]
    forsTreeAdrs = adrs
    forsPkAdrs = adrs
  forsTreeAdrs.setType(FORS_TREE)
  forsTreeAdrs.setKeyPairAddress(adrs.getKeyPairAddress)
  forsPkAdrs.setType(FORS_ROOTS)
  forsPkAdrs.setKeyPairAddress(adrs.getKeyPairAddress)

  for i in 0..<k:
    let idxOff = i * (1 shl forsHeight)
    forsTreeAdrs.setTreeHeight(0)
    forsTreeAdrs.setTreeIndex(indices[i] + idxOff)
    sig[i].key = fors_SKgen(sk, forsTreeAdrs)
    var treeStack: array[forsHeight+1, TreeNode]
    treeHash(roots[i], sig[i].auth, treeStack, sk, pk, indices[i], idxOff, forsGenLeaf, forsTreeAdrs)

  public = T_k(pk, forsPkAdrs, roots)
    # Hash horizontally across all tree roots to derive the public key.

proc fors_pkFromSig(sig: ForsSignature; msg: openArray[byte]; pk: PK; adrs: var Address): Nbytes =
  ## Compute a FORS public key from a FORS signature
  let indices = messageIndices msg
  var
    roots: array[forsTrees, Nbytes]
    forsTreeAdrs = adrs
    forsPkAdrs = adrs

  forsTreeAdrs.setType(FORS_TREE)
  forsTreeAdrs.setKeyPairAddress(adrs.getKeyPairAddress)

  forsPkAdrs.setType(FORS_ROOTS)
  forsPkAdrs.setKeyPairAddress(adrs.getKeyPairAddress)

  for i in 0..<forsTrees:
    let idxOff = i * (1 shl forsHeight)
    forsTreeAdrs.setTreeHeight(0)
    forsTreeAdrs.setTreeIndex(indices[i] + idxOff)

    let leaf = fors_SKtoLeaf(pk, forsTreeAdrs, sig[i].key)
      # derive the leaf from the included secret key part

    roots[i] = computeRoot(leaf, indices[i], idxOff, sig[i].auth, a, pk, forsTreeAdrs)
      # derive the corresponding root node of this tree

  T_k(pk, forsPkAdrs, roots)
    # Hash horizontally across all tree roots to derive the public key.

const
  spxTreeHeight = h div d
  signatureSize* = n + k*(n+a*n) + d*(wotsLen*n+(h div d)*n)
    ## Size of SPHINCS⁺ signture minus the message. The message
    ## is appended during signing so it should be no longer than a
    ## hash digest.

type
  SpxSignature = object {.packed.}
    R: Nbytes
    FORS: ForsSignature
    HT: HtSignature

  RandomBytes* = proc(buf: pointer; size: int)
    ## Procedure type for collecting entropy during
    ## key generation and signing. Please supply
    ## a procedure that writes `size` random bytes to `buf`.

{.pop.} # allow runtime checks

proc sign*(pair: KeyPair; M: string|openArray[byte]|seq[byte]; optRand: Nbytes): string {.noSideEffect.} =
  ## Generate a SPHINCS⁺ signature.
  ## The signature will be deterministic unless `optRand` is randomized.
  let msgOff = sizeof(SpxSignature)
  result = newString(msgOff+M.len)

  let sig = cast[ptr SpxSignature](result[0].addr)
  sig.R = PRFmsg(pair.sk, optRand, M)
    # generate randomizer

  let (md, mTree, mLeaf) = Hmsg(sig.R, pair.pk, M)
  var
    root: Nbytes
    treeAdrs = initAdrs(TREE)
    wotsAdrs = initAdrs(WOTS_HASH)

  wotsAdrs.setTreeAddress(mTree)
  wotsAdrs.setKeyPairAddress(mLeaf)
  forsSign(sig.FORS, root, md, pair.sk, pair.pk, wotsAdrs)
    # FORS sign
  block:
    var
      idxTree = mTree
      idxLeaf = mLeaf
    for i in 0..<d:
      treeAdrs.setLayerAddress(i)
      treeAdrs.setTreeAddress(idxTree)
      wotsAdrs.copySubtree(treeAdrs)
      wotsAdrs.setKeypairAddress(idxLeaf)

      sig.HT[i].sig = wots_sign(root, pair.sk, pair.pk, wotsAdrs)
      var treeStack: array[spxTreeHeight+1, TreeNode]
      treeHash(root, sig.HT[i].auth, treeStack, pair.sk, pair.pk,
        idxLeaf, 0, wotsGenLeaf, treeAdrs)

      idxLeaf = (int32)idxTree and ((1 shl spxTreeHeight) - 1)
      idxTree = idxTree shr spxTreeHeight
        # update the indices for the next layer
  for i in 0..<M.len:
    result[msgOff+i] = (char)M[i]
    # append signature with message

proc sign*(pair: KeyPair; M: string|openArray[byte]|seq[byte]; rand: RandomBytes): string {.noSideEffect.} =
  ## Generate a SPHINCS⁺ signature. The passed `rand` procedure is used to
  ## create non-deterministic signatures which are generally recommended.
  var optRand: Nbytes
  rand(optRand.addr, n)
  pair.sign(M, optRand)

proc verify(pk: PK; sigStr: var string): (bool, string) {.noSideEffect.} =
  assert(sigStr.len > sizeof(SpxSignature))
  let
    sig = cast[ptr SpxSignature](sigStr[0].addr)
    M = sigStr[sizeof(SpxSignature)..sigStr.high]
  var
    root, leaf: Nbytes
    wotsAdrs = initAdrs(WOTS_HASH)
    treeAdrs = initAdrs(TREE)
    wotsPkAdrs = initAdrs(WOTS_PK)
    (md, idxTree, idxLeaf) = Hmsg(sig.R, pk, M)

  wotsAdrs.setTreeAddress(idxTree)
  wotsAdrs.setKeyPairAddress(idxLeaf)

  root = fors_pkFromSig(sig.FORS, md, pk, wotsAdrs)

  for i in 0..<d:
    # for each subtree
    treeAdrs.setLayerAddress(i)
    treeAdrs.setTreeAddress(idxTree)

    wotsAdrs.copySubtree(treeAdrs)
    wotsAdrs.setKeypairAddress(idxLeaf)
    wotsPkAdrs.copyKeyPair(wotsAdrs)

    let wotsPk = wots_pkFromSig(sig.HT[i].sig, root, pk, wotsAdrs)
    leaf = T_len(pk, wotsPkAdrs, wotsPk)
    root = computeRoot(leaf, idxLeaf, 0, sig.HT[i].auth, h div d, pk, treeAdrs)

    idxLeaf = (int32)idxTree and ((1 shl spxTreeHeight) - 1)
    idxTree = idxTree shr spxTreeHeight
      # update the indices for the next layer

  if root == pk.root:
    (true, M)
  else:
    (false, "")

proc verify*(pk: PK; sig: string): (bool, string) {.noSideEffect.} =
  ## Verify a SPHINCS⁺ signature.
  ## The signed message is assumed to be stored at the
  ## end of the signature string.
  var sig = sig
  pk.verify sig

proc generateKeypair*(seedProc: RandomBytes): KeyPair {.noSideEffect.} =
  ## Generate a SPHINCS⁺ key pair.
  seedProc(result.addr, n*3)
    # Randomize the seeds and PRF
  result.pk.root = ht_PKgen(result.sk, result.pk)
    # Compute root node of top-most subtree
