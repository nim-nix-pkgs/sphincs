SPHINCS⁺ is a stateless hash-based signature scheme that
has been submitted to the NIST post-quantum crypto project.

This library contains Nim implementations for the six SHAKE256
variants of SPHINCS⁺. Performance will be abysmal until the
Keccak implementation is optimized.

Each signature scheme is implemented as a seperate module.
Multiple scheme modules may be imported at once, the correct
procedures will be deduced from the keypair type.

A procedure for supplying random bytes must be provided
for key generation and non-deterministic signing. This
allows the compiler to enforce the `noSideEffect` pragma
for all exported procedures. This helps mitigate (or
implement) side-channels.

```
import sphincs/shake256_128s
import sphincs/shake256_256f

proc genEntropy(p: pointer; size: int) =
  ## Don't try this at home.
  zeroMem(p, size)

let
  pair1 = shake256_128s.generateKeypair(genEntropy)
  pair2 = shake256_256f.generateKeypair(genEntropy)
  sig1 = pair1.sign("foo", genEntropy)
  sig2 = pair2.sign("bar", genEntropy)
  (valid1, msg1) = pair1.pk.verify(sig1)
  (valid2, msg2) = pair2.pk.verify(sig2)
assert(valid1)
assert(msg2 == "bar")
```

Tests are available via the `nimble test` task and a makefile
is provided for recreating the test-vectors from the reference
implementation.
