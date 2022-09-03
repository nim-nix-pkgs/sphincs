##
## Small SPHINCS⁺ SHAKE256 scheme with 133-bit security and 8080 byte signatures.
##

const
  n* = 16 ## The security parameter in bytes.
  h* = 64 ## The height of the hypertree.
  d* = 8 ## The number of layers in the hypertree.
  a* = 15 ## The log of the number of leaves of a FORS tree.
  k* = 10 ## The number of trees in FORS.
  w* = 16 ## The Winternitz parameter.

include private/sphincs_shake256
