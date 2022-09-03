##
## Small SPHINCS⁺ SHAKE256 scheme with 196-bit security and 17064 byte signatures.
##

const
  n* = 24 ## The security parameter in bytes.
  h* = 64 ## The height of the hypertree.
  d* = 8 ## The number of layers in the hypertree.
  a* = 16 ## The log of the number of leaves of a FORS tree.
  k* = 14 ## The number of trees in FORS.
  w* = 16 ## The Winternitz parameter.

include ./private/sphincs_shake256
