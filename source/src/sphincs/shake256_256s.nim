##
## Small SPHINCS⁺ SHAKE256 scheme with 255-bit security and 29792 byte signatures.
##

const
  n* = 32 ## The security parameter in bytes.
  h* = 64 ## The height of the hypertree.
  d* = 8 ## The number of layers in the hypertree.
  a* = 14 ## The log of the number of leaves of a FORS tree.
  k* = 22 ## The number of trees in FORS.
  w* = 16 ## The Winternitz parameter.

include ./private/sphincs_shake256
