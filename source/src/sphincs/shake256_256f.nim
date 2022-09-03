##
## Fast SPHINCS⁺ SHAKE256 scheme with 254-bit security and 49216 byte signatures.
##

const
  n* = 32 ## The security parameter in bytes.
  h* = 68 ## The height of the hypertree.
  d* = 17 ## The number of layers in the hypertree.
  a* = 10 ## The log of the number of leaves of a FORS tree.
  k* = 30 ## The number of trees in FORS.
  w* = 16 ## The Winternitz parameter.

include ./private/sphincs_shake256
