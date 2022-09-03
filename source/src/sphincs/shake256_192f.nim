##
## Fast SPHINCS⁺ SHAKE256 scheme with 194-bit security and 34664 byte signatures.
##

const
  n* = 24 ## The security parameter in bytes.
  h* = 66 ## The height of the hypertree.
  d* = 22 ## The number of layers in the hypertree.
  a* = 8 ## The log of the number of leaves of a FORS tree.
  k* = 33 ## The number of trees in FORS.
  w* = 16 ## The Winternitz parameter.

include ./private/sphincs_shake256
