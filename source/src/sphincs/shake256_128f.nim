##
## Fast SPHINCS⁺ SHAKE256 scheme with 128-bit security and 16976 byte signatures.
##

const
  n* = 16 ## The security parameter in bytes.
  h* = 60 ## The height of the hypertree.
  d* = 20 ## The number of layers in the hypertree.
  a* = 9 ## The log of the number of leaves of a FORS tree.
  k* = 30 ## The number of trees in FORS.
  w* = 16 ## The Winternitz parameter.

include private/sphincs_shake256
