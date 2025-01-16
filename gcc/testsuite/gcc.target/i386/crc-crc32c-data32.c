/* { dg-do run } */
/* { dg-options "-mcrc32 -O2 -fdump-rtl-dfinish -fdump-tree-crc" } */
/* { dg-skip-if "" { *-*-* } { "-flto"} } */

#include "../aarch64/crc-crc32c-data32.c"

/* { dg-final { scan-tree-dump "calculates CRC!" "crc"} } */
/* { dg-final { scan-tree-dump-times "Couldn't generate faster CRC code." 0 "crc"} } */
/* { dg-final { scan-rtl-dump "UNSPEC_CRC32" "dfinish"} } */
/* { dg-final { scan-assembler "crc32l" } } */
