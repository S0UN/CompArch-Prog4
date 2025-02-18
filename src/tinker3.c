#include "syntax_verifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <strings.h>
#include "arraylist.h"
#include "label_table.h"
#include "line.h"


// Integer Arithmetic Instructions
void add(uint64_t *rd, uint64_t rs, uint64_t rt) { *rd = rs + rt; }
void addi(uint64_t *rd, uint64_t L) { *rd = *rd + L; }
void sub(uint64_t *rd, uint64_t rs, uint64_t rt) { *rd = rs - rt; }
void subi(uint64_t *rd, uint64_t L) { *rd = *rd - L; }
void mul(uint64_t *rd, uint64_t rs, uint64_t rt) { *rd = rs * rt; }
void div_(uint64_t *rd, uint64_t rs, uint64_t rt) { *rd = rs / rt; }

// Logic Instructions
void and_(uint64_t *rd, uint64_t rs, uint64_t rt) { *rd = rs & rt; }
void or_(uint64_t *rd, uint64_t rs, uint64_t rt) { *rd = rs | rt; }
void xor_(uint64_t *rd, uint64_t rs, uint64_t rt) { *rd = rs ^ rt; }e
void not_(uint64_t *rd, uint64_t rs) { *rd = ~rs; }
void shftr(uint64_t *rd, uint64_t rs, uint64_t rt) { *rd = rs >> rt; }
void shftri(uint64_t *rd, uint64_t L) { *rd = *rd >> L; }
void shftl(uint64_t *rd, uint64_t rs, uint64_t rt) { *rd = rs << rt; }
void shftli(uint64_t *rd, uint64_t L) { *rd = *rd << L; }

// Control Instructions
void br(uint64_t *pc, uint64_t rd) { *pc = rd; }
void brr(uint64_t *pc, uint64_t rd) { *pc += rd; }
void brr_L(uint64_t *pc, int64_t L) { *pc += L; }
void brnz(uint64_t *pc, uint64_t rd, uint64_t rs) { *pc = (rs != 0) ? rd : (*pc + 4); }
void call(uint64_t *pc, uint64_t *stack, uint64_t rd) { stack[-1] = *pc + 4; *pc = rd; }
void return_(uint64_t *pc, uint64_t *stack) { *pc = stack[-1]; }
void brgt(uint64_t *pc, uint64_t rd, uint64_t rs, uint64_t rt) { *pc = (rs > rt) ? rd : (*pc + 4); }

// Data Movement Instructions
void mov(uint64_t *rd, uint64_t rs) { *rd = rs; }
void mov_L(uint64_t *rd, uint64_t L) { *rd = (*rd & ~(0xFFF << 52)) | (L << 52); }
void mov_mem(uint64_t *rd, uint64_t *mem, uint64_t rs, uint64_t L) { *rd = mem[rs + L]; }
void store_mem(uint64_t *mem, uint64_t rd, uint64_t rs, uint64_t L) { mem[rd + L] = rs; }

// Floating Point Instructions
void addf(double *rd, double rs, double rt) { *rd = rs + rt; }
void subf(double *rd, double rs, double rt) { *rd = rs - rt; }
void mulf(double *rd, double rs, double rt) { *rd = rs * rt; }
void divf(double *rd, double rs, double rt) { *rd = rs / rt; }

// Privileged Instructions
void halt() { while (1); }
void trap(uint64_t *mode) { *mode = 1; }
void rte(uint64_t *mode) { *mode = 0; }
void input(uint64_t *rd, uint64_t *input_ports, uint64_t rs) { *rd = input_ports[rs]; }
void output(uint64_t *output_ports, uint64_t rd, uint64_t rs) { output_ports[rd] = rs; }

