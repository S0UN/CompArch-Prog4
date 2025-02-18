#include "syntax_verifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <strings.h>
#include "arraylist.h"
#include "label_table.h"
#include "line.h"

#define MEM (512 * 1024)
#define NUM_REGISTERS 32
#define START_ADDRESS 1000

// Integer Arithmetic Instructions
void add(uint64_t *rd, uint64_t rs, uint64_t rt)
{
    *rd = rs + rt;
}
void addi(uint64_t *rd, uint64_t L)
{
    *rd = *rd + L;
}
void sub(uint64_t *rd, uint64_t rs, uint64_t rt)
{
    *rd = rs - rt;
}
void subi(uint64_t *rd, uint64_t L)
{
    *rd = *rd - L;
}
void mul(uint64_t *rd, uint64_t rs, uint64_t rt)
{
    *rd = rs * rt;
}
void div_(uint64_t *rd, uint64_t rs, uint64_t rt)
{
    *rd = rs / rt;
}

// Logic Instructions
void and_(uint64_t *rd, uint64_t rs, uint64_t rt)
{
    *rd = rs & rt;
}
void or_(uint64_t *rd, uint64_t rs, uint64_t rt)
{
    *rd = rs | rt;
}
void xor_(uint64_t *rd, uint64_t rs, uint64_t rt)
{
    *rd = rs ^ rt;
}
void not_(uint64_t *rd, uint64_t rs)
{
    *rd = ~rs;
}
void shftr(uint64_t *rd, uint64_t rs, uint64_t rt)
{
    *rd = rs >> rt;
}
void shftri(uint64_t *rd, uint64_t L)
{
    *rd = *rd >> L;
}
void shftl(uint64_t *rd, uint64_t rs, uint64_t rt)
{
    *rd = rs << rt;
}
void shftli(uint64_t *rd, uint64_t L)
{
    *rd = *rd << L;
}

// Control Instructions
void br(uint64_t *pc, uint64_t rd)
{
    *pc = rd;
}
void brr(uint64_t *pc, uint64_t rd)
{
    *pc += rd;
}
void brr_L(uint64_t *pc, int64_t L)
{
    *pc += L;
}
void brnz(uint64_t *pc, uint64_t rd, uint64_t rs)
{
    *pc = (rs != 0) ? rd : (*pc + 4);
}
void call(uint64_t *pc, uint64_t *stack, uint64_t rd)
{
    stack[-1] = *pc + 4;
    *pc = rd;
}
void return_(uint64_t *pc, uint64_t *stack)
{
    *pc = stack[-1];
}
void brgt(uint64_t *pc, uint64_t rd, uint64_t rs, uint64_t rt)
{
    *pc = (rs > rt) ? rd : (*pc + 4);
}

// Data Movement Instructions
void mov(uint64_t *rd, uint64_t rs)
{
    *rd = rs;
}
void mov_L(uint64_t *rd, uint64_t L) { *rd = (*rd & ~(0xFFF << 52)) | (L << 52); }
void mov_mem(uint64_t *rd, uint64_t *mem, uint64_t rs, uint64_t L)
{
    *rd = mem[rs + L];
}
void store_mem(uint64_t *mem, uint64_t rd, uint64_t rs, uint64_t L)
{
    mem[rd + L] = rs;
}

// Floating Point Instructions
void addf(double *rd, double rs, double rt)
{
    *rd = rs + rt;
}
void subf(double *rd, double rs, double rt)
{
    *rd = rs - rt;
}
void mulf(double *rd, double rs, double rt)
{
    *rd = rs * rt;
}
void divf(double *rd, double rs, double rt)
{
    *rd = rs / rt;
}

void firstRead(void *ptr, size_t size, size_t count, FILE *file)
{
    size_t bytesRead;
    uint64_t programCounter = START_ADDRESS;
    while ((bytesRead = fread((char *)ptr + programCounter, size, count, file)) > 0)
    {
        programCounter += 4;
    }
}
void secondPass(char *memory, uint64_t *registers)
{
    uint64_t programCounter = START_ADDRESS;
    while (memory[programCounter] != NULL)
    {
        uint32_t instruction = *((uint32_t *)(memory + programCounter));

        // Print instruction in binary
        printf("Instruction (Binary): ");
        printBinary(instruction);
        printf("\n");

        uint8_t opcode = (instruction >> 27) & 0x1F; // Extract first 5 bits (0-4)
        uint8_t rd = (instruction >> 22) & 0x1F;    // Extract bits 5-9
        uint8_t rs = (instruction >> 17) & 0x1F;    // Extract bits 10-14
        uint8_t rt = (instruction >> 12) & 0x1F;    // Extract bits 15-19
        uint16_t L = instruction & 0xFFF;          // Extract bits 20-31

        switch (opcode)
        {
        case 0x18:
            printf("ADD Instruction: rd=%u, rs=%u, rt=%u\n", rd, rs, rt);
            break;
        case 0x19:
            printf("ADDI Instruction: rd=%u, L=%u\n", rd, L);
            break;
        case 0x1A:
            printf("SUB Instruction: rd=%u, rs=%u, rt=%u\n", rd, rs, rt);
            break;
        case 0x1B:
            printf("SUBI Instruction: rd=%u, L=%u\n", rd, L);
            break;
        case 0x1C:
            printf("MUL Instruction: rd=%u, rs=%u, rt=%u\n", rd, rs, rt);
            break;
        case 0x1D:
            printf("DIV Instruction: rd=%u, rs=%u, rt=%u\n", rd, rs, rt);
            break;
        case 0x00:
            printf("AND Instruction: rd=%u, rs=%u, rt=%u\n", rd, rs, rt);
            break;
        case 0x01:
            printf("OR Instruction: rd=%u, rs=%u, rt=%u\n", rd, rs, rt);
            break;
        case 0x02:
            printf("XOR Instruction: rd=%u, rs=%u, rt=%u\n", rd, rs, rt);
            break;
        case 0x03:
            printf("NOT Instruction: rd=%u, rs=%u\n", rd, rs);
            break;
        default:
            printf("Unknown opcode: 0x%X\n", opcode);
            break;
        }

        programCounter += 4; // Move to the next instruction (4-byte aligned)
    }
}

int main(int argc, char *argv[])
{
    char *memory = (char *)calloc(MEM, sizeof(char));
    if (memory == NULL)
    {
        printf("Memory allocation failed \n");
        return 1;
    }

    uint64_t *registers = (uint64_t *)calloc(NUM_REGISTERS, sizeof(uint64_t));

    if (registers == NULL)
    {
        printf("Memory allocation failed!\n");
        return 1;
    }

    registers[31] = (uint64_t)memory;

    FILE *file = fopen("data.bin", "rb"); // Change this to be the actual binary file
    if (file == NULL)
    {
        printf("Error opening file\n");
        return 1;
    }

    firstRead(memory, 4, 1, file);

    fclose(file);
    free(memory);
    free(registers);

    return 0;
}
