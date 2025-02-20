#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <strings.h>
#include <stdint.h>
#include <inttypes.h>

#define MEM (512 * 1024)
#define NUM_REGISTERS 32
#define START_ADDRESS 0x1000

// Integer Arithmetic Instructions
void exec_add(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    registers[rd] = registers[rs] + registers[rt];
}
void exec_addi(uint8_t rd, uint64_t L, uint64_t *registers)
{
    registers[rd] += L;
}
void exec_sub(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    registers[rd] = registers[rs] - registers[rt];
}
void exec_subi(uint8_t rd, uint64_t L, uint64_t *registers)
{
    registers[rd] -= L;
}
void exec_mul(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    registers[rd] = registers[rs] * registers[rt];
}
void exec_div(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    if (registers[rt] == 0)
    {
        fprintf(stderr, "Simulation error: Division by zero\n");
        exit(1);
    }
    registers[rd] = registers[rs] / registers[rt];
}

// Logic Instructions

void exec_and(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    registers[rd] = registers[rs] & registers[rt];
}
void exec_or(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    registers[rd] = registers[rs] | registers[rt];
}
void exec_xor(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    registers[rd] = registers[rs] ^ registers[rt];
}
void exec_not(uint8_t rd, uint8_t rs, uint64_t *registers)
{
    registers[rd] = ~registers[rs];
}
void exec_shftr(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    registers[rd] = registers[rs] >> registers[rt];
}
void exec_shftri(uint8_t rd, uint64_t L, uint64_t *registers)
{
    registers[rd] = registers[rd] >> L;
}
void exec_shftl(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    registers[rd] = registers[rs] << registers[rt];
}
void exec_shftli(uint8_t rd, uint64_t L, uint64_t *registers)
{
    registers[rd] = registers[rd] << L;
}

// Control Instructions

void exec_br(uint8_t rd, uint64_t *registers, uint64_t *new_pc)
{
    if (registers[rd] >= MEM)
    {
        fprintf(stderr, "Simulation error: Branch target out of bounds\n");
        exit(1);
    }
    *new_pc = registers[rd];
}
void exec_brr(uint8_t rd, uint64_t current_pc, uint64_t *registers, uint64_t *new_pc)
{
    uint64_t target = current_pc + registers[rd];
    if (target >= MEM || target < START_ADDRESS)
    {
        fprintf(stderr, "Simulation error: Branch target out of bounds\n");
        exit(1);
    }
    *new_pc = target;
}
void exec_brrL(uint64_t L, uint64_t current_pc, uint64_t *new_pc)
{
    int32_t offset = (int32_t)L;
    if (offset & 0x800)
    { // sign-extend 12-bit value
        offset |= 0xFFFFF000;
    }
    uint64_t target = current_pc + offset;
    if (target >= MEM || target < START_ADDRESS)
    {
        fprintf(stderr, "Simulation error: Branch target out of bounds\n");
        exit(1);
    }
    *new_pc = target;
}
void exec_brnz(uint8_t rd, uint8_t rs, uint64_t current_pc, uint64_t *registers, uint64_t *new_pc)
{
    if (registers[rs] != 0)
    {
        if (registers[rd] >= MEM || registers[rd] < START_ADDRESS)
        {
            fprintf(stderr, "Simulation error: Branch target out of bounds\n");
            exit(1);
        }
        *new_pc = registers[rd];
    }
    // Otherwise, new_pc remains current_pc + 4
}
void exec_call(uint8_t rd, char *memory, uint64_t *registers, uint64_t current_pc, uint64_t *new_pc)
{
    // Decrement stack pointer by 8 (simulate push)
    if (registers[31] < 8)
    {
        fprintf(stderr, "Simulation error: Stack underflow\n");
        exit(1);
    }
    registers[31] -= 8;
    if (registers[31] + 8 > MEM)
    {
        fprintf(stderr, "Simulation error: Stack pointer out of bounds\n");
        exit(1);
    }
    *((uint64_t *)(memory + registers[31])) = current_pc + 4;
    *new_pc = registers[rd];
}
void exec_return(char *memory, uint64_t *registers, uint64_t *new_pc)
{
    if (registers[31] > MEM - 8)
    {
        fprintf(stderr, "Simulation error: Stack underflow\n");
        exit(1);
    }
    *new_pc = *((uint64_t *)(memory + registers[31]));
    registers[31] += 8;
}
void exec_brgt(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers, uint64_t *new_pc)
{
    if ((int64_t)registers[rs] > (int64_t)registers[rt])
    {
        if (registers[rd] >= MEM || registers[rd] < START_ADDRESS)
        {
            fprintf(stderr, "Simulation error: Branch target out of bounds\n");
            exit(1);
        }
        *new_pc = registers[rd];
    }
    // Otherwise, new_pc remains unchanged (caller will add 4)
}

// Privileged Instruction
bool exec_priv(uint64_t L, uint8_t rd, uint8_t rs, uint64_t *registers, char *memory, uint64_t *pc)
{
    switch (L)
    {
    case 0x0:
        return true;
    case 0x1:
        break;
    case 0x2:
        break;
    case 0x3:
        if (registers[rs] == 0)
        {
            if (scanf("%" SCNu64, &registers[rd]) != 1)
            {
                fprintf(stderr, "Simulation error: Failed to read input\n");
                exit(1);
            }
        }
        break;
    case 0x4:
        if (registers[rd] == 1)
        {
            printf("%" PRIu64, registers[rs]);
            fflush(stdout);
        }
        break;
    default:
        exit(1);
    }
    return false;
}

// Data Movement Instructions

void exec_mov_mem(uint8_t rd, uint8_t rs, uint64_t L, char *memory, uint64_t *registers)
{
    uint64_t addr = registers[rs] + L;
    if (addr % 8 != 0)
    {
        fprintf(stderr, "Simulation error: Unaligned memory access\n");
        exit(1);
    }
    if (addr + 8 > MEM)
    {
        fprintf(stderr, "Simulation error: Memory access out of bounds\n");
        exit(1);
    }
    registers[rd] = *((uint64_t *)(memory + addr));
}
void exec_mov_reg(uint8_t rd, uint8_t rs, uint64_t *registers)
{
    registers[rd] = registers[rs];
}
void exec_mov_L(uint8_t rd, uint64_t L, uint64_t *registers)
{
    registers[rd] &= ~((uint64_t)0xFFF << 52);
    registers[rd] |= (L << 52);
}
void exec_store_mem(uint8_t rd, uint64_t L, uint8_t rs, char *memory, uint64_t *registers)
{
    uint64_t addr = registers[rd] + L;
    if (addr % 8 != 0)
    {
        fprintf(stderr, "Simulation error: Unaligned memory access\n");
        exit(1);
    }
    if (addr + 8 > MEM)
    {
        fprintf(stderr, "Simulation error: Memory access out of bounds\n");
        exit(1);
    }
    *((uint64_t *)(memory + addr)) = registers[rs];
}

// Floating Point Instructions

void exec_addf(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    double a = *((double *)&registers[rs]);
    double b = *((double *)&registers[rt]);
    *((double *)&registers[rd]) = a + b;
}
void exec_subf(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    double a = *((double *)&registers[rs]);
    double b = *((double *)&registers[rt]);
    *((double *)&registers[rd]) = a - b;
}
void exec_mulf(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    double a = *((double *)&registers[rs]);
    double b = *((double *)&registers[rt]);
    *((double *)&registers[rd]) = a * b;
}
void exec_divf(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *registers)
{
    double b = *((double *)&registers[rt]);
    if (b == 0.0)
    {
        fprintf(stderr, "Simulation error: Division by zero (floating point)\n");
        exit(1);
    }
    double a = *((double *)&registers[rs]);
    *((double *)&registers[rd]) = a / b;
}

void firstRead(void *ptr, size_t size, size_t count, FILE *file)
{
    size_t bytesRead;
    uint64_t programCounter = START_ADDRESS;
    while ((bytesRead = fread((char *)ptr + programCounter, size, count, file)) > 0)
    {
        programCounter += 4;
        if (programCounter + 4 > MEM)
        {
            fprintf(stderr, "Simulation error: Program too large for memory\n");
            exit(1);
        }
    }
}

void secondPass(char *memory, uint64_t *registers)
{
    uint64_t pc = START_ADDRESS;
    bool halted = false;
    while (!halted)
    {
 
        if (pc + 4 > MEM)
        {
            fprintf(stderr, "Simulation error: PC out of bounds\n");
            exit(1);
        }
        // Check: Ensure PC is 4-byte aligned
        if (pc % 4 != 0)
        {
            fprintf(stderr, "Simulation error: Unaligned PC\n");
            exit(1);
        }
        // Fetch 4-byte instruction (little-endian)
        uint32_t instruction = *((uint32_t *)(memory + pc));
        // Decode fields
        uint8_t opcode = (instruction >> 27) & 0x1F;
        uint8_t rd = (instruction >> 22) & 0x1F;
        uint8_t rs = (instruction >> 17) & 0x1F;
        uint8_t rt = (instruction >> 12) & 0x1F;
        uint64_t L = instruction & 0xFFF;
        // Default next PC is pc + 4
        uint64_t next_pc = pc + 4;

        switch (opcode)
        {
        // Arithmetic
        case 0x18:
            exec_add(rd, rs, rt, registers);
            break;
        case 0x19:
            exec_addi(rd, L, registers);
            break;
        case 0x1A:
            exec_sub(rd, rs, rt, registers);
            break;
        case 0x1B:
            exec_subi(rd, L, registers);
            break;
        case 0x1C:
            exec_mul(rd, rs, rt, registers);
            break;
        case 0x1D:
            exec_div(rd, rs, rt, registers);
            break;
        // Logical
        case 0x00:
            exec_and(rd, rs, rt, registers);
            break;
        case 0x01:
            exec_or(rd, rs, rt, registers);
            break;
        case 0x02:
            exec_xor(rd, rs, rt, registers);
            break;
        case 0x03:
            exec_not(rd, rs, registers);
            break;
        case 0x04:
            exec_shftr(rd, rs, rt, registers);
            break;
        case 0x05:
            exec_shftri(rd, L, registers);
            break;
        case 0x06:
            exec_shftl(rd, rs, rt, registers);
            break;
        case 0x07:
            exec_shftli(rd, L, registers);
            break;
        // Control
        case 0x08:
            exec_br(rd, registers, &next_pc);
            break;
        case 0x09:
            exec_brr(rd, pc, registers, &next_pc);
            break;
        case 0x0A:
            exec_brrL(L, pc, &next_pc);
            break;
        case 0x0B:
            exec_brnz(rd, rs, pc, registers, &next_pc);
            break;
        case 0x0C:
            exec_call(rd, memory, registers, pc, &next_pc);
            break;
        case 0x0D:
            exec_return(memory, registers, &next_pc);
            break;
        case 0x0E:
            exec_brgt(rd, rs, rt, registers, &next_pc);
            break;
        // Privileged
        case 0x0F:
            if (exec_priv(L, rd, rs, registers, memory, &pc))
            {
                halted = true;
            }
            break;
        // Floating point
        case 0x14:
            exec_addf(rd, rs, rt, registers);
            break;
        case 0x15:
            exec_subf(rd, rs, rt, registers);
            break;
        case 0x16:
            exec_mulf(rd, rs, rt, registers);
            break;
        case 0x17:
            exec_divf(rd, rs, rt, registers);
            break;
        // Data Movement
        case 0x10:
            exec_mov_mem(rd, rs, L, memory, registers);
            break;
        case 0x11:
            exec_mov_reg(rd, rs, registers);
            break;
        case 0x12:
            exec_mov_L(rd, L, registers);
            break;
        case 0x13:
            exec_store_mem(rd, L, rs, memory, registers);
            break;
        default:
            fprintf(stderr, "Simulation error: Unknown opcode 0x%X\n", opcode);
            exit(1);
        }
       if (next_pc < START_ADDRESS)
        {
            fprintf(stderr, "Simulation error: PC underflow\n");
            exit(1);
        }
        pc = next_pc;
 
    }
}

int main(int argc, char *argv[])
{
    // Modified Check: If no file provided, print exactly "Invalid tinker filepath"
    if (argc < 2)
    {
        fprintf(stderr, "Invalid tinker filepath\n");
        return 1;
    }

    char *memory = (char *)calloc(MEM, sizeof(char));
    if (memory == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    uint64_t *registers = (uint64_t *)calloc(NUM_REGISTERS, sizeof(uint64_t));
    if (registers == NULL)
    {
        fprintf(stderr, "Memory allocation failed!\n");
        free(memory);
        return 1;
    }

    // Initialize stack pointer (R31) to point to the top of memory
    registers[31] = (uint64_t)memory;

    FILE *file = fopen(argv[1], "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Invalid tinker filepath\n");
        free(memory);
        free(registers);
        return 1;
    }

    // Load the binary file into memory starting at START_ADDRESS.
    firstRead(memory, 4, 1, file);
    fclose(file);

    // Now call secondPass to simulate execution of the loaded instructions.
    secondPass(memory, registers);

    free(memory);
    free(registers);
    return 0;
}
