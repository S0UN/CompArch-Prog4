#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <strings.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "tinker_file_header.h"

#define MEM (512 * 1024)
#define NUM_REGISTERS 32
#define START_ADDRESS 0x1000

// Global simulated memory and registers.
uint8_t memory[MEM];
uint64_t r[NUM_REGISTERS];

// Global error function.
void error(const char *message)
{
    fprintf(stderr, "Simulation error: %s\n", message);
    exit(1);
}

// Global write function: writes a 64-bit value to memory in little-endian order.
void mem_write(uint64_t address, uint64_t value)
{

    for (int i = 0; i < 8; i++)
    {
        memory[address + i] = (value >> (8 * i)) & 0xFF;
    }
}

uint64_t read(uint64_t address)
{

    uint64_t value = 0;
    for (int i = 0; i < 8; i++)
    {
        value |= ((uint64_t)memory[address + i]) << (8 * i);
    }
    return value;
}

// Integer Arithmetic Instructions
void exec_add(uint8_t rd, uint8_t rs, uint8_t rt)
{
    r[rd] = r[rs] + r[rt];
}
void exec_addi(uint8_t rd, uint64_t L)
{
    r[rd] += L;
}
void exec_sub(uint8_t rd, uint8_t rs, uint8_t rt)
{
    r[rd] = r[rs] - r[rt];
}
void exec_subi(uint8_t rd, uint64_t L)
{
    r[rd] -= L;
}
void exec_mul(uint8_t rd, uint8_t rs, uint8_t rt)
{
    r[rd] = r[rs] * r[rt];
}
void exec_div(uint8_t rd, uint8_t rs, uint8_t rt)
{
    if (r[rt] == 0)
    {
        fprintf(stderr, "Simulation error: Division by zero\n");
        exit(1);
    }
    r[rd] = r[rs] / r[rt];
}

// Logic Instructions
void exec_and(uint8_t rd, uint8_t rs, uint8_t rt)
{
    r[rd] = r[rs] & r[rt];
}
void exec_or(uint8_t rd, uint8_t rs, uint8_t rt)
{
    r[rd] = r[rs] | r[rt];
}
void exec_xor(uint8_t rd, uint8_t rs, uint8_t rt)
{
    r[rd] = r[rs] ^ r[rt];
}
void exec_not(uint8_t rd, uint8_t rs)
{
    r[rd] = ~r[rs];
}
void exec_shftr(uint8_t rd, uint8_t rs, uint8_t rt)
{
    r[rd] = r[rs] >> r[rt];
}
void exec_shftri(uint8_t rd, uint64_t L)
{
    r[rd] = r[rd] >> L;
}
void exec_shftl(uint8_t rd, uint8_t rs, uint8_t rt)
{
    r[rd] = r[rs] << r[rt];
}
void exec_shftli(uint8_t rd, uint64_t L)
{
    r[rd] = r[rd] << L;
}

// Control Instructions
void exec_br(uint8_t rd, uint64_t *new_pc)
{
    if (r[rd] >= MEM)
    {
        fprintf(stderr, "Simulation error: Branch target out of bounds\n");
        exit(1);
    }
    *new_pc = r[rd];
}
void exec_brr(uint8_t rd, uint64_t current_pc, uint64_t *new_pc)
{
    uint64_t target = current_pc + r[rd];
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
void exec_brnz(uint8_t rd, uint8_t rs, uint64_t current_pc, uint64_t *new_pc)
{
    if (r[rs] != 0)
    {
        if (r[rd] >= MEM || r[rd] < START_ADDRESS)
        {
            fprintf(stderr, "Simulation error: Branch target out of bounds\n");
            exit(1);
        }
        *new_pc = r[rd];
    }
    // Otherwise, new_pc remains unchanged (caller will add 4)
}
void exec_call(uint8_t rd, uint64_t current_pc, uint64_t *new_pc)
{
    if (r[31] < 8)
    {
        fprintf(stderr, "Simulation error: Stack underflow\n");
        exit(1);
    }
    if (r[31] + 8 > MEM)
    {
        fprintf(stderr, "Simulation error: Stack pointer out of bounds\n");
        exit(1);
    }
    *((uint64_t *)(memory + r[31]-8)) = current_pc + 4;
    *new_pc = r[rd];
}


void exec_return(uint64_t *new_pc)
{
    if (r[31] > MEM - 8)
    {
        fprintf(stderr, "Simulation error: Stack underflow\n");
        exit(1);
    }
    *new_pc = *((uint64_t *)(memory + r[31]-8));
}

void exec_brgt(uint8_t rd, uint8_t rs, uint8_t rt, uint64_t *new_pc)
{
    if ((int64_t)r[rs] > (int64_t)r[rt])
    {
        if (r[rd] >= MEM || r[rd] < START_ADDRESS)
        {
            fprintf(stderr, "Simulation error: Branch target out of bounds\n");
            exit(1);
        }
        *new_pc = r[rd];
    }
    // Otherwise, new_pc remains unchanged (caller will add 4)
}

// Privileged Instruction
bool exec_priv(uint64_t L, uint8_t rd, uint8_t rs, uint64_t *pc)
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
        if (r[rs] == 0)
        {
            if (scanf("%" SCNu64, &r[rd]) != 1)
            {
                fprintf(stderr, "Simulation error: Failed to read input\n");
                exit(1);
            }
        }
        break;
    case 0x4:
        if (r[rd] == 1)
        {
            printf("%lu\n", r[rs]); // add newline
        }
        break;
    default:
        error("Illegal privilege instruction.");
    }
    return false;
}

// Data Movement Instructions
// mov_rm: Memory-to-register
uint64_t mov_rm(uint64_t pc, uint8_t rd, uint8_t rs, uint8_t rt, uint16_t literal)
{
    int64_t offset = (literal & 0x800) ? ((int64_t)literal | 0xFFFFFFFFFFFFF000ULL) : literal;
    uint64_t address = r[rs] + offset;

    r[rd] = read(address);
    return pc + 4;
}
// mov_rr: Register-to-register
uint64_t mov_rr(uint64_t pc, uint8_t rd, uint8_t rs, uint8_t rt, uint16_t literal)
{
    r[rd] = r[rs];
    return pc + 4;
}
// mov_rl: Register literal modification
uint64_t mov_rl(uint64_t pc, uint8_t rd, uint8_t rs, uint8_t rt, uint16_t literal)
{
    uint64_t mask = 0xFFF;
    r[rd] = (r[rd] & ~mask) | (literal & mask);
    return pc + 4;
}
// mov_mr: Register-to-memory
uint64_t mov_mr(uint64_t pc, uint8_t rd, uint8_t rs, uint8_t rt, uint16_t literal)
{
    uint16_t lit12 = literal & 0xFFF; // no extra masking here
    int64_t offset = (lit12 & 0x800)
                         ? ((int64_t)lit12 | 0xFFFFFFFFFFFFF000ULL)
                         : (int64_t)lit12;
    uint64_t address = r[rd] + offset;

   if (address % 8 != 0) {
        error("Memory must be 8-byte aligned.");
    }
    mem_write(address, r[rs]);
    return pc + 4;
}

// Floating Point Instructions
void exec_addf(uint8_t rd, uint8_t rs, uint8_t rt)
{
    double a, b, result;
    memcpy(&a, &r[rs], sizeof(double));
    memcpy(&b, &r[rt], sizeof(double));
    result = a + b;
    memcpy(&r[rd], &result, sizeof(double));
}
void exec_subf(uint8_t rd, uint8_t rs, uint8_t rt)
{
    double a, b, result;
    memcpy(&a, &r[rs], sizeof(double));
    memcpy(&b, &r[rt], sizeof(double));
    result = a - b;
    memcpy(&r[rd], &result, sizeof(double));
}
void exec_mulf(uint8_t rd, uint8_t rs, uint8_t rt)
{
    double a, b, result;
    memcpy(&a, &r[rs], sizeof(double));
    memcpy(&b, &r[rt], sizeof(double));
    result = a * b;
    memcpy(&r[rd], &result, sizeof(double));
}
void exec_divf(uint8_t rd, uint8_t rs, uint8_t rt)
{
    double a, b, result;
    memcpy(&a, &r[rs], sizeof(double));
    memcpy(&b, &r[rt], sizeof(double));
    if (b == 0.0)
    {
        error("Division by zero (floating point)");
    }
    result = a / b;
    memcpy(&r[rd], &result, sizeof(double));
}

void firstRead(size_t size, size_t count, FILE *file)
{
    size_t bytesRead;
    uint64_t programCounter = START_ADDRESS;
    while ((bytesRead = fread((char *)memory + programCounter, size, count, file)) > 0)
    {
        programCounter += 4;
        if (programCounter + 4 > MEM)
        {
            error("Program too large for memory");
        }
    }
}
void secondPass_simulation(uint64_t start_pc) {
    uint64_t pc = start_pc;
    uint64_t start = start_pc;
    bool halted = false;
    while (!halted) {
        if (pc + 4 > MEM)
            error("PC out of bounds");
        if (pc % 4 != 0)
            error("Unaligned PC");
        if (pc < start)
            error("PC underflow");
        uint32_t instruction = *((uint32_t *)(memory + pc));
        uint8_t opcode = (instruction >> 27) & 0x1F;
        uint8_t rd = (instruction >> 22) & 0x1F;
        uint8_t rs = (instruction >> 17) & 0x1F;
        uint8_t rt = (instruction >> 12) & 0x1F;
        uint16_t literal = instruction & 0xFFF;
        uint64_t next_pc = pc + 4;
        switch (opcode) {
            case 0x18: exec_add(rd, rs, rt); break;
            case 0x19: exec_addi(rd, literal); break;
            case 0x1A: exec_sub(rd, rs, rt); break;
            case 0x1B: exec_subi(rd, literal); break;
            case 0x1C: exec_mul(rd, rs, rt); break;
            case 0x1D: exec_div(rd, rs, rt); break;
            case 0x00: exec_and(rd, rs, rt); break;
            case 0x01: exec_or(rd, rs, rt); break;
            case 0x02: exec_xor(rd, rs, rt); break;
            case 0x03: exec_not(rd, rs); break;
            case 0x04: exec_shftr(rd, rs, rt); break;
            case 0x05: exec_shftri(rd, literal); break;
            case 0x06: exec_shftl(rd, rs, rt); break;
            case 0x07: exec_shftli(rd, literal); break;
            case 0x08: exec_br(rd, &next_pc); break;
            case 0x09: exec_brr(rd, pc, &next_pc); break;
            case 0x0A: exec_brrL(literal, pc, &next_pc); break;
            case 0x0B: exec_brnz(rd, rs, pc, &next_pc); break;
            case 0x0C: exec_call(rd, pc, &next_pc); break;
            case 0x0D: exec_return(&next_pc); break;
            case 0x0E: exec_brgt(rd, rs, rt, &next_pc); break;
            case 0x0F:
                if (exec_priv(literal, rd, rs, &pc))
                    halted = true;
                break;
            case 0x14: exec_addf(rd, rs, rt); break;
            case 0x15: exec_subf(rd, rs, rt); break;
            case 0x16: exec_mulf(rd, rs, rt); break;
            case 0x17: exec_divf(rd, rs, rt); break;
            case 0x10: next_pc = mov_rm(pc, rd, rs, rt, literal); break;
            case 0x11: next_pc = mov_rr(pc, rd, rs, rt, literal); break;
            case 0x12: next_pc = mov_rl(pc, rd, rs, rt, literal); break;
            case 0x13: next_pc = mov_mr(pc, rd, rs, rt, literal); break;
            default:
                error("Unknown opcode");
        }
        if (next_pc < start)
            error("PC underflow");
        pc = next_pc;
    }
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <binary_file>\n", argv[0]);
        return 1;
    }
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        fprintf(stderr, "Invalid tinker binary filepath\n");
        return 1;
    }

    // Read header (40 bytes: 5 64-bit values).
    TinkerFileHeader header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        fprintf(stderr, "Error reading header\n");
        fclose(file);
        return 1;
    }
  
    // Read code segment.
    if (header.code_seg_size > 0) {
        if (fseek(file, sizeof(header), SEEK_SET) != 0) {
            perror("fseek code segment");
            fclose(file);
            return 1;
        }
        size_t code_read = fread(memory + header.code_seg_begin, 1, header.code_seg_size, file);
        if (code_read != header.code_seg_size) {
            fprintf(stderr, "Failed to read complete code segment\n");
            fclose(file);
            return 1;
        }
    }

    // Read data segment.
    if (header.data_seg_size > 0) {
        if (fseek(file, sizeof(header) + header.code_seg_size, SEEK_SET) != 0) {
            perror("fseek data segment");
            fclose(file);
            return 1;
        }
        size_t data_read = fread(memory + header.data_seg_begin, 1, header.data_seg_size, file);
        if (data_read != header.data_seg_size) {
            fprintf(stderr, "Failed to read complete data segment\n");
            fclose(file);
            return 1;
        }
    }

    fclose(file);

    // Set simulation PC to the start of the code segment.
    // Now run the simulation starting at header.code_seg_begin.
    secondPass_simulation(header.code_seg_begin);

    return 0;
}