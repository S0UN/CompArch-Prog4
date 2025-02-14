#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_LINE 256

// Structure that holds an instruction’s mnemonic, its opcode, its format code,
// and a flag indicating whether its immediate operand (if any) is signed (1) or unsigned (0).
// Format codes for non-mov instructions:
//   "R"  : three registers (rd, rs, rt)
//   "I"  : register and immediate (rd, L)
//   "R2" : two registers (rd, rs)
//   "U"  : one register (rd)
//   "J"  : immediate only
//   "N"  : no operand
//   "P"  : privileged instruction (rd, rs, rt, L)
//   "M1" : data movement with register, register, immediate (for movmem and movmem2)
typedef struct {
    char *mnemonic;
    int opcode;
    char *format;
    int immediate_signed;  // 0 = unsigned immediate; 1 = signed immediate.
} InstructionInfo;

// Instruction set – 30 instructions as specified.
// (Note: all mov instructions in the file will be given as "mov" and are handled specially below.)
InstructionInfo instructions[] = {
    {"add",    0x18, "R", 0},
    {"addi",   0x19, "I", 0},   // unsigned immediate
    {"sub",    0x1a, "R", 0},
    {"subi",   0x1b, "I", 0},   // unsigned immediate
    {"mul",    0x1c, "R", 0},
    {"div",    0x1d, "R", 0},
    {"and",    0x0,  "R", 0},
    {"or",     0x1,  "R", 0},
    {"xor",    0x2,  "R", 0},
    {"not",    0x3,  "R2", 0},
    {"shftr",  0x4,  "R", 0},
    {"shftri", 0x5,  "I", 0},   // unsigned immediate
    {"shftl",  0x6,  "R", 0},
    {"shftli", 0x7,  "I", 0},   // unsigned immediate
    {"br",     0x8,  "U", 0},
    // "brr" is ambiguous – see special handling below.
    {"brnz",   0xb, "R2", 0},
    {"call",   0xc, "U", 0},
    {"return", 0xd, "N", 0},
    {"brgt",   0xe, "R", 0},
    {"priv",   0xf, "P", 1},     // assume its immediate is signed
    {"ld",     0x20, "I", 0},    // ld rd, L => unsigned immediate
    {"addf",   0x14, "R", 0},
    {"subf",   0x15, "R", 0},
    {"mulf",   0x16, "R", 0},
    {"divf",   0x17, "R", 0},
    {"ld",     0x20, "I", 0},    // ld rd, L => unsigned immediate
    {NULL,     0,     NULL, 0}
};

// Helper: Convert a 32-character bit string into a uint32_t.
uint32_t bitstr_to_uint32(char *bitstr) {
    uint32_t result = 0;
    while (*bitstr){
        result = (result << 1) | (*bitstr - '0');
        bitstr++;
    }
    return result;
}

// Helper: Convert a bit string into a uint64_t.
uint64_t bitstr_to_uint64(char *bitstr) {
    uint64_t result = 0;
    while (*bitstr){
        result = (result << 1) | (*bitstr - '0');
        bitstr++;
    }
    return result;
}
// Look up an instruction by mnemonic (non-"mov" instructions).
InstructionInfo* getInstructionInfo(const char *mnemonic) {
    for (int i = 0; instructions[i].mnemonic != NULL; i++) {
        if (strcasecmp(instructions[i].mnemonic, mnemonic) == 0)
            return &instructions[i];
    }
    return NULL;
}

// Convert an integer value to a binary string with the specified number of bits.
// (For signed immediates, using two's complement if negative.)
void int_to_bin_string(int value, int bits, char *dest) {
    unsigned int mask = 1 << (bits - 1);
    unsigned int uvalue;
    if (value < 0)
        uvalue = ((unsigned int)1 << bits) + value;
    else
        uvalue = value;
    for (int i = 0; i < bits; i++) {
        dest[i] = (uvalue & mask) ? '1' : '0';
        mask >>= 1;
    }
    dest[bits] = '\0';
}

// Convert an immediate value to a binary string with the specified number of bits,
// taking into account whether it is signed or unsigned.
void immediate_to_bin_string(int value, int bits, int signed_immediate, char *dest) {
    if (!signed_immediate) {
        if (value < 0) {
            fprintf(stderr, "Error: Unsigned immediate cannot be negative: %d\n", value);
            exit(1);
        }
        if (value >= (1 << bits)) {
            fprintf(stderr, "Error: Unsigned immediate out of range: %d\n", value);
            exit(1);
        }
        unsigned int uvalue = value;
        unsigned int mask = 1 << (bits - 1);
        for (int i = 0; i < bits; i++) {
            dest[i] = (uvalue & mask) ? '1' : '0';
            mask >>= 1;
        }
        dest[bits] = '\0';
    } else {
        int_to_bin_string(value, bits, dest);
    }
}

// Convert a 64-bit (signed) value to a binary string of the specified number of bits.
void ll_to_bin_string(long long value, int bits, char *dest) {
    unsigned long long mask = 1ULL << (bits - 1);
    unsigned long long uvalue;
    if (value < 0)
        uvalue = ((unsigned long long)1 << bits) + value;
    else
        uvalue = value;
    for (int i = 0; i < bits; i++) {
        dest[i] = (uvalue & mask) ? '1' : '0';
        mask >>= 1;
    }
    dest[bits] = '\0';
}

// Given a register token like "r2", return its integer number.
int parse_register(const char *token) {
    if (token[0] == 'r' || token[0] == 'R') {
        return atoi(token + 1);
    }
    return -1;
}

// Remove commas from a string (in place).
void remove_commas(char *str) {
    char *src = str, *dst = str;
    while (*src) {
        if (*src != ',') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

// Check if a string starts with a given prefix (case insensitive).
int starts_with(const char *str, const char *prefix) {
    while (*prefix) {
        if (tolower(*prefix) != tolower(*str))
            return 0;
        prefix++;
        str++;
    }
    return 1;
}

// Assemble a single instruction line into a 32-bit binary string.
// Fields: [opcode (5)][rd (5)][rs (5)][rt (5)][immediate (12)] (unused fields are zero).
char* assemble_instruction(const char *line) {
    char *result = malloc(33);
    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    result[0] = '\0';
    
    char buffer[MAX_LINE];
    strncpy(buffer, line, MAX_LINE);
    buffer[MAX_LINE - 1] = '\0';
    remove_commas(buffer);
    
    char *tokens[6];
    int count = 0;
    char *token = strtok(buffer, " \t\n");
    while (token && count < 6) {
        tokens[count++] = token;
        token = strtok(NULL, " \t\n");
    }
    if (count == 0) return NULL;
    
    char *mnemonic = tokens[0];
    
    // Special handling for "brr" (unchanged)
    if (strcasecmp(mnemonic, "brr") == 0) {
        if (count < 2) {
            fprintf(stderr, "Not enough operands for brr instruction\n");
            free(result);
            return NULL;
        }
        if (tokens[1][0] == 'r' || tokens[1][0] == 'R') {
            int opcode = 0x9;
            char opcode_bin[6];
            int_to_bin_string(opcode, 5, opcode_bin);
            int rd = parse_register(tokens[1]);
            char rd_bin[6], rs_bin[6], rt_bin[6], imm_bin[13];
            int_to_bin_string(rd, 5, rd_bin);
            strcpy(rs_bin, "00000");
            strcpy(rt_bin, "00000");
            strcpy(imm_bin, "000000000000");
            sprintf(result, "%s%s%s%s%s", opcode_bin, rd_bin, rs_bin, rt_bin, imm_bin);
            return result;
        } else {
            int opcode = 0xa;
            char opcode_bin[6];
            int_to_bin_string(opcode, 5, opcode_bin);
            int imm = atoi(tokens[1]);
            char imm_bin[13];
            immediate_to_bin_string(imm, 12, 1, imm_bin);
            char zero5[6] = "00000";
            sprintf(result, "%s%s%s%s%s", opcode_bin, zero5, zero5, zero5, imm_bin);
            return result;
        }
    }
    
    // Special handling for "mov" (all move instructions are written as "mov")
    if (strcasecmp(mnemonic, "mov") == 0) {
        if (count != 3) {
            fprintf(stderr, "Instruction 'mov' expects 2 operands.\n");
            free(result);
            return NULL;
        }
        char *op1 = tokens[1];
        char *op2 = tokens[2];
        char opcode_bin[6];
        char rd_bin[6] = "00000";
        char rs_bin[6] = "00000";
        char rt_bin[6] = "00000";
        char imm_bin[13] = "000000000000";
        
        // Check first operand: if it starts with '(' then it's Form D.
        if (op1[0] == '(') {
            // Form D: mov (r_d)(L), r_s
            int rd, imm;
            if (sscanf(op1, "(r%d)(%d)", &rd, &imm) != 2) {
                fprintf(stderr, "Invalid format for mov operand: %s\n", op1);
                free(result);
                return NULL;
            }
            int rs = parse_register(op2);
            int_to_bin_string(rd, 5, rd_bin);
            int_to_bin_string(rs, 5, rs_bin);
            strcpy(rt_bin, "00000");
            // Immediate is signed.
            immediate_to_bin_string(imm, 12, 1, imm_bin);
            // Opcode for Form D is 0x13.
            int opcode = 0x13;
            int_to_bin_string(opcode, 5, opcode_bin);
        } else {
            // op1 is a register.
            int rd = parse_register(op1);
            int_to_bin_string(rd, 5, rd_bin);
            // Now check second operand.
            if (op2[0] == '(') {
                // Form A: mov r_d, (r_s)(L)
                int rs, imm;
                if (sscanf(op2, "(r%d)(%d)", &rs, &imm) != 2) {
                    fprintf(stderr, "Invalid format for mov operand: %s\n", op2);
                    free(result);
                    return NULL;
                }
                int_to_bin_string(rs, 5, rs_bin);
                strcpy(rt_bin, "00000");
                immediate_to_bin_string(imm, 12, 1, imm_bin);
                // Opcode for Form A is 0x10.
                int opcode = 0x10;
                int_to_bin_string(opcode, 5, opcode_bin);
            } else {
                // op2 does not begin with '('.
                if (op2[0]=='r' || op2[0]=='R') {
                    // Form B: mov r_d, r_s
                    int rs = parse_register(op2);
                    int_to_bin_string(rs, 5, rs_bin);
                    strcpy(rt_bin, "00000");
                    strcpy(imm_bin, "000000000000");
                    // Opcode for Form B is 0x11.
                    int opcode = 0x11;
                    int_to_bin_string(opcode, 5, opcode_bin);
                } else {
                    // Form C: mov r_d, L
                    int imm = atoi(op2);
                    strcpy(rs_bin, "00000");
                    strcpy(rt_bin, "00000");
                    immediate_to_bin_string(imm, 12, 0, imm_bin);
                    // Opcode for Form C is 0x12.
                    int opcode = 0x12;
                    int_to_bin_string(opcode, 5, opcode_bin);
                }
            }
        }
        sprintf(result, "%s%s%s%s%s", opcode_bin, rd_bin, rs_bin, rt_bin, imm_bin);
        return result;
    }
    
    // For non-"mov" instructions, use the standard method.
    InstructionInfo *info = getInstructionInfo(mnemonic);
    if (!info) {
        fprintf(stderr, "Unknown mnemonic: %s\n", mnemonic);
        free(result);
        return NULL;
    }
    
    char opcode_bin[6];
    int_to_bin_string(info->opcode, 5, opcode_bin);
    
    char rd_bin[6]   = "00000";
    char rs_bin[6]   = "00000";
    char rt_bin[6]   = "00000";
    char imm_bin[13] = "000000000000";
    
    if (strcmp(info->format, "R") == 0) {
        if (count != 4) {
            fprintf(stderr, "Instruction '%s' expects 3 operands.\n", mnemonic);
            free(result);
            return NULL;
        }
        int rd = parse_register(tokens[1]);
        int rs = parse_register(tokens[2]);
        int rt = parse_register(tokens[3]);
        int_to_bin_string(rd, 5, rd_bin);
        int_to_bin_string(rs, 5, rs_bin);
        int_to_bin_string(rt, 5, rt_bin);
    } else if (strcmp(info->format, "I") == 0) {
        if (count != 3) {
            fprintf(stderr, "Instruction '%s' expects 2 operands.\n", mnemonic);
            free(result);
            return NULL;
        }
        int rd = parse_register(tokens[1]);
        int imm = atoi(tokens[2]);
        int_to_bin_string(rd, 5, rd_bin);
        immediate_to_bin_string(imm, 12, info->immediate_signed, imm_bin);
    } else if (strcmp(info->format, "R2") == 0) {
        if (count != 3) {
            fprintf(stderr, "Instruction '%s' expects 2 operands.\n", mnemonic);
            free(result);
            return NULL;
        }
        int rd = parse_register(tokens[1]);
        int rs = parse_register(tokens[2]);
        int_to_bin_string(rd, 5, rd_bin);
        int_to_bin_string(rs, 5, rs_bin);
    } else if (strcmp(info->format, "U") == 0) {
        if (count != 2) {
            fprintf(stderr, "Instruction '%s' expects 1 operand.\n", mnemonic);
            free(result);
            return NULL;
        }
        int rd = parse_register(tokens[1]);
        int_to_bin_string(rd, 5, rd_bin);
    } else if (strcmp(info->format, "J") == 0) {
        if (count != 2) {
            fprintf(stderr, "Instruction '%s' expects 1 immediate operand.\n", mnemonic);
            free(result);
            return NULL;
        }
        int imm = atoi(tokens[1]);
        immediate_to_bin_string(imm, 12, info->immediate_signed, imm_bin);
    } else if (strcmp(info->format, "N") == 0) {
        // No operands.
    } else if (strcmp(info->format, "P") == 0) {
        if (count != 5) {
            fprintf(stderr, "Instruction '%s' expects 4 operands.\n", mnemonic);
            free(result);
            return NULL;
        }
        int rd = parse_register(tokens[1]);
        int rs = parse_register(tokens[2]);
        int rt = parse_register(tokens[3]);
        int imm = atoi(tokens[4]);
        int_to_bin_string(rd, 5, rd_bin);
        int_to_bin_string(rs, 5, rs_bin);
        int_to_bin_string(rt, 5, rt_bin);
        immediate_to_bin_string(imm, 12, info->immediate_signed, imm_bin);
    } else if (strcmp(info->format, "M1") == 0) {
        if (count != 4) {
            fprintf(stderr, "Instruction '%s' expects 3 operands.\n", mnemonic);
            free(result);
            return NULL;
        }
        int rd = parse_register(tokens[1]);
        int rs = parse_register(tokens[2]);
        int imm = atoi(tokens[3]);
        int_to_bin_string(rd, 5, rd_bin);
        int_to_bin_string(rs, 5, rs_bin);
        immediate_to_bin_string(imm, 12, info->immediate_signed, imm_bin);
    } else {
        fprintf(stderr, "Unhandled format for instruction: %s\n", mnemonic);
        free(result);
        return NULL;
    }
    
    sprintf(result, "%s%s%s%s%s", opcode_bin, rd_bin, rs_bin, rt_bin, imm_bin);
    return result;
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s input.asm output.bin\n", argv[0]);
        return 1;
    }
    
    FILE *fin = fopen(argv[1], "r");
    if (!fin) {
        perror("Error opening input file");
        return 1;
    }
    
    // Open output file in binary mode.
    FILE *fout = fopen(argv[2], "wb");
    if (!fout) {
        perror("Error opening output file");
        fclose(fin);
        return 1;
    }
    
    int mode = 0; // 1 = code; 2 = data.
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fin)) {
        char *trimmed = line;
        while (isspace(*trimmed))
            trimmed++;
        
        // Check for section headers.
        if (trimmed[0] == '.') {
            if (starts_with(trimmed, ".code"))
                mode = 1;
            else if (starts_with(trimmed, ".data"))
                mode = 2;
            continue;
        }
        // Skip empty lines.
        if (strlen(trimmed) == 0)
            continue;
        
        if (mode == 1) {
            char *bin_instr = assemble_instruction(trimmed);
            if (bin_instr) {
                // Convert 32-bit bit string to a uint32_t and write in binary.
                uint32_t instr = bitstr_to_uint32(bin_instr);
                fwrite(&instr, sizeof(instr), 1, fout);
                free(bin_instr);
            }
        } else if (mode == 2) {
            long long data_val = atoll(trimmed);
            char data_bin[65]; // 64 bits + null terminator.
            ll_to_bin_string(data_val, 64, data_bin);
            // Convert the 64-bit string to a uint64_t and write.
            uint64_t data = bitstr_to_uint64(data_bin);
            fwrite(&data, sizeof(data), 1, fout);
        }
    }
    
    fclose(fin);
    fclose(fout);
    return 0;
}