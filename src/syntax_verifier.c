#include "syntax_verifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <strings.h>
#include "arraylist.h"
#include "label_table.h"
#include "line.h"

#define MAX_OPERAND_LENGTH 32

LabelTable *labels = NULL;

#define MAX_LINE 256

typedef struct
{
    char *mnemonic;
    int opcode;
    char *format;
    int immediate_signed; // 0 = unsigned immediate; 1 = signed immediate.
} InstructionInfo;
typedef struct
{
    unsigned int file_type;      // Always 0 for now.
    unsigned int code_seg_begin; // For this project, code loads at 0x2000.
    unsigned int code_seg_size;  // In bytes.
    unsigned int data_seg_begin; // For this project, data loads at 0x10000.
    unsigned int data_seg_size;  // In bytes.
} TinkerFileHeader;
// Instruction set – 30 instructions as specified.
InstructionInfo instructions[] = {
    {"add", 0x18, "R", 0},
    {"addi", 0x19, "I", 0},
    {"sub", 0x1a, "R", 0},
    {"subi", 0x1b, "I", 0},
    {"mul", 0x1c, "R", 0},
    {"div", 0x1d, "R", 0},
    {"and", 0x0, "R", 0},
    {"or", 0x1, "R", 0},
    {"xor", 0x2, "R", 0},
    {"not", 0x3, "R2", 0},
    {"shftr", 0x4, "R", 0},
    {"shftri", 0x5, "I", 0},
    {"shftl", 0x6, "R", 0},
    {"shftli", 0x7, "I", 0},
    {"br", 0x8, "U", 0},
    {"brnz", 0xb, "R2", 0},
    {"call", 0xc, "U", 0},
    {"return", 0xd, "N", 0},
    {"brgt", 0xe, "R", 0},
    {"priv", 0xf, "P", 1},
    {"addf", 0x14, "R", 0},
    {"subf", 0x15, "R", 0},
    {"mulf", 0x16, "R", 0},
    {"divf", 0x17, "R", 0},
    {NULL, 0, NULL, 0}
};

// Helper: Convert a 32-character bit string into a uint32_t.
uint32_t bitstr_to_uint32(char *bitstr)
{
    uint32_t result = 0;
    while (*bitstr)
    {
        result = (result << 1) | (*bitstr - '0');
        bitstr++;
    }
    return result;
}

// Helper: Convert a bit string into a uint64_t.
uint64_t bitstr_to_uint64(char *bitstr)
{
    uint64_t result = 0;
    while (*bitstr)
    {
        result = (result << 1) | (*bitstr - '0');
        bitstr++;
    }
    return result;
}

void print_label_table(LabelTable *labels)
{
    LabelTable *entry, *tmp;
    HASH_ITER(hh, labels, entry, tmp)
    {
        printf("Label: %s, Address: %d, in_code_section: %d\n",
               entry->label, entry->address, entry->in_code_section);
    }
}

// Look up an instruction by mnemonic (non-"mov" instructions).
InstructionInfo *getInstructionInfo(const char *mnemonic)
{
    for (int i = 0; instructions[i].mnemonic != NULL; i++)
    {
        if (strcasecmp(instructions[i].mnemonic, mnemonic) == 0)
            return &instructions[i];
    }
    return NULL;
}

// Convert an integer value to a binary string with the specified number of bits.
// (For signed immediates, using two's complement if negative.)
void int_to_bin_string(int value, int bits, char *dest)
{
    unsigned int mask = 1 << (bits - 1);
    unsigned int uvalue;
    if (value < 0)
        uvalue = ((unsigned int)1 << bits) + value;
    else
        uvalue = value;
    for (int i = 0; i < bits; i++)
    {
        dest[i] = (uvalue & mask) ? '1' : '0';
        mask >>= 1;
    }
    dest[bits] = '\0';
}

// Convert an immediate value to a binary string with the specified number of bits,
// taking into account whether it is signed or unsigned.
void immediate_to_bin_string(int value, int bits, int signed_immediate, char *dest)
{
    if (!signed_immediate)
    {
        if (value < 0)
        {
            fprintf(stderr, "Error: Unsigned immediate cannot be negative: %d\n", value);
            exit(1);
        }
        if (value >= (1 << bits))
        {
            fprintf(stderr, "Error: Unsigned immediate out of range: %d\n", value);
            exit(1);
        }
        unsigned int uvalue = value;
        unsigned int mask = 1 << (bits - 1);
        for (int i = 0; i < bits; i++)
        {
            dest[i] = (uvalue & mask) ? '1' : '0';
            mask >>= 1;
        }
        dest[bits] = '\0';
    }
    else
    {
        int_to_bin_string(value, bits, dest);
    }
}

// Convert a 64-bit (signed) value to a binary string of the specified number of bits.
void ll_to_bin_string(long long value, int bits, char *dest)
{
    // Cast the value directly to unsigned long long. This produces the two's complement representation.
    unsigned long long uvalue = (unsigned long long)value;
    unsigned long long mask = 1ULL << (bits - 1);
    for (int i = 0; i < bits; i++)
    {
        dest[i] = (uvalue & mask) ? '1' : '0';
        mask >>= 1;
    }
    dest[bits] = '\0';
}

// Given a register token like "r2", return its integer number.
int parse_register(const char *token)
{
    if (token[0] == 'r' || token[0] == 'R')
    {
        return atoi(token + 1);
    }
    return -1;
}

// Remove commas from a string (in place).
void remove_commas(char *str)
{
    char *src = str, *dst = str;
    while (*src)
    {
        if (*src != ',')
        {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

// Check if a string starts with a given prefix (case insensitive).
int starts_with(const char *str, const char *prefix)
{
    while (*prefix)
    {
        if (tolower(*prefix) != tolower(*str))
            return 0;
        prefix++;
        str++;
    }
    return 1;
}

unsigned int hex_to_decimal(const char *hex_str)
{
    unsigned int result = 0;
    if (hex_str == NULL)
        return 0;

    // If the string begins with "0x" or "0X", skip it.
    if (hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X'))
    {
        hex_str += 2;
    }

    while (*hex_str)
    {
        int digit = 0;
        if (*hex_str >= '0' && *hex_str <= '9')
            digit = *hex_str - '0';
        else if (*hex_str >= 'a' && *hex_str <= 'f')
            digit = *hex_str - 'a' + 10;
        else if (*hex_str >= 'A' && *hex_str <= 'F')
            digit = *hex_str - 'A' + 10;
        else
            break; // Stop conversion on encountering a non-hex character

        result = result * 16 + digit;
        hex_str++;
    }

    return result;
}

// Assemble a single instruction line into a 32-bit binary string.
// Fields: [opcode (5)][rd (5)][rs (5)][rt (5)][immediate (12)] (unused fields are zero).

char *assemble_instruction(const char *line)
{
    char *result = malloc(33);
    if (!result)
    {
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
    while (token && count < 6)
    {
        tokens[count++] = token;
        token = strtok(NULL, " \t\n");
    }
    if (count == 0)
        return NULL;

    char *mnemonic = tokens[0];

    printf("%s\n", mnemonic);

    // Special handling for "brr" (unchanged)
    if (strcasecmp(mnemonic, "brr") == 0)
    {
        if (count < 2)
        {
            fprintf(stderr, "Not enough operands for brr instruction\n");
            free(result);
            return NULL;
        }
        if (tokens[1][0] == 'r' || tokens[1][0] == 'R')
        {
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
        }
        else
        {
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
    if (strcasecmp(mnemonic, "mov") == 0)
    {
        if (count != 3)
        {
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
        if (op1[0] == '(')
        {
            // Form D: mov (r_d)(L), r_s
            int rd, imm;
            if (sscanf(op1, "(r%d)(%d)", &rd, &imm) != 2)
            {
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
        }
        else
        {
            // op1 is a register.
            int rd = parse_register(op1);
            int_to_bin_string(rd, 5, rd_bin);
            // Now check second operand.
            if (op2[0] == '(')
            {
                // Form A: mov r_d, (r_s)(L)
                int rs, imm;
                if (sscanf(op2, "(r%d)(%d)", &rs, &imm) != 2)
                {
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
            }
            else
            {
                // op2 does not begin with '('.
                if (op2[0] == 'r' || op2[0] == 'R')
                {
                    // Form B: mov r_d, r_s
                    int rs = parse_register(op2);
                    int_to_bin_string(rs, 5, rs_bin);
                    strcpy(rt_bin, "00000");
                    strcpy(imm_bin, "000000000000");
                    // Opcode for Form B is 0x11.
                    int opcode = 0x11;
                    int_to_bin_string(opcode, 5, opcode_bin);
                }
                else
                {
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
    if (!info)
    {
        fprintf(stderr, "Unknown mnemonic: %s\n", mnemonic);
        free(result);
        return NULL;
    }

    char opcode_bin[6];
    int_to_bin_string(info->opcode, 5, opcode_bin);

    char rd_bin[6] = "00000";
    char rs_bin[6] = "00000";
    char rt_bin[6] = "00000";
    char imm_bin[13] = "000000000000";

    if (strcmp(info->format, "R") == 0)
    {
        if (count != 4)
        {
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
    }
    else if (strcmp(info->format, "I") == 0)
    {
        if (count != 3)
        {
            fprintf(stderr, "Instruction '%s' expects 2 operands.\n", mnemonic);
            free(result);
            return NULL;
        }
        int rd = parse_register(tokens[1]);
        int imm = atoi(tokens[2]);
        int_to_bin_string(rd, 5, rd_bin);
        immediate_to_bin_string(imm, 12, info->immediate_signed, imm_bin);
    }
    else if (strcmp(info->format, "R2") == 0)
    {
        if (count != 3)
        {
            fprintf(stderr, "Instruction '%s' expects 2 operands.\n", mnemonic);
            free(result);
            return NULL;
        }
        int rd = parse_register(tokens[1]);
        int rs = parse_register(tokens[2]);
        int_to_bin_string(rd, 5, rd_bin);
        int_to_bin_string(rs, 5, rs_bin);
    }
    else if (strcmp(info->format, "U") == 0)
    {
        if (count != 2)
        {
            fprintf(stderr, "Instruction '%s' expects 1 operand.\n", mnemonic);
            free(result);
            return NULL;
        }
        int rd = parse_register(tokens[1]);
        int_to_bin_string(rd, 5, rd_bin);
    }
    else if (strcmp(info->format, "J") == 0)
    {
        if (count != 2)
        {
            fprintf(stderr, "Instruction '%s' expects 1 immediate operand.\n", mnemonic);
            free(result);
            return NULL;
        }
        int imm = atoi(tokens[1]);
        immediate_to_bin_string(imm, 12, info->immediate_signed, imm_bin);
    }
    else if (strcmp(info->format, "N") == 0)
    {
        // No operands.
    }
    else if (strcmp(info->format, "P") == 0)
    {
        if (count != 5)
        {
            fprintf(stderr, "Instruction '%s' expects 4 operands.\n", mnemonic);
            free(result);
            return NULL;
        }

        int opcode = info->opcode; // Get opcode from instruction struct
        char opcode_bin[6];
        int_to_bin_string(opcode, 5, opcode_bin);
        fprintf(stderr, "opcode '%s' \n", opcode_bin);

        int rd = parse_register(tokens[1]);
        int rs = parse_register(tokens[2]);
        int rt = parse_register(tokens[3]);
        unsigned int imm = hex_to_decimal(tokens[4]);

        char rd_bin[6], rs_bin[6], rt_bin[6], imm_bin[13];

        int_to_bin_string(rd, 5, rd_bin);
        int_to_bin_string(rs, 5, rs_bin);
        int_to_bin_string(rt, 5, rt_bin);
        fprintf(stderr, "opcode '%s' \n", rd_bin);
        fprintf(stderr, "opcode '%s' \n", rs_bin);

        fprintf(stderr, "opcode '%s' \n", rt_bin);

        immediate_to_bin_string(imm, 12, info->immediate_signed, imm_bin);
        fprintf(stderr, "imm '%d' \n", imm);

        sprintf(result, "%s%s%s%s%s", opcode_bin, rd_bin, rs_bin, rt_bin, imm_bin);
        fprintf(stderr, "result '%s' \n", result);

        return result;
    }

    else if (strcmp(info->format, "M1") == 0)
    {
        if (count != 4)
        {
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
    }
    else
    {
        fprintf(stderr, "Unhandled format for instruction: %s\n", mnemonic);
        free(result);
        return NULL;
    }

    sprintf(result, "%s%s%s%s%s", opcode_bin, rd_bin, rs_bin, rt_bin, imm_bin);
    return result;
}
void ull_to_bin_string(unsigned long long value, int bits, char *dest)
{
    unsigned long long mask = 1ULL << (bits - 1);
    for (int i = 0; i < bits; i++)
    {
        dest[i] = (value & mask) ? '1' : '0';
        mask >>= 1;
    }
    dest[bits] = '\0';
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <source_input.asm> <final_output.bin>\n", argv[0]);
        return 1;
    }

    ArrayList instructions;
    initialize_arraylist(&instructions);
    int address = 0; // PC starts at 0x1000

    // First pass: Collect labels.
    if (process_file_first_pass(argv[1], &labels, &address) != 0)
    {
        printf("Error processing file during first pass.\n");
        free_arraylist(&instructions);
        free_label_table(labels);
        return 1;
    }

    // Second pass: Expand macros and collect instructions.
    if (process_file_second_pass(argv[1], &instructions, labels, &address) != 0)
    {
        printf("Error processing file during second pass.\n");
        free_arraylist(&instructions);
        free_label_table(labels);
        return 1;
    }

    printf("\nDEBUG: Resolving labels...\n");
    resolve_labels(&instructions, labels);
    printf("DEBUG: Label resolution complete!\n");

    // Write the intermediate assembly output to a temporary file.
    // (This file will be used as input to the binary converter phase.)
    const char *tempAssembly = "temp.asm";
    write_output_file(tempAssembly, &instructions);

    free_arraylist(&instructions);
    free_label_table(labels);

    FILE *fin = fopen(tempAssembly, "r");
    if (!fin)
    {
        perror("Error opening intermediate assembly file");
        return 1;
    }

    // Open final output file in binary mode.
    FILE *fout = fopen(argv[2], "wb");
    if (!fout)
    {
        perror("Error opening final output file");
        fclose(fin);
        return 1;
    }

    int mode = 0; // 1 = code; 2 = data.
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fin))
    {
        char *trimmed = line;
        while (isspace(*trimmed))
            trimmed++;

        // Check for section headers.
        if (trimmed[0] == '.')
        {
            if (starts_with(trimmed, ".code"))
                mode = 1;
            else if (starts_with(trimmed, ".data"))
                mode = 2;
            continue;
        }
        // Skip empty lines.
        if (strlen(trimmed) == 0)
            continue;

        if (mode == 1)
        {
            char *bin_instr = assemble_instruction(trimmed);
            if (bin_instr)
            {
                // Convert the 32-character bit string to a uint32_t and write in binary.
                printf("%s\n", bin_instr);

                uint32_t instr = bitstr_to_uint32(bin_instr);
                printf("%d\n", instr);
                fwrite(&instr, sizeof(instr), 1, fout);
                free(bin_instr);
            }
        }
        else if (mode == 2)
        {
            // Read the input string as a 64-bit unsigned integer.
            char *endptr;
            unsigned long long value = strtoull(trimmed, &endptr, 0);
            printf("%llu", value);
            int32_t temp = (int32_t)value;
            value = (uint64_t)temp;

            char data_bin[65]; // 64 bits + null terminator.

            ll_to_bin_string(value, 64, data_bin);
            uint64_t data = bitstr_to_uint64(data_bin);
            fwrite(&data, sizeof(data), 1, fout);
        }
    }

    fclose(fin);
    fclose(fout);

    // Optionally remove the temporary file.
    remove(tempAssembly);

    return 0;
}

void trim_whitespace(char *line)
{
    int start = 0;
    while (line[start] && isspace((unsigned char)line[start]))
        start++;
    if (start > 0)
        memmove(line, line + start, strlen(line + start) + 1);
    int len = strlen(line);
    while (len > 0 && isspace((unsigned char)line[len - 1]))
        line[--len] = '\0';
}

void remove_comments(char *line)
{
    char *comment_pos = strchr(line, ';'); // Find the first occurrence of ';'
    if (comment_pos)
    {
        *comment_pos = '\0'; // Truncate the line at the comment position
    }
    trim_whitespace(line); // Ensure no trailing spaces remain
}

bool isValidRegister(const char *reg)
{
    if (reg[0] != 'r' && reg[0] != 'R')
        return false;
    char *endptr;
    long num = strtol(reg + 1, &endptr, 10);
    return (*endptr == '\0' && num >= 0 && num <= 31);
}

bool isValidImmediate(const char *imm, bool allow_negative, int bit_size)
{
    while (isspace((unsigned char)*imm))
        imm++;
    if (*imm == '\0')
        return false;

    bool neg = false;
    if (*imm == '-')
    {
        if (!allow_negative)
            return false;
        neg = true;
        imm++;
    }

    long min_val, max_val;
    if (bit_size == 12)
    { // 12-bit immediate range
        if (allow_negative)
        {
            min_val = -2048;
            max_val = 2047;
        }
        else
        {
            min_val = 0;
            max_val = 4095;
        }
    }
    else if (bit_size == 5)
    { // 5-bit immediate range
        min_val = 0;
        max_val = 31;
    }
    else
    {
        return false;
    }

    long val;
    char *endptr;
    if (imm[0] == '0' && (imm[1] == 'x' || imm[1] == 'X'))
    {
        val = strtol(imm + 2, &endptr, 16);
    }
    else
    {
        val = strtol(imm, &endptr, 10);
    }
    if (*endptr != '\0')
        return false;
    if (neg)
        val = -val;
    return (val >= min_val && val <= max_val);
}

bool isMemoryOperand(const char *operand)
{
    char reg[10];
    int lit;
    return (sscanf(operand, "(%[^)])(%d)", reg, &lit) == 2);
}

bool isLabelSyntax(const char *operand)
{
    return operand[0] == ':';
}

bool isValidLabel(const char *str)
{
    if (str == NULL || !isalpha(str[0]) && str[0] != '_')
    {
        return false;
    }
    for (int i = 1; str[i] != '\0'; i++)
    {
        if (!isalnum(str[i]) && str[i] != '_')
        {
            return false;
        }
    }
    return true;
}
bool isValidMemoryAddress(const char *str)
{
    if (str == NULL || str[0] != '0' || (str[1] != 'x' && str[1] != 'X'))
    {
        return false;
    }
    for (int i = 2; str[i] != '\0'; i++)
    {
        if (!isxdigit(str[i]))
        {
            return false;
        }
    }
    return true;
}

int validate_label_format(char *token)
{
    if (token[0] != ':')
        return 0;
    for (int i = 1; token[i] != '\0'; i++)
    {
        if (!isalnum((unsigned char)token[i]) && token[i] != '_')
            return 0;
    }
    return 1;
}

int validate_macro(char *token)
{
    const char *valid_macros[] = {"in", "out", "clr", "ld", "push", "pop", "halt", NULL};
    for (int i = 0; valid_macros[i] != NULL; i++)
    {
        if (strcmp(token, valid_macros[i]) == 0)
            return 1;
    }
    return 0;
}

int validate_spacing(const char *line)
{
    // Make a duplicate of the input line so we don't modify the caller's copy.
    char lineCopy[256];
    strncpy(lineCopy, line, sizeof(lineCopy));
    lineCopy[sizeof(lineCopy) - 1] = '\0';

    // If the line is a label or directive, skip spacing checks.
    if (lineCopy[0] == ':' || lineCopy[0] == '.')
        return 1;

    // Check that the original line starts with a tab or exactly four spaces.
    if (!(lineCopy[0] == '\t' || (lineCopy[0] == ' ' && lineCopy[1] == ' ' && lineCopy[2] == ' ' && lineCopy[3] == ' ')))
    {
        fprintf(stderr, "Syntax Error: Instruction must be indented with a tab or exactly 4 spaces: %s\n", line);
        return 0;
    }

    trim_whitespace(lineCopy);

    // Tokenize to get the opcode
    char *opcode = strtok(lineCopy, " \t");
    if (!opcode)
        return 1;

    // Handle the special cases where "halt" and "return" don't require a space afterward
    if (strcasecmp(opcode, "halt") == 0 || strcasecmp(opcode, "return") == 0)
    {
        // If there's another token after "halt" or "return", it's an error
        char *extraToken = strtok(NULL, " \t");
        if (extraToken)
        {
            fprintf(stderr, "Syntax Error: 'halt' and 'return' must not be followed by additional characters: %s\n", line);
            return 0;
        }
        return 1;
    }

    // For other opcodes, ensure they are followed by exactly one space
    int opcode_len = strlen(opcode);
    if (lineCopy[opcode_len] != ' ' && lineCopy[opcode_len] != '\0')
    {
        fprintf(stderr, "Syntax Error: Opcode must be followed by exactly one space: %s\n", line);
        return 0;
    }

    // Validate operand spacing
    char *tokens[5];
    int token_count = 0;
    char *token = strtok(NULL, " \t");
    while (token && token_count < 5)
    {
        tokens[token_count++] = token;
        token = strtok(NULL, " \t");
    }

    for (int i = 0; i < token_count; i++)
    {
        int len = strlen(tokens[i]);

        // If it's a label (starts with ':'), don't enforce a trailing comma.
        if (tokens[i][0] == ':')
            continue;

        // Only enforce commas if there is another operand after this one
        if (i < token_count - 1 && tokens[i][len - 1] != ',')
        {
            fprintf(stderr, "Syntax Error: Incorrect spacing around operands: %s\n", line);
            return 0;
        }
    }

    return 1;
}

bool validate_macro_instruction(const char *line)
{
    char buf[300];
    // Copy the input line into a local buffer.
    strncpy(buf, line, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    trim_whitespace(buf); // Remove any extra whitespace

    // Tokenize to get the opcode.
    char *opcode = strtok(buf, " \t");
    if (!opcode)
        error("Empty macro instruction");

    int operandCount = 0;
    // We expect at most 2 operands for these macros (with a little extra space if needed)
    char *operands[3];
    char *token = strtok(NULL, " \t,");
    while (token != NULL && operandCount < 3)
    {
        // Duplicate and trim each token so we ignore extra spaces.
        char *trimmed = strdup(token);
        if (!trimmed)
            error("Memory allocation failed in macro validation");
        trim_whitespace(trimmed);
        // Only store nonempty tokens.
        if (strlen(trimmed) > 0)
        {
            operands[operandCount++] = trimmed;
        }
        else
        {
            free(trimmed);
        }
        token = strtok(NULL, " \t,");
    }

    // Now validate based on the opcode:
    if (strcasecmp(opcode, "in") == 0)
    {
        // Expected syntax: in rd, rs
        if (operandCount != 2)
            error("Macro 'in' requires exactly two operands (rd, rs)");
        if (!isValidRegister(operands[0]) || !isValidRegister(operands[1]))
            error("Macro 'in': both operands must be valid registers");
    }
    else if (strcasecmp(opcode, "out") == 0)
    {
        // Expected syntax: out rd, rs
        if (operandCount != 2)
            error("Macro 'out' requires exactly two operands (rd, rs)");
        if (!isValidRegister(operands[0]) || !isValidRegister(operands[1]))
            error("Macro 'out': both operands must be valid registers");
    }
    else if (strcasecmp(opcode, "clr") == 0)
    {
        // Expected syntax: clr rd
        if (operandCount != 1)
            error("Macro 'clr' requires exactly one operand (rd)");
        if (!isValidRegister(operands[0]))
            error("Macro 'clr': operand must be a valid register");
    }
    else if (strcasecmp(opcode, "ld") == 0)
    {
        // Expected syntax: ld rd, L
        if (operandCount != 2)
        {
            error("Macro 'ld' requires exactly two operands (rd, literal/memory address/label)");
        }
        if (!isValidRegister(operands[0]))
        {
            error("Macro 'ld': first operand must be a valid register");
        }
        /*
        // Check if the second operand is a valid number, memory address, or label
        if (!(isdigit(operands[1][0]) || (operands[1][0] == '-' && isdigit(operands[1][1])) || isValidLabel(operands[1]))) {
            error("Macro 'ld': second operand must be a literal number, memory address, or label");
        }
        */
    }
    else if (strcasecmp(opcode, "push") == 0)
    {
        // Expected syntax: push rd
        if (operandCount != 1)
            error("Macro 'push' requires exactly one operand (rd)");
        if (!isValidRegister(operands[0]))
            error("Macro 'push': operand must be a valid register");
    }
    else if (strcasecmp(opcode, "pop") == 0)
    {
        // Expected syntax: pop rd
        if (operandCount != 1)
            error("Macro 'pop' requires exactly one operand (rd)");
        if (!isValidRegister(operands[0]))
            error("Macro 'pop': operand must be a valid register");
    }
    else if (strcasecmp(opcode, "halt") == 0)
    {
        // Expected syntax: halt (no operands)
        if (operandCount != 0)
            error("Macro 'halt' takes no operands");
    }
    else
    {
        for (int i = 0; i < operandCount; i++)
        {
            free(operands[i]);
        }
        error("Unknown macro instruction");
    }

    // Free any allocated tokens.
    for (int i = 0; i < operandCount; i++)
    {
        free(operands[i]);
    }

    return true;
}

bool validate_instruction(const char *line)
{
    char opcode[20];
    char *operands[4];
    int operandCount = 0;
    printf("[%s]\n", line);

    char temp[300];
    strcpy(temp, line);
    char *token = strtok(temp, " \t");
    if (!token)
    {
        fprintf(stderr, "Empty instruction!\n");
        return false;
    }
    strcpy(opcode, token);

    printf("\nDEBUG: Tokenized Opcode -> %s\n", opcode);

    while ((token = strtok(NULL, " \t,")) != NULL && operandCount < 4)
    {
        operands[operandCount] = token;
        printf("DEBUG: Operand[%d]: %s\n", operandCount, operands[operandCount]);
        operandCount++;
    }

    printf("DEBUG: Total Operands Found: %d\n", operandCount);

    if (strcasecmp(opcode, "add") == 0 ||
        strcasecmp(opcode, "sub") == 0 ||
        strcasecmp(opcode, "mul") == 0 ||
        strcasecmp(opcode, "div") == 0)
    {
        if (operandCount != 3)
            error("Arithmetic instructions require three operands (rd, rs, rt)");
        for (int i = 0; i < 3; i++)
        {
            if (!isValidRegister(operands[i]))
                error("Arithmetic instructions: all operands must be registers");
        }
    }
    else if (strcasecmp(opcode, "addi") == 0 ||
             strcasecmp(opcode, "subi") == 0)
    {
        if (operandCount != 2)
            error("Immediate arithmetic instructions require two operands (rd, imm)");
        if (!isValidRegister(operands[0]))
            error("addi/subi: first operand must be a register");
        if (!isValidImmediate(operands[1], false, 12))
            error("addi/subi: second operand must be a 12-bit unsigned immediate");
    }
    else if (strcasecmp(opcode, "xor") == 0 ||
             strcasecmp(opcode, "and") == 0 ||
             strcasecmp(opcode, "or") == 0)
    {
        if (operandCount != 3)
            error("Logical operations require three operands (rd, rs, rt)");
        for (int i = 0; i < 3; i++)
        {
            if (!isValidRegister(operands[i]))
                error("Logical operations: all operands must be registers");
        }
    }
    else if (strcasecmp(opcode, "not") == 0)
    {
        if (operandCount != 2)
            error("not requires two operands (rd, rs)");
        if (!isValidRegister(operands[0]) || !isValidRegister(operands[1]))
            error("not: operands must be registers");
    }
    else if (strcasecmp(opcode, "brr") == 0)
    {
        if (operandCount != 1)
            error("brr requires one operand (register, signed immediate, or label)");
        if (!isValidRegister(operands[0]) && !isValidImmediate(operands[0], true, 12) && !isLabelSyntax(operands[0]))
            error("brr: operand must be a register, a 12-bit signed immediate, or a label");
    }
    else if (strcasecmp(opcode, "brnz") == 0)
    {
        if (operandCount != 2)
            error("brnz requires two operands (rd, rs)");
        if (!isValidRegister(operands[1]))
            error("brnz: second operand (rs) must be a register");
        if (!isValidRegister(operands[0]) && !isLabelSyntax(operands[0]))
            error("brnz: first operand (rd) must be a register or a label");
    }
    else if (strcasecmp(opcode, "br") == 0)
    {
        if (operandCount != 1)
            error("br requires one operand (register or label)");
        if (!isValidRegister(operands[0]) && !isLabelSyntax(operands[0]))
            error("br: operand must be a register or a label");
    }
    else if (strcasecmp(opcode, "call") == 0)
    {
        if (operandCount != 1)
            error("call requires one operand (a 12-bit signed immediate or label)");

        /*
    if (!isValidImmediate(operands[0], true, 12) && !isLabelSyntax(operands[0]))
        error("call: operand must be a 12-bit signed immediate or a label");
        */
    }
    else if (strcasecmp(opcode, "return") == 0)
    {
        if (operandCount != 0)
            error("return takes no operands");
    }
    else if (strcasecmp(opcode, "mov") == 0)
    {
        int r0, r1, L;
        char extra[100] = {0}; // Buffer to check for extra tokens.
        // Assume that after "mov " (4 characters) the operands start.
        const char *tkn = line + 4;

        // Try pattern 1: "r%d, (r%d)(%d)" i.e. register-to-memory form.
        if (sscanf(tkn, "r%d, (r%d)(%d)", &r0, &r1, &L) == 3)
        {
            if (sscanf(tkn, "r%d, (r%d)(%d) %s", &r0, &r1, &L, extra) == 4)
                error("Invalid Tinker Instruction for mov!");
            return true;
        }
        // Try pattern 2: "r%d, r%d" i.e. register-to-register form.
        else if (sscanf(tkn, "r%d, r%d", &r0, &r1) == 2)
        {
            if (sscanf(tkn, "r%d, r%d %s", &r0, &r1, extra) == 3)
                error("Invalid Tinker Instruction for mov!");
            return true;
        }
        // Try pattern 3: "r%d, %u" i.e. register-to-immediate form.
        else if (sscanf(tkn, "r%d, %u", &r0, &L) == 2)
        {
            if (sscanf(tkn, "r%d, %d %s", &r0, &r1, extra) == 3)
                error("Invalid Tinker Instruction for mov!");
            return true;
        }
        // Try pattern 4: "(r%d)(%u), r%d" i.e. memory-to-register form.
        else if (sscanf(tkn, "(r%d)(%u), r%d", &r0, &L, &r1) == 3)
        {
            if (sscanf(tkn, "(r%d)(%u), r%d %s", &r0, &L, &r1, extra) == 4)
                error("Invalid Tinker Instruction for mov!");
            return true;
        }
        else
        {
            error("mov: Invalid operands. Must be one of: (rd, rs) or (rd, imm) or memory forms.");
        }
    }

    else if (strcasecmp(opcode, "brgt") == 0)
    {
        if (operandCount != 3)
            error("brgt requires three operands (rd, rs, rt)");
        if (!isValidRegister(operands[0]) || !isValidRegister(operands[1]) || !isValidRegister(operands[2]))
            error("brgt: all operands must be registers");
    }
    else if (strcasecmp(opcode, "trap") == 0)
    {
        if (operandCount != 1)
            error("trap requires one operand (immediate)");
        if (!isValidImmediate(operands[0], false, 12))
            error("trap: operand must be a 12-bit unsigned immediate");
    }
    else if (strcasecmp(opcode, "halt") == 0)
    {
        if (operandCount != 0)
            error("halt takes no operands");
    }
    else if (strcasecmp(opcode, "addf") == 0 ||
             strcasecmp(opcode, "subf") == 0 ||
             strcasecmp(opcode, "mulf") == 0 ||
             strcasecmp(opcode, "divf") == 0)
    {
        if (operandCount != 3)
            error("Floating point instructions require three operands");
        for (int i = 0; i < 3; i++)
        {
            if (!isValidRegister(operands[i]))
                error("Floating point instructions: operands must be registers");
        }
    }
    else if (strcasecmp(opcode, "shftr") == 0 || strcasecmp(opcode, "shftl") == 0)
    {
        if (operandCount != 3)
            error("Shift instructions require three operands (rd, rs, rt)");
        for (int i = 0; i < 3; i++)
        {
            if (!isValidRegister(operands[i]))
                error("Shift instructions: operands must be registers");
        }
    }
    else if (strcasecmp(opcode, "shftri") == 0 || strcasecmp(opcode, "shftli") == 0)
    {
        if (operandCount != 2)
            error("Shift immediate instructions require two operands (rd, imm)");
        if (!isValidRegister(operands[0]))
            error("Shift immediate: first operand must be a register");
        /*
    if (!isValidImmediate(operands[1], true, 5))
        error("Shift immediate: second operand must be a 5-bit unsigned immediate");
        */
    }
    return true;
}

void error(const char *message)
{
    fprintf(stderr, "Error: %s\n", message);
    exit(1);
}
void expand_macro(Line *line_entry, ArrayList *instruction_list, int *address)
{
    Line new_entry;
    memset(&new_entry, 0, sizeof(Line));
    new_entry.type = 'I';

    if (strcasecmp(line_entry->opcode, "clr") == 0)
    {
        strcpy(new_entry.opcode, "xor");
        strncpy(new_entry.operands[0], line_entry->operands[0], sizeof(new_entry.operands[0]) - 1);
        strncpy(new_entry.operands[1], line_entry->operands[0], sizeof(new_entry.operands[1]) - 1);
        strncpy(new_entry.operands[2], line_entry->operands[0], sizeof(new_entry.operands[2]) - 1);
        new_entry.operand_count = 3;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        // (*address) += 4;
        return;
    }
    else if (strcasecmp(line_entry->opcode, "halt") == 0)
    {
        // halt -> priv r0, r0, r0, 0x0
        strcpy(new_entry.opcode, "priv");
        strcpy(new_entry.operands[0], "r0");
        strcpy(new_entry.operands[1], "r0");
        strcpy(new_entry.operands[2], "r0");
        strcpy(new_entry.operands[3], "0x0"); // Immediate 0x0
        new_entry.operand_count = 4;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        // (*address) += 4;
        return;
    }

    else if (strcasecmp(line_entry->opcode, "push") == 0)
    {
        // push rd -> mov (r31)(-8), rd; subi r31, 8
        // First instruction: mov (r31)(-8), rd
        strcpy(new_entry.opcode, "mov");
        // Set operand 0 to the fixed memory operand "(r31)(-8)"
        snprintf(new_entry.operands[0], sizeof(new_entry.operands[0]), "(r31)(-8)");
        // Set operand 1 to the register provided by the macro (rd)
        strncpy(new_entry.operands[1], line_entry->operands[0], sizeof(new_entry.operands[1]) - 1);
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        // (*address) += 4;

        // Second instruction: subi r31, 8
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "subi");
        // For immediate arithmetic in our macro, we want to output "subi r31, 8"
        strcpy(new_entry.operands[0], "r31");
        strcpy(new_entry.operands[1], "8"); // Use the literal "8" (as a string)
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        // (*address) += 4;
        return;
    }
    else if (strcasecmp(line_entry->opcode, "pop") == 0)
    {
        // pop rd -> mov rd, (r31)(0); addi r31, 8
        // First instruction: mov rd, (r31)(0)
        strcpy(new_entry.opcode, "mov");
        // Set operand 0 to the register provided (rd)
        strncpy(new_entry.operands[0], line_entry->operands[0], sizeof(new_entry.operands[0]) - 1);
        // Set operand 1 to the fixed memory operand "(r31)(0)"
        snprintf(new_entry.operands[1], sizeof(new_entry.operands[1]), "(r31)(0)");
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        // (*address) += 4;

        // Second instruction: addi r31, 8
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "addi");
        strcpy(new_entry.operands[0], "r31");
        strcpy(new_entry.operands[1], "8"); // Use literal "8" instead of "r31"
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        // (*address) += 4;
        return;
    }
    else if (strcasecmp(line_entry->opcode, "out") == 0)
    {
        // out rs, rt -> priv rs, rt, r0, 0x4
        strcpy(new_entry.opcode, "priv");
        strncpy(new_entry.operands[0], line_entry->operands[0], sizeof(new_entry.operands[0]) - 1);
        strncpy(new_entry.operands[1], line_entry->operands[1], sizeof(new_entry.operands[1]) - 1);
        strcpy(new_entry.operands[2], "r0");
        snprintf(new_entry.operands[3], sizeof(new_entry.operands[3]), "0x4");
        new_entry.operand_count = 4;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    else if (strcasecmp(line_entry->opcode, "in") == 0)
    {
        // in rd -> priv rd, r?, r0, 0x3 (assume the second operand is provided in the source code)
        // For this example, we assume the syntax "in rd, rX" where rX is provided.
        strcpy(new_entry.opcode, "priv");
        strncpy(new_entry.operands[0], line_entry->operands[0], sizeof(new_entry.operands[0]) - 1);
        strncpy(new_entry.operands[1], line_entry->operands[1], sizeof(new_entry.operands[1]) - 1);
        strcpy(new_entry.operands[2], "r0");
        snprintf(new_entry.operands[3], sizeof(new_entry.operands[3]), "0x3");
        new_entry.operand_count = 4;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        // (*address) += 4;
        return;
    }
    // Inside process_file() or similar:
    if (strcasecmp(line_entry->opcode, "ld") == 0)
    {

        expand_ld_instruction(line_entry, instruction_list, address, labels);
    }

    // If the instruction is not a defined macro, do nothing.
}

#define MAX_OPERAND_LENGTH 32

void expand_ld_instruction(Line *line_entry, ArrayList *instruction_list, int *address, LabelTable *labels)
{
    long long value;

    // If the literal operand starts with a colon, resolve it as a label.
    if (line_entry->operands[1][0] == ':')
    {
        char lbl[20];
        // Copy everything after the colon.
        strcpy(lbl, line_entry->operands[1] + 1);
        trim_whitespace(lbl);

        // Remove surrounding quotes if present.
        if (lbl[0] == '\"' || lbl[0] == '\'')
        {
            memmove(lbl, lbl + 1, strlen(lbl));
        }
        size_t len = strlen(lbl);
        if (len > 0 && (lbl[len - 1] == '\"' || lbl[len - 1] == '\''))
        {
            lbl[len - 1] = '\0';
        }

        printf("DEBUG: Looking up label: '%s'\n", lbl);
        int addr = get_label_address(labels, lbl);

        printf("ADRESS OF LABEL IS'%i'", addr);
        if (addr == -1)
        {
            fprintf(stderr, "Undefined label: %s\n", lbl);
            exit(EXIT_FAILURE);
        }
        value = addr;
    }
    else
    {
        value = strtoll(line_entry->operands[1], NULL, 0); // Parse immediate value
    }

    // Break the 64-bit immediate into fixed chunks.
    long long chunk0 = (value >> 52) & 0xFFF; // top 12 bits
    long long chunk1 = (value >> 40) & 0xFFF;
    long long chunk2 = (value >> 28) & 0xFFF;
    long long chunk3 = (value >> 16) & 0xFFF;
    long long chunk4 = (value >> 4) & 0xFFF;
    long long chunk5 = value & 0xF; // final 4 bits

    Line new_entry1;
    memset(&new_entry1, 0, sizeof(Line));
    strcpy(new_entry1.opcode, "xor");
    // All three operands are the destination register.
    strncpy(new_entry1.operands[0], line_entry->operands[0], sizeof(new_entry1.operands[0]) - 1);
    strncpy(new_entry1.operands[1], line_entry->operands[0], sizeof(new_entry1.operands[1]) - 1);
    strncpy(new_entry1.operands[2], line_entry->operands[0], sizeof(new_entry1.operands[2]) - 1);
    new_entry1.operand_count = 3;
    new_entry1.program_counter = (*address);
    new_entry1.type = 'I';
    add_to_arraylist(instruction_list, new_entry1);
    // (*address) += 4;

    Line new_entry2;
    memset(&new_entry2, 0, sizeof(Line));
    new_entry2.type = 'I';
    strcpy(new_entry2.opcode, "addi");
    strncpy(new_entry2.operands[0], line_entry->operands[0], sizeof(new_entry2.operands[0]) - 1);
    // Use chunk0 (even if it is 0).
    snprintf(new_entry2.operands[1], sizeof(new_entry2.operands[1]), "%lld", chunk0);
    new_entry2.operand_count = 2;
    new_entry2.program_counter = (*address);
    add_to_arraylist(instruction_list, new_entry2);
    // (*address) += 4;

    // --- Instructions 3-10: Four pairs of (shftli, addi) for chunks 1 to 4 ---
    // Each pair shifts left by 12 bits and then adds the next 12-bit chunk.
    long long chunks[4] = {chunk1, chunk2, chunk3, chunk4};
    for (int i = 0; i < 4; i++)
    {
        // Shift left by 12
        {
            Line new_entry3;
            memset(&new_entry3, 0, sizeof(Line));
            new_entry3.type = 'I';
            strcpy(new_entry3.opcode, "shftli");
            strncpy(new_entry3.operands[0], line_entry->operands[0], sizeof(new_entry3.operands[0]) - 1);
            snprintf(new_entry3.operands[1], sizeof(new_entry3.operands[1]), "12");
            new_entry3.operand_count = 2;
            new_entry3.program_counter = (*address);
            add_to_arraylist(instruction_list, new_entry3);
            //(*address) += 4;
        }
        // Add the 12-bit chunk (even if it is 0)
        {
            Line new_entry4;
            memset(&new_entry4, 0, sizeof(Line));
            new_entry4.type = 'I';
            strcpy(new_entry4.opcode, "addi");
            strncpy(new_entry4.operands[0], line_entry->operands[0], sizeof(new_entry4.operands[0]) - 1);
            snprintf(new_entry4.operands[1], sizeof(new_entry4.operands[1]), "%lld", chunks[i]);
            new_entry4.operand_count = 2;
            new_entry4.program_counter = (*address);
            add_to_arraylist(instruction_list, new_entry4);
            // (*address) += 4;
        }
    }

    Line new_entry5;
    memset(&new_entry5, 0, sizeof(Line));
    new_entry5.type = 'I';
    strcpy(new_entry5.opcode, "shftli");
    strncpy(new_entry5.operands[0], line_entry->operands[0], sizeof(new_entry5.operands[0]) - 1);
    snprintf(new_entry5.operands[1], sizeof(new_entry5.operands[1]), "4");
    new_entry5.operand_count = 2;
    new_entry5.program_counter = (*address);
    add_to_arraylist(instruction_list, new_entry5);
    //(*address) += 4;
    Line new_entry6;
    memset(&new_entry6, 0, sizeof(Line));
    new_entry6.type = 'I';
    strcpy(new_entry6.opcode, "addi");
    strncpy(new_entry6.operands[0], line_entry->operands[0], sizeof(new_entry6.operands[0]) - 1);
    // Add the final 4 bits.
    snprintf(new_entry6.operands[1], sizeof(new_entry6.operands[1]), "%lld", chunk5);
    new_entry6.operand_count = 2;
    new_entry6.program_counter = (*address);
    add_to_arraylist(instruction_list, new_entry6);
    //  (*address) += 4;
}

void resolve_labels(ArrayList *instructions, LabelTable *labels)
{
    for (int i = 0; i < instructions->size; i++)
    {
        Line *line = &instructions->lines[i];

        // Resolve the dedicated label field, if it starts with a colon.
        if (line->label[0] == ':')
        {
            char lbl[20];
            strcpy(lbl, line->label + 1); // Remove the colon
            trim_whitespace(lbl);         // Ensure no leading/trailing spaces

            printf("DEBUG: Resolving label '%s' (without colon)\n", lbl);
            int addr = get_label_address(labels, lbl);

            if (addr != -1)
            {
                snprintf(line->label, sizeof(line->label), "%d", addr);
                printf("DEBUG: Label '%s' resolved to address %d\n", lbl, addr);
            }
            else
            {
                printf("ERROR: Label '%s' not found in label table!\n", lbl);
                strcpy(line->label, "UNRESOLVED");
            }
        }
        else if (line->label[0] != '\0')
        { // Handle labels without colons
            char lbl[20];
            strncpy(lbl, line->label, sizeof(lbl) - 1);
            lbl[sizeof(lbl) - 1] = '\0';
            trim_whitespace(lbl);

            printf("DEBUG: Resolving label '%s' (direct lookup)\n", lbl);
            int addr = get_label_address(labels, lbl);

            if (addr != -1)
            {
                snprintf(line->label, sizeof(line->label), "%d", addr);
                printf("DEBUG: Label '%s' resolved to address %d\n", lbl, addr);
            }
            else
            {
                printf("ERROR: Label '%s' not found in label table!\n", lbl);
                strcpy(line->label, "UNRESOLVED");
            }
        }

        // Also resolve any operand that begins with a colon.
        for (int j = 0; j < line->operand_count; j++)
        {
            if (line->operands[j][0] == ':')
            {
                char lbl[20];
                strcpy(lbl, line->operands[j] + 1); // Remove the colon
                trim_whitespace(lbl);

                printf("DEBUG: Resolving operand label '%s' (without colon)\n", lbl);
                int addr = get_label_address(labels, lbl);

                if (addr != -1)
                {
                    snprintf(line->operands[j], sizeof(line->operands[j]), "%d", addr);
                    printf("DEBUG: Operand label '%s' resolved to address %d\n", lbl, addr);
                }
                else
                {
                    printf("ERROR: Operand Label '%s' not found in label table!\n", lbl);
                    strcpy(line->operands[j], "UNRESOLVED");
                }
            }
            else if (isLabelSyntax(line->operands[j]))
            { // Handle labels without colons
                char lbl[20];
                strncpy(lbl, line->operands[j], sizeof(lbl) - 1);
                lbl[sizeof(lbl) - 1] = '\0';
                trim_whitespace(lbl);

                printf("DEBUG: Resolving operand label '%s' (direct lookup)\n", lbl);
                int addr = get_label_address(labels, lbl);

                if (addr != -1)
                {
                    snprintf(line->operands[j], sizeof(line->operands[j]), "%d", addr);
                    printf("DEBUG: Operand label '%s' resolved to address %d\n", lbl, addr);
                }
                else
                {
                    printf("ERROR: Operand Label '%s' not found in label table!\n", lbl);
                    strcpy(line->operands[j], "UNRESOLVED");
                }
            }
        }
    }
}

int process_file_first_pass(const char *input_filename, LabelTable **labels, int *address)
{
    FILE *fp = fopen(input_filename, "r");
    if (!fp)
    {
        printf("Error: Could not open input file %s\n", input_filename);
        return 1;
    }

    char buffer[256];
    int in_code_section = 1; // 1 = .code, 0 = .data

    printf("DEBUG: Starting first pass...\n");

    while (fgets(buffer, sizeof(buffer), fp))
    {
        remove_comments(buffer);
        trim_whitespace(buffer);
        if (strchr(buffer, '-') != NULL)
        {
            fprintf(stderr, "Error: Negative values are not allowed anywhere in the line.\n");
            exit(1);
        }
        if (strlen(buffer) == 0)
            continue;

        // Handle section directives.
        if (strncmp(buffer, ".code", 5) == 0)
        {
            in_code_section = 1;
            *address = 0x2000; // Reset the address to the start of the data section.
            printf("DEBUG: Entering .code section at address %d\n", *address);
            continue;
        }
        if (strncmp(buffer, ".data", 5) == 0)
        {
            in_code_section = 0;
            *address = 0x10000; // Reset the address to the start of the data section.
            printf("DEBUG: Entering .data section at address 0x%X\n", *address);
            continue;
        }

        // If the line is a label (starts with ':')
        if (buffer[0] == ':')
        {
            if (!validate_label_format(buffer))
            {
                fprintf(stderr, "Syntax Error: Invalid label format: %s\n", buffer);
                fclose(fp);
                return 1;
            }

            // Trim the label first.
            char tempLabel[50];
            strncpy(tempLabel, buffer, sizeof(tempLabel) - 1);
            tempLabel[sizeof(tempLabel) - 1] = '\0';
            trim_whitespace(tempLabel);

            // Store the label in the label table.

            store_label(labels, tempLabel + 1, *address, in_code_section);
            int stored_addr = get_label_address(*labels, tempLabel + 1);
            printf("DEBUG: Stored Label -> %s at address %d (retrieved address: %d)\n",
                   tempLabel + 1, *address, stored_addr);
            print_label_table(*labels);

            printf("DEBUG: Stored Label -> %s at address %d\n", tempLabel + 1, *address);
        }
        else
        {
            // Increment address for instructions or data.
            char *line = malloc(strlen(buffer));
            line = strdup(buffer);
            char *tkn = malloc(strlen(line));
            tkn = strtok(line, " ");

            if (strcmp(tkn, "ld") == 0)
            {
                *address += 48;
            }
            else if (strcmp(tkn, "push") == 0)
            {
                *address += 8;
            }
            else if (strcmp(tkn, "pop") == 0)
            {
                *address += 8;
            }
            else
            {
                *address += in_code_section ? 4 : 8;
            }
            printf("DEBUG: Processed instruction/data, updated address to %d\n", *address);
        }
    }

    printf("DEBUG: First pass completed.\n");

    fclose(fp);
    return 0;
}

int process_file_second_pass(const char *input_filename, ArrayList *lines, LabelTable *labels, int *address)
{
    FILE *fp = fopen(input_filename, "r");
    if (!fp)
    {
        printf("Error: Could not open input file %s\n", input_filename);
        return 1;
    }

    char buffer[256];
    char original_buffer[256]; // Save original line for validation
    int in_code_section = 1;   // 1 = .code, 0 = .data

    while (fgets(buffer, sizeof(buffer), fp))
    {
        validate_spacing(buffer);

        strcpy(original_buffer, buffer); // Save the original line
        remove_comments(buffer);
        trim_whitespace(buffer);
        if (strlen(buffer) == 0)
            continue;

        // Handle section directives.
        if (strncmp(buffer, ".code", 5) == 0)
        {
            in_code_section = 1;

            // Add .code directive to the array list
            Line section_line;
            memset(&section_line, 0, sizeof(Line));
            strcpy(section_line.opcode, ".code");
            section_line.type = 'I'; // Mark as instruction section
            section_line.program_counter = *address;
            add_to_arraylist(lines, section_line);

            continue;
        }
        if (strncmp(buffer, ".data", 5) == 0)
        {
            in_code_section = 0;

            // Add .data directive to the array list
            Line section_line;
            memset(&section_line, 0, sizeof(Line));
            strcpy(section_line.opcode, ".data");
            section_line.type = 'D'; // Mark as data section
            section_line.program_counter = *address;
            add_to_arraylist(lines, section_line);

            continue;
        }

        // If the line is a label (starts with ':'), skip it (already processed in the first pass).
        if (buffer[0] == ':')
        {
            continue;
        }

        // For data section, if the line consists solely of a number, treat it as a data literal.
        char *firstToken = strtok(buffer, " \t");
        if (firstToken && firstToken[0] == '-')
        {
            fprintf(stderr, "Error: Negative values are not allowed.\n");
            exit(1);
        }

        if (!in_code_section && (isdigit(firstToken[0])))
        {
            Line data_line;
            memset(&data_line, 0, sizeof(Line));
            data_line.program_counter = *address;
            data_line.size = 8; // Data items take 8 bytes.
            data_line.type = 'D';
            // Save the literal as an integer value.
            data_line.literal = (unsigned int)strtoul(firstToken, NULL, 0);
            // Store the literal as text in the opcode field (so we can print it).
            snprintf(data_line.opcode, sizeof(data_line.opcode), "%d", data_line.literal);
            data_line.operand_count = 0;
            add_to_arraylist(lines, data_line);
            // *address += 8;
            continue;
        }

        // Otherwise, process as an instruction.
        // Restore the original buffer for tokenization/validation.
        strcpy(buffer, original_buffer);
        remove_comments(buffer);
        trim_whitespace(buffer);

        // Check if there's a '-' anywhere in the line
        if (strchr(original_buffer, '-') != NULL)
        {
            fprintf(stderr, "Error: Negative values are not allowed anywhere in the line.\n");
            exit(1);
        }
        char *token = strtok(buffer, " \t");
        if (!token)
        {
            fprintf(stderr, "Syntax Error: Empty instruction\n");
            fclose(fp);
            return 1;
        }

        printf("\nDEBUG: Tokenized Instruction -> %s\n", token);

        Line line_entry;
        memset(&line_entry, 0, sizeof(Line));
        line_entry.program_counter = *address;
        line_entry.size = in_code_section ? 4 : 8;
        line_entry.type = in_code_section ? 'I' : 'D';
        line_entry.from_call = 0;

        // Check if the instruction is a macro.
        if (strcasecmp(token, "halt") == 0)
        {
            // Special-case: halt takes no operands.
            strcpy(line_entry.opcode, token);
            line_entry.operand_count = 0;
            char *validateCopy = strdup(original_buffer);
            if (!validateCopy)
                error("Memory allocation failed during macro validation");
            validate_macro_instruction(validateCopy); // Should succeed.
            free(validateCopy);
            expand_macro(&line_entry, lines, address);
        }
        else if (validate_macro(token))
        {
            // Validate macro using a duplicate.
            char *validateCopy = strdup(original_buffer);
            if (!validateCopy)
                error("Memory allocation failed during macro validation");
            validate_macro_instruction(validateCopy);
            free(validateCopy);

            // Duplicate the original line for tokenization.
            char *macroLine = strdup(original_buffer);
            if (!macroLine)
                error("Memory allocation failed during macro expansion tokenization");

            char *macroToken = strtok(macroLine, " \t");
            strcpy(line_entry.opcode, macroToken);
            int opCount = 0;
            while ((macroToken = strtok(NULL, " \t,")) != NULL && opCount < 4)
            {
                trim_whitespace(macroToken);
                if (strlen(macroToken) > 0)
                {
                    strncpy(line_entry.operands[opCount], macroToken, sizeof(line_entry.operands[opCount]) - 1);
                    printf("DEBUG: Macro Operand[%d]: '%s'\n", opCount, line_entry.operands[opCount]);
                    opCount++;
                }
            }
            line_entry.operand_count = opCount;
            free(macroLine);

            expand_macro(&line_entry, lines, address);
        }
        else
        {
            strcpy(line_entry.opcode, token);
            int opCount = 0;
            while ((token = strtok(NULL, " \t,")) != NULL && opCount < 4)
            {
                if (isMemoryOperand(token))
                {
                    strncpy(line_entry.operands[opCount], token, sizeof(line_entry.operands[opCount]) - 1);
                }
                else if (token[0] == 'r' && isValidRegister(token))
                {
                    strncpy(line_entry.registers[opCount], token, sizeof(line_entry.registers[opCount]) - 1);
                    strncpy(line_entry.operands[opCount], token, sizeof(line_entry.operands[opCount]) - 1);
                }
                else if (isdigit(token[0]) || token[0] == '-')
                {
                    line_entry.literal = atoi(token);
                    strncpy(line_entry.operands[opCount], token, sizeof(line_entry.operands[opCount]) - 1);
                }
                else if (token[0] == ':')
                {
                    strncpy(line_entry.label, token, sizeof(line_entry.label) - 1);
                    strncpy(line_entry.operands[opCount], token, sizeof(line_entry.operands[opCount]) - 1);
                }
                else
                {
                    strncpy(line_entry.operands[opCount], token, sizeof(line_entry.operands[opCount]) - 1);
                }
                printf("DEBUG: Operand[%d]: %s\n", opCount, token);
                opCount++;
            }
            line_entry.operand_count = opCount;
            remove_comments(original_buffer);
            validate_instruction(original_buffer);
            add_to_arraylist(lines, line_entry);
            // *address += in_code_section ? 4 : 8;
        }
    }

    fclose(fp);
    return 0;
}

void write_output_file(const char *output_filename, ArrayList *instructions)
{
    FILE *fp = fopen(output_filename, "w");
    if (!fp)
    {
        perror("Error opening output file");
        return;
    }

    // Print header to stdout for clarity.
    printf("\n----- Final Assembled Output -----\n");

    // Print a single .code section header.
    fprintf(fp, ".code\n");
    printf(".code\n");

    // Loop through instructions and print only code lines (type 'I')
    // that are not section directives (i.e. opcode does NOT start with '.').
    for (int i = 0; i < instructions->size; i++)
    {
        Line *line = &instructions->lines[i];

        // Only output code instructions and ignore any section directives.
        if (line->type == 'I' && line->opcode[0] != '.')
        {
            // Print a tab for formatting.
            fprintf(fp, "\t");
            printf("\t");

            // Based on specific formatting rules.
            if ((strcasecmp(line->opcode, "addi") == 0 || strcasecmp(line->opcode, "subi") == 0) &&
                line->operand_count == 2)
            {
                fprintf(fp, "%s %s, %s", line->opcode, line->operands[0], line->operands[1]);
                printf("%s %s, %s", line->opcode, line->operands[0], line->operands[1]);
            }
            else if (strcasecmp(line->opcode, "mov") == 0 && line->operand_count == 2)
            {
                fprintf(fp, "mov %s, %s", line->operands[0], line->operands[1]);
                printf("mov %s, %s", line->operands[0], line->operands[1]);
            }
            else if (strcasecmp(line->opcode, "xor") == 0 && line->operand_count == 3)
            {
                fprintf(fp, "xor %s, %s, %s", line->operands[0], line->operands[1], line->operands[2]);
                printf("xor %s, %s, %s", line->operands[0], line->operands[1], line->operands[2]);
            }
            else if (strcasecmp(line->opcode, "shftli") == 0 && line->operand_count == 2)
            {
                fprintf(fp, "shftli %s, %s", line->operands[0], line->operands[1]);
                printf("shftli %s, %s", line->operands[0], line->operands[1]);
            }
            else if (strcasecmp(line->opcode, "st") == 0 || strcasecmp(line->opcode, "ld") == 0)
            {
                fprintf(fp, "%s %s, %s", line->opcode, line->operands[0], line->operands[1]);
                printf("%s %s, %s", line->opcode, line->operands[0], line->operands[1]);
                if (line->operand_count == 3)
                {
                    fprintf(fp, ", %s", line->operands[2]);
                    printf(", %s", line->operands[2]);
                }
            }
            else if (strcasecmp(line->opcode, "trap") == 0)
            {
                fprintf(fp, "trap %s", line->operands[0]);
                printf("trap %s", line->operands[0]);
            }
            else if (strcasecmp(line->opcode, "br") == 0)
            {
                if (line->label[0] != '\0')
                {
                    fprintf(fp, "br %s", line->label);
                    printf("br %s", line->label);
                }
                else
                {
                    fprintf(fp, "br %s", line->operands[0]);
                    printf("br %s", line->operands[0]);
                }
            }
            else if (strcasecmp(line->opcode, "priv") == 0 && line->operand_count == 4)
            {
                fprintf(fp, "priv %s, %s, %s, %s", line->operands[0],
                        line->operands[1], line->operands[2], line->operands[3]);
                printf("priv %s, %s, %s, %s", line->operands[0],
                       line->operands[1], line->operands[2], line->operands[3]);
            }
            else
            {
                // General instruction format.
                fprintf(fp, "%s", line->opcode);
                printf("%s", line->opcode);
                for (int j = 0; j < line->operand_count; j++)
                {
                    if (j == 0)
                    {
                        fprintf(fp, " %s", line->operands[j]);
                        printf(" %s", line->operands[j]);
                    }
                    else
                    {
                        fprintf(fp, ", %s", line->operands[j]);
                        printf(", %s", line->operands[j]);
                    }
                }
            }
            // End the instruction line.
            fprintf(fp, "\n");
            printf("\n");
        }
    }

    // Print a single .data section header.
    fprintf(fp, ".data\n");
    printf(".data\n");

    // Output data lines that are not section directives.
    for (int i = 0; i < instructions->size; i++)
    {
        Line *line = &instructions->lines[i];

        // Only output data lines (type 'D') that are not directives.
        if (line->type == 'D' && line->operand_count == 0 && line->opcode[0] != '.')
        {
            unsigned int data = (unsigned int)strtoul(line->opcode, NULL, 0);
            fprintf(fp, "\t%u\n", data);
            printf("\t%u\n", data);
        }
    }

    fclose(fp);

    // Mark the end of the output.
    printf("----- End of Assembled Output -----\n\n");
}
