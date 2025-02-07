#include "syntax_verifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <strings.h>

/* -------------------- Helper Functions -------------------- */
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

/* -------------------- Syntax Validation Helpers -------------------- */
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
        if (!allow_negative) // If negatives aren't allowed (e.g., in unsigned immediate fields)
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

/* -------------------- New Helper Functions -------------------- */
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

int validate_spacing(char *line)
{
    trim_whitespace(line); // Remove leading and trailing whitespace
    char *tokens[5];
    int token_count = 0;
    char *copy = strdup(line);
    if (!copy)
    {
        perror("Memory allocation failed in validate_spacing");
        exit(1);
    }
    char *token = strtok(copy, " ");
    while (token && token_count < 5)
    {
        tokens[token_count++] = token;
        token = strtok(NULL, " ");
    }
    int opcode_len = strlen(tokens[0]);
    if (line[opcode_len] != ' ')
    {
        free(copy);
        fprintf(stderr, "Syntax Error: Opcode must be followed by exactly one space: %s\n", line);
        return 0;
    }
    for (int i = 1; i < token_count - 1; i++)
    {
        int len = strlen(tokens[i]);
        if (tokens[i][len - 1] != ',')
        {
            free(copy);
            fprintf(stderr, "Syntax Error: Incorrect spacing around operands: %s\n", line);
            return 0;
        }
    }
    free(copy);
    return 1;
}

/* -------------------- validate_instruction() -------------------- */
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
        if (!isValidImmediate(operands[0], true, 12) && !isLabelSyntax(operands[0]))
            error("call: operand must be a 12-bit signed immediate or a label");
    }
    else if (strcasecmp(opcode, "return") == 0)
    {
        if (operandCount != 0)
            error("return takes no operands");
    }
    else if (strcasecmp(opcode, "ld") == 0)
    {
        if (operandCount != 3)
            error("ld requires three operands (rd, rs, imm)");
        if (!isValidRegister(operands[0]) || !isValidRegister(operands[1]))
            error("ld: first two operands must be registers");
        if (!isValidImmediate(operands[2], true, 12))
            error("ld: third operand must be a 12-bit signed immediate");
    }
    else if (strcasecmp(opcode, "mov") == 0)
    {
        if (operandCount == 2)
        {
            if (isValidRegister(operands[0]) && isValidRegister(operands[1]))
                return true;
            if (isValidRegister(operands[0]) && isValidImmediate(operands[1], true, 12))
                return true;
        }
        else if (operandCount == 3)
        {
            if (isMemoryOperand(operands[0]) && isValidRegister(operands[1]))
                return true;
            if (isMemoryOperand(operands[1]) && isValidRegister(operands[0]))
                return true;
        }
        error("mov: Invalid operands. Must be one of: (rd, rs) or (rd, imm) or memory forms.");
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
        if (!isValidImmediate(operands[1], true, 5))
            error("Shift immediate: second operand must be a 5-bit unsigned immediate");
    }
    return true;
}

/* -------------------- expand_macro() -------------------- */
/* Expands the following macros:
   - clr rd   → xor rd, rd, rd
   - push rd  → mov (r31)(-8), rd; subi r31, r31, 8
   - pop rd   → mov rd, (r31)(0); addi r31, r31, 8
   - out rs, rt → priv rs, rt, r0, 0x4
   - in rd    → priv rd, r?, r0, 0x3   (assumes a second register operand is provided)
   - halt     → trap 0
*/
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
        (*address) += 4;
        return;
    }
    else if (strcasecmp(line_entry->opcode, "halt") == 0)
    {
        // halt -> trap 0
        strcpy(new_entry.opcode, "trap");
        strcpy(new_entry.operands[0], "0");
        new_entry.operand_count = 1;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    else if (strcasecmp(line_entry->opcode, "push") == 0)
    {
        // push rd -> mov (r31)(-8), rd; subi r31, r31, 8
        strcpy(new_entry.opcode, "mov");
        snprintf(new_entry.operands[0], sizeof(new_entry.operands[0]), "(r31)(-8)");
        strncpy(new_entry.operands[1], line_entry->operands[0], sizeof(new_entry.operands[1]) - 1);
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;

        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "subi");
        strcpy(new_entry.operands[0], "r31");
        strcpy(new_entry.operands[1], "r31");
        new_entry.literal = 8;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    else if (strcasecmp(line_entry->opcode, "pop") == 0)
    {
        // pop rd -> mov rd, (r31)(0); addi r31, r31, 8
        strcpy(new_entry.opcode, "mov");
        strncpy(new_entry.operands[0], line_entry->operands[0], sizeof(new_entry.operands[0]) - 1);
        snprintf(new_entry.operands[1], sizeof(new_entry.operands[1]), "(r31)(0)");
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;

        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "addi");
        strcpy(new_entry.operands[0], "r31");
        strcpy(new_entry.operands[1], "r31");
        new_entry.literal = 8;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
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
        (*address) += 4;
        return;
    }
    else if (strcasecmp(line_entry->opcode, "ld") == 0)
    {
        // ld rd, L -> Load literal L into rd using a sequence of instructions.
        long long value = atoll(line_entry->operands[1]);

        // Clear rd: xor rd, rd, rd
        strcpy(new_entry.opcode, "xor");
        strncpy(new_entry.operands[0], line_entry->operands[0], sizeof(new_entry.operands[0]) - 1);
        strncpy(new_entry.operands[1], line_entry->operands[0], sizeof(new_entry.operands[1]) - 1);
        strncpy(new_entry.operands[2], line_entry->operands[0], sizeof(new_entry.operands[2]) - 1);
        new_entry.operand_count = 3;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;

        // For simplicity, use a loop to load chunks of the literal.
        for (int shift = 40; shift >= 0; shift -= 12)
        {
            memset(&new_entry, 0, sizeof(Line));
            new_entry.type = 'I';
            strcpy(new_entry.opcode, "shftli");
            strncpy(new_entry.operands[0], line_entry->operands[0], sizeof(new_entry.operands[0]) - 1);
            snprintf(new_entry.operands[1], sizeof(new_entry.operands[1]), "12");
            new_entry.operand_count = 2;
            new_entry.program_counter = (*address);
            add_to_arraylist(instruction_list, new_entry);
            (*address) += 4;

            memset(&new_entry, 0, sizeof(Line));
            new_entry.type = 'I';
            strcpy(new_entry.opcode, "addi");
            strncpy(new_entry.operands[0], line_entry->operands[0], sizeof(new_entry.operands[0]) - 1);
            snprintf(new_entry.operands[1], sizeof(new_entry.operands[1]), "%lld", (value >> shift) & 0xFFF);
            new_entry.operand_count = 2;
            new_entry.program_counter = (*address);
            add_to_arraylist(instruction_list, new_entry);
            (*address) += 4;
        }
    }
    // If the instruction is not a defined macro, do nothing.
}

/* -------------------- resolve_labels() -------------------- */
void resolve_labels(ArrayList *instructions, LabelTable *labels)
{
    for (int i = 0; i < instructions->size; i++)
    {
        Line *line = &instructions->lines[i];
        if (line->label[0] == ':')
        {
            char lbl[20];
            strcpy(lbl, line->label + 1);
            int addr = get_label_address(labels, lbl);
            if (addr != -1)
                snprintf(line->label, sizeof(line->label), "0x%X", addr);
        }
    }
}

/* -------------------- process_file() -------------------- */
int process_file(const char *input_filename, ArrayList *lines, LabelTable **labels)
{
    FILE *fp = fopen(input_filename, "r");
    if (!fp)
    {
        printf("Error: Could not open input file %s\n", input_filename);
        return 1;
    }

    char buffer[256];
    char original_buffer[256]; // Save original line for validation
    int address = 0x1000;      // PC starts at 0x1000
    int in_code_section = 1;   // 1 = .code, 0 = .data

    while (fgets(buffer, sizeof(buffer), fp))
    {
        strcpy(original_buffer, buffer); // Save the original line
        remove_comments(buffer);
        trim_whitespace(buffer);
        if (strlen(buffer) == 0)
            continue;

        if (strncmp(buffer, ".code", 5) == 0)
        {
            in_code_section = 1;
            continue;
        }
        if (strncmp(buffer, ".data", 5) == 0)
        {
            in_code_section = 0;
            continue;
        }
        validate_spacing(buffer);

        Line line_entry;
        memset(&line_entry, 0, sizeof(Line));
        line_entry.program_counter = address;
        line_entry.size = in_code_section ? 4 : 8;
        line_entry.type = in_code_section ? 'I' : 'D';
        line_entry.from_call = 0;

        // If the line is a label (starts with ':')
        if (buffer[0] == ':')
        {
            if (!validate_label_format(buffer))
            {
                fprintf(stderr, "Syntax Error: Invalid label format: %s\n", buffer);
                fclose(fp);
                return 1;
            }
            store_label(labels, buffer + 1, address, in_code_section);
            continue;
        }

        // For data section, if the line consists solely of a number, treat it as a data literal.
        char *firstToken = strtok(buffer, " \t");
        if (!in_code_section && (isdigit(firstToken[0]) || firstToken[0] == '-'))
        {
            // Treat as a data literal.
            line_entry.literal = atoi(firstToken);
            // For data, we don't need an opcode; you may leave it blank.
            strcpy(line_entry.opcode, "");
            line_entry.operand_count = 0;
            add_to_arraylist(lines, line_entry);
            address += 8;
            continue;
        }

        // Otherwise, process as an instruction
        // Restore the original buffer for tokenization/validation.
        strcpy(buffer, original_buffer);
        remove_comments(buffer);
        trim_whitespace(buffer);

        char *token = strtok(buffer, " \t");
        if (!token)
        {
            fprintf(stderr, "Syntax Error: Empty instruction\n");
            fclose(fp);
            return 1;
        }

        printf("\nDEBUG: Tokenized Instruction -> %s\n", token);

        if (validate_macro(token))
        {
            strcpy(line_entry.opcode, token);
            int opCount = 0;
            while ((token = strtok(NULL, " \t,")) != NULL && opCount < 4)
            {
                strncpy(line_entry.operands[opCount], token, sizeof(line_entry.operands[opCount]) - 1);
                printf("DEBUG: Macro Operand[%d]: %s\n", opCount, token);
                opCount++;
            }
            line_entry.operand_count = opCount;
            expand_macro(&line_entry, lines, &address);
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
            address += in_code_section ? 4 : 8;
        }
    }

    fclose(fp);
    return 0;
}

/* -------------------- write_output_file() -------------------- */
void write_output_file(const char *output_filename, ArrayList *instructions)
{
    FILE *fp = fopen(output_filename, "w");
    if (!fp)
    {
        perror("Error opening output file");
        return;
    }

    char current_section = '\0';
    for (int i = 0; i < instructions->size; i++)
    {
        Line *line = &instructions->lines[i];
        if (line->type != current_section)
        {
            if (line->type == 'I')
                fprintf(fp, ".code\n");
            else if (line->type == 'D')
                fprintf(fp, ".data\n");
            current_section = line->type;
        }
        fprintf(fp, "\t");
        if ((strcasecmp(line->opcode, "addi") == 0 || strcasecmp(line->opcode, "subi") == 0) && line->operand_count == 2)
        {
            fprintf(fp, "%s %s, %s", line->opcode, line->operands[0], line->operands[1]);
        }
        else if (strcasecmp(line->opcode, "mov") == 0 && line->operand_count == 2)
        {
            fprintf(fp, "mov %s, %s", line->operands[0], line->operands[1]);
        }
        else if (strcasecmp(line->opcode, "xor") == 0 && line->operand_count == 3)
        {
            fprintf(fp, "xor %s, %s, %s", line->operands[0], line->operands[1], line->operands[2]);
        }
        else if (strcasecmp(line->opcode, "shftli") == 0 && line->operand_count == 2)
        {
            fprintf(fp, "shftli %s, %s", line->operands[0], line->operands[1]);
        }
        else if (strcasecmp(line->opcode, "st") == 0 || strcasecmp(line->opcode, "ld") == 0)
        {
            fprintf(fp, "%s %s, %s, %s", line->opcode, line->operands[0], line->operands[1], line->operands[2]);
        }
        else if (strcasecmp(line->opcode, "trap") == 0)
        {
            fprintf(fp, "trap %s", line->operands[0]);
        }
        else if (strcasecmp(line->opcode, "br") == 0)
        {
            if (line->label[0] != '\0')
                fprintf(fp, "br %s", line->label);
            else
                fprintf(fp, "br %s", line->operands[0]);
        }
        else if (strcasecmp(line->opcode, "priv") == 0 && line->operand_count == 4)
        {
            fprintf(fp, "priv %s, %s, %s, %s", line->operands[0], line->operands[1], line->operands[2], line->operands[3]);
        }
        else
        {
            fprintf(fp, "%s", line->opcode);
            for (int j = 0; j < line->operand_count; j++)
            {
                if (j == 0)
                    fprintf(fp, " %s", line->operands[j]);
                else
                    fprintf(fp, ", %s", line->operands[j]);
            }
        }
        fprintf(fp, "\n");
    }
    fclose(fp);
}
