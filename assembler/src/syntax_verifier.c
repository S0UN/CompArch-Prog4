#include <stdio.h>
#include <stdlib.h>
#include <ctype.h> // Include this to use isdigit(), isspace(), isalnum()

#include <string.h>
#include "syntax_verifier.h"
#include "arraylist.h"
#include "label_table.h"
#include "line.h"

// Function to process the file and check syntax
// List of valid Tinker instructions
const char *valid_opcodes[] = {
    "add", "sub", "mul", "div", "addi", "subi",
    "shftl", "shftr", "xor", "and", "or", "not",
    "brr", "br", "call", "return", "ld", "mov",
    "priv", "trap", "halt", NULL // NULL to mark the end
};

const char *valid_macros[] = {
    "clr", "push", "pop", "out", "halt", "in", "ld", NULL};

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "syntax_verifier.h"
#include "arraylist.h"
#include "label_table.h"
#include "line.h"

#define MAX_TOKENS 4
#define MAX_LINE_LENGTH 256

// ------------------------------------------------------
// Second Pass: Resolve label operands in instructions
// ------------------------------------------------------
void resolve_labels(ArrayList *instructions, LabelTable *labels) {
    for (int i = 0; i < instructions->size; i++) {
        Line *line = &instructions->lines[i];
        // If the dedicated label field holds a label (starting with ':'),
        // look it up and replace with its hexadecimal address.
        if (line->label[0] == ':') {
            char label_name[20];
            strcpy(label_name, line->label + 1); // Skip the colon
            int addr = get_label_address(labels, label_name);
            if (addr == -1) {
                fprintf(stderr, "Error: Undefined label %s\n", line->label);
            } else {
                snprintf(line->label, sizeof(line->label), "0x%X", addr);
            }
        }
        // Also, resolve any label present in the operands array.
        for (int j = 0; j < line->operand_count; j++) {
            if (line->operands[j][0] == ':') {
                char label_name[20];
                strcpy(label_name, line->operands[j] + 1);
                int addr = get_label_address(labels, label_name);
                if (addr == -1) {
                    fprintf(stderr, "Error: Undefined label %s\n", line->operands[j]);
                } else {
                    snprintf(line->operands[j], sizeof(line->operands[j]), "0x%X", addr);
                }
            }
        }
    }
}

// ------------------------------------------------------
// Write final output to a .tk file with proper formatting
// ------------------------------------------------------
void write_output_file(const char *output_filename, ArrayList *instructions, LabelTable *labels) {
    FILE *fp = fopen(output_filename, "w");
    if (!fp) {
        perror("Error opening output file");
        return;
    }
    
    char current_section = '\0';
    // Assume instructions are stored in order (by program counter)
    for (int i = 0; i < instructions->size; i++) {
        Line *line = &instructions->lines[i];
        // Insert a section directive if the type changes.
        if (line->type != current_section) {
            if (line->type == 'I')
                fprintf(fp, ".code\n");
            else if (line->type == 'D')
                fprintf(fp, ".data\n");
            current_section = line->type;
        }
        // Write the instruction line with a tab indent.
        // We use the opcode field and then output each operand (which may have been resolved).
        fprintf(fp, "\t%s", line->opcode);
        for (int j = 0; j < line->operand_count; j++) {
            if (j == 0)
                fprintf(fp, " %s", line->operands[j]);
            else
                fprintf(fp, ", %s", line->operands[j]);
        }
        fprintf(fp, "\n");
    }
    
    fclose(fp);
}

void tokenize_line(const char *line_buffer, char *tokens[], int *token_count)
{
    *token_count = 0;
    char temp_buffer[MAX_LINE_LENGTH]; // Copy of line_buffer to avoid modifying original
    strncpy(temp_buffer, line_buffer, MAX_LINE_LENGTH - 1);
    temp_buffer[MAX_LINE_LENGTH - 1] = '\0'; // Ensure null termination

    char *token = strtok(temp_buffer, " ,");
    while (token && *token_count < MAX_TOKENS)
    {
        tokens[(*token_count)++] = token;
        token = strtok(NULL, " ,");
    }

    // Print tokenized output
    printf("Tokenized result (%d tokens):\n", *token_count);
    for (int i = 0; i < *token_count; i++)
    {
        printf("tokens[%d] = \"%s\"\n", i, tokens[i]);
    }
}

int process_file(const char *input_filename, ArrayList *lines, LabelTable **labels)
{
    FILE *input_file = fopen(input_filename, "r");
    if (!input_file)
    {
        printf("Error: Could not open input file %s\n", input_filename);
        return 1;
    }

    char line_buffer[MAX_LINE_LENGTH];
    int address = 0x1000;    // Program Counter starts at 0x1000
    int in_code_section = 0; // 1 if in .code, 0 if in .data

    while (fgets(line_buffer, sizeof(line_buffer), input_file))
    {
        remove_comments(line_buffer);
        trim_trailing_whitespace(line_buffer);

        if (strlen(line_buffer) == 0)
            continue; // Skip empty lines

        // Detect section changes
        if (strncmp(line_buffer, ".code", 5) == 0)
        {
            in_code_section = 1;
            continue;
        }
        if (strncmp(line_buffer, ".data", 5) == 0)
        {
            in_code_section = 0;
            continue;
        }

        Line line_entry;
        memset(&line_entry, 0, sizeof(Line));
        line_entry.program_counter = address;
        line_entry.type = in_code_section ? 'I' : 'D';

        // Handle Labels
        if (line_buffer[0] == ':')
        {
            if (!validate_label_format(line_buffer))
            {
                report_error("Syntax Error: Invalid label format", line_buffer);
                fclose(input_file);
                return 1;
            }

            strncpy(line_entry.label, line_buffer + 1, sizeof(line_entry.label) - 1); // Remove leading ':'
            line_entry.is_label = 1;
            store_label(labels, line_entry.label, address, !in_code_section);
            continue; // Do not add labels directly to the instruction list
        }

        // Tokenize using helper function AFTER removing comments
        // Tokenize using helper function AFTER removing comments
        char *tokens[MAX_TOKENS] = {NULL};
        int token_count = 0;
        tokenize_line(line_buffer, tokens, &token_count);

        if (token_count == 0)
        {
            report_error("Syntax Error: Empty instruction", line_buffer);
            fclose(input_file);
            return 1;
        }

        // 🔥 FIRST: Check if it's a macro **before** opcode validation
        if (validate_macro(tokens[0]))
        {
            printf("DEBUG: Expanding macro: %s\n", tokens[0]);

            // Populate line_entry for macro expansion
            strncpy(line_entry.opcode, tokens[0], sizeof(line_entry.opcode) - 1);
            line_entry.operand_count = token_count - 1;

            // Copy operands before expansion
            for (int i = 1; i < token_count; i++)
            {
                strncpy(line_entry.operands[i - 1], tokens[i], sizeof(line_entry.operands[i - 1]) - 1);
                line_entry.operands[i - 1][sizeof(line_entry.operands[i - 1]) - 1] = '\0'; // Ensure null-termination
            }

            // 🔥 Expand macro BEFORE validating opcode
            expand_macro(&line_entry, lines, &address);
            continue; // ✅ Skip the rest of the normal instruction validation
        }

        // Validate opcode **after macros are expanded**
        if (!validate_opcode(tokens[0]))
        {
            report_error("Syntax Error: Invalid opcode", tokens[0]);
            fclose(input_file);
            return 1;
        }

        strncpy(line_entry.opcode, tokens[0], sizeof(line_entry.opcode) - 1);
        line_entry.operand_count = token_count - 1;

        // Populate operands & registers
        for (int i = 1; i < token_count; i++)
        {
            strncpy(line_entry.operands[i - 1], tokens[i], sizeof(line_entry.operands[i - 1]) - 1);
            line_entry.operands[i - 1][sizeof(line_entry.operands[i - 1]) - 1] = '\0'; // Ensure null-termination

            // Check if operand is a register, literal, or label
            if (tokens[i][0] == 'r' && validate_register(tokens[i]))
            {
                strncpy(line_entry.registers[i - 1], tokens[i], sizeof(line_entry.registers[i - 1]) - 1);
            }
            else if (isdigit(tokens[i][0]) || tokens[i][0] == '-')
            {
                line_entry.literal = atoi(tokens[i]); // Store as an integer literal
            }
            else if (tokens[i][0] == ':')
            {
                strncpy(line_entry.label, tokens[i], sizeof(line_entry.label) - 1);
            }
        }

        // Debugging output for validation
        printf("DEBUG: Parsed Instruction -> PC: 0x%X | Opcode: %s | Registers: [%s, %s, %s] | Literal: %d | Label: %s\n",
               line_entry.program_counter, line_entry.opcode,
               line_entry.registers[0], line_entry.registers[1], line_entry.registers[2],
               line_entry.literal, line_entry.label);

        // Add validated instruction to the instruction list
        add_to_arraylist(lines, line_entry);

        // Increment address (4 bytes per instruction)
        address += in_code_section ? 4 : 8;
    }

    fclose(input_file);
    return 0;
}
void expand_macro(Line *line_entry, ArrayList *instruction_list, int *address)
{
    Line new_entry;

    // ✅ Only process macros, return if it's a normal instruction
    if (!(strcmp(line_entry->opcode, "clr") == 0 ||
          strcmp(line_entry->opcode, "halt") == 0 ||
          strcmp(line_entry->opcode, "push") == 0 ||
          strcmp(line_entry->opcode, "pop") == 0 ||
          strcmp(line_entry->opcode, "out") == 0 ||
          strcmp(line_entry->opcode, "in") == 0 ||
          strcmp(line_entry->opcode, "call") == 0 ||
          strcmp(line_entry->opcode, "return") == 0))
    {
        return; // Not a macro, so do nothing
    }

    // ✅ Expand clr rX -> xor rX, rX, rX
    if (strcmp(line_entry->opcode, "clr") == 0)
    {
        new_entry = *line_entry;
        strcpy(new_entry.opcode, "xor");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0]) - 1);
        strncpy(new_entry.registers[1], new_entry.registers[0], sizeof(new_entry.registers[1]) - 1);
        strncpy(new_entry.registers[2], new_entry.registers[0], sizeof(new_entry.registers[2]) - 1);
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4; // Increment PC
        return;
    }

    // ✅ Expand halt -> trap 0x0
    if (strcmp(line_entry->opcode, "halt") == 0)
    {
        new_entry = *line_entry;
        strcpy(new_entry.opcode, "trap");
        new_entry.literal = 0;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }

    // ✅ Expand push rX -> subi r30, r30, 8 + st rX, r30, 0
    if (strcmp(line_entry->opcode, "push") == 0)
    {
        new_entry = *line_entry;
        strcpy(new_entry.opcode, "subi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;

        new_entry = *line_entry;
        strcpy(new_entry.opcode, "st");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0]) - 1);
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }

    // ✅ Expand pop rX -> ld rX, r30, 0 + addi r30, r30, 8
    if (strcmp(line_entry->opcode, "pop") == 0)
    {
        new_entry = *line_entry;
        strcpy(new_entry.opcode, "ld");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0]) - 1);
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;

        new_entry = *line_entry;
        strcpy(new_entry.opcode, "addi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }

    // ✅ Expand call :label -> subi r30, r30, 8 + st r31, r30, 0 + br :label
    if (strcmp(line_entry->opcode, "call") == 0)
    {
        new_entry = *line_entry;
        strcpy(new_entry.opcode, "subi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;

        new_entry = *line_entry;
        strcpy(new_entry.opcode, "st");
        strcpy(new_entry.registers[0], "r31");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;

        new_entry = *line_entry;
        strcpy(new_entry.opcode, "br");
        strncpy(new_entry.label, line_entry->operands[0], sizeof(new_entry.label) - 1);
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }

    // ✅ Expand return -> ld r31, r30, 0 + addi r30, r30, 8 + br r31
    if (strcmp(line_entry->opcode, "return") == 0)
    {
        new_entry = *line_entry;
        strcpy(new_entry.opcode, "ld");
        strcpy(new_entry.registers[0], "r31");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;

        new_entry = *line_entry;
        strcpy(new_entry.opcode, "addi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;

        new_entry = *line_entry;
        strcpy(new_entry.opcode, "br");
        strcpy(new_entry.registers[0], "r31");
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
}

void remove_comments(char *line)
{
    char *comment_pos = strchr(line, ';'); // Find the first occurrence of ';'
    if (comment_pos)
    {
        *comment_pos = '\0'; // Truncate the line at the comment position
    }

    trim_trailing_whitespace(line); // Remove any extra spaces left after comment removal
}
void trim_trailing_whitespace(char *line)
{
    int len = strlen(line);
    while (len > 0 && isspace(line[len - 1]))
    {
        line[--len] = '\0'; // Remove trailing whitespace
    }
}

// Function to determine whether a line is a comment, label, or instruction
/*
int validate_line_type(char *line)
{
   trim_trailing_whitespace(line); // Remove extra spaces at the end

   // Ignore empty lines and comments
   if (strlen(line) == 0 || line[0] == ';')
   {
       return 1; // No validation needed for comments
   }

   // If the line starts with a colon, it's a label
   if (line[0] == ':')
   {
       return validate_label_format(line); // Ensure label is formatted correctly
   }

   // Validate spacing before checking instruction or macro
   if (!validate_spacing(line))
   {
       report_error("Syntax Error: Incorrect spacing", line);
       return 0;
   }


   // Check if it's an instruction or macro

   if ((line))
   {
       return validate_instruction(line);
   }
   else if (validate_macro(line))
   {
       return 1; // Valid macro (already checked in validate_macro)
   }


   return 0;
}
*/
int validate_macro(char *token)
{
    // List of valid macros
    const char *valid_macros[] = {"clr", "push", "pop", "out", "halt", "in", NULL};

    // Check if token matches a known macro
    for (int i = 0; valid_macros[i] != NULL; i++)
    {
        if (strcmp(token, valid_macros[i]) == 0)
        {
            return 1; // ✅ Valid macro
        }
    }

    return 0; // ❌ Not a macro
}

int validate_memory_operand(char *token)
{
    // Check if it's a valid label (labels start with ':')
    if (token[0] == ':')
    {
        return validate_label_format(token); // Labels must be validated separately
    }

    // Check if it's a valid numeric memory address (e.g., 0x1000)
    if (strncmp(token, "0x", 2) == 0)
    {
        for (int i = 2; token[i] != '\0'; i++)
        {
            if (!isxdigit(token[i]))
            {
                return 0; // Not a valid hexadecimal number
            }
        }
        return 1; // Valid hex address
    }

    // Otherwise, invalid memory operand
    return 0;
}
// Function to check if an opcode is valid and debug tokens
int validate_opcode(char *token)
{
    int i = 0;
    const char *currOpcode = valid_opcodes[i]; // Initialize with first opcode

    // DEBUG: Print the received token BEFORE trimming
    printf("DEBUG: Raw opcode token: '%s'\n", token);

    // Trim leading spaces or tabs
    while (*token == ' ' || *token == '\t')
        token++;

    // DEBUG: Print the received token AFTER trimming
    printf("DEBUG: Trimmed opcode token: '%s'\n", token);

    while (currOpcode != NULL)
    {
        // DEBUG: Print the opcode being compared
        printf("DEBUG: Comparing with valid opcode: '%s'\n", currOpcode);

        if (strcmp(token, currOpcode) == 0)
        { // Compare token with valid opcodes
            printf("DEBUG: Matched opcode: '%s'\n", currOpcode);
            return 1; // Opcode is valid
        }
        i++;
        currOpcode = valid_opcodes[i]; // Move to next opcode
    }

    printf("DEBUG: Opcode '%s' not found!\n", token);
    return 0; // Opcode is invalid
}

/*
int validate_instruction(char *line) {
    if (line == NULL || strlen(line) == 0) {
        report_error("Syntax Error: Empty instruction", line);
        return 0;
    }

    // ✅ Allocate memory for a copy of the line (excluding leading whitespace)
    char *temp = malloc(strlen(&line[1]) + 1);
    if (!temp) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    strcpy(temp, &line[1]);  // Copy the line starting from the second character

    // ✅ Extract opcode (first token before space)
    char *command = strtok(temp, " ");
    if (!command) {
        report_error("Syntax Error: Missing opcode", line);
        free(temp);
        return 0;
    }

    // ✅ Extract operands (rest of the line after the first space)
    char *args = strtok(NULL, "\n"); // Get everything after the first space
    char *operands[3] = {NULL}; // Max 3 operands
    int operand_count = 0;

    if (args) {
        char *token = strtok(args, ","); // Split operands using commas
        while (token && operand_count < 3) {
            while (*token == ' ') token++; // Trim leading spaces
            operands[operand_count++] = token;
            token = strtok(NULL, ","); // Get next operand
        }
    }

    // Debug: Print extracted tokens
    printf("DEBUG: Parsed opcode: '%s'\n", command);
    for (int i = 0; i < operand_count; i++) {
        printf("  Operand %d: '%s'\n", i, operands[i]);
    }

    // ✅ Validate opcode
    if (!validate_opcode(command)) {
        report_error("Syntax Error: Invalid opcode", command);
        free(temp);
        return 0;
    }

    // ✅ Validate operand count based on opcode
    if (strcmp(command, "add") == 0 || strcmp(command, "sub") == 0 ||
        strcmp(command, "mul") == 0 || strcmp(command, "div") == 0) {
        if (operand_count != 3) {
            report_error("Syntax Error: Incorrect operand count for arithmetic instruction", line);
            free(temp);
            return 0;
        }
        if (!validate_register(operands[0]) || !validate_register(operands[1]) || !validate_register(operands[2])) {
            report_error("Syntax Error: Invalid register in arithmetic instruction", line);
            free(temp);
            return 0;
        }
    }

    // Immediate Arithmetic Instructions: Expect 1 register + 1 literal
    else if (strcmp(command, "addi") == 0 || strcmp(command, "subi") == 0) {
        if (operand_count != 2) {
            report_error("Syntax Error: Incorrect operand count for immediate arithmetic instruction", line);
            free(temp);
            return 0;
        }
        if (!validate_register(operands[0]) || !validate_literal(operands[1])) {
            report_error("Syntax Error: Invalid operand for immediate arithmetic instruction", line);
            free(temp);
            return 0;
        }
    }

    free(temp);
    return 1;  // ✅ Instruction is valid
}
*/

int validate_label_format(char *token)
{
    // A label must start with ':'
    if (token[0] != ':')
    {
        return 0; // Not a label
    }

    // Ensure label contains only valid characters (letters, numbers, underscores)
    for (int i = 1; token[i] != '\0'; i++)
    {
        if (!isalnum(token[i]) && token[i] != '_') // Allow letters, numbers, and '_'
        {
            return 0; // Invalid character in label
        }
    }

    return 1; // Valid label format
}

int validate_register(char *token)
{
    // Check if it starts with 'r'
    if (token[0] != 'r')
    {
        return 0; // Not a register
    }

    // Extract register number
    int reg_num = atoi(token + 1); // Convert "rX" to integer X

    // Ensure register is in valid range (r0 - r31)
    if (reg_num < 0 || reg_num > 31)
    {
        return 0; // Invalid register
    }

    return 1; // Valid register
}
int validate_spacing(char *line)
{
    trim_trailing_whitespace(line);

    // Extract tokens (keep commas!)
    char *tokens[5];
    int token_count = 0;
    char *token = strtok(line, " "); // Only split on spaces
    while (token && token_count < 5)
    {
        tokens[token_count++] = token;
        token = strtok(NULL, " ");
    }

    // Ensure opcode is followed by exactly one space
    if (line[strlen(tokens[0])] != ' ')
    {
        report_error("Syntax Error: Opcode must be followed by exactly one space", line);
        return 0;
    }

    // Ensure operands are properly spaced with ", "
    for (int i = 1; i < token_count - 1; i++)
    {
        char *operand = tokens[i];

        // ✅ FIX: Check if the **last character** of operand[i] is ','
        if (operand[strlen(operand) - 1] != ',')
        {
            report_error("Syntax Error: Incorrect spacing around operands", line);
            return 0;
        }
    }

    return 1; // Spacing is valid
}

// Function to check if a literal is valid (numeric and within range)
int validate_literal(char *token)
{
    int i = (token[0] == '-') ? 1 : 0; // Allow negative numbers

    while (token[i] != '\0')
    {
        if (!isdigit(token[i]))
            return 0; // Invalid character found
        i++;
    }

    return 1; // Valid numeric literal
}

// Function to print error messages and stop execution
void report_error(const char *message, const char *line)
{
    printf("%s: %s\n", message, line);
}