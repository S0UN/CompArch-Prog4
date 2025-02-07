#include "syntax_verifier.h"
#include "arraylist.h"
#include "label_table.h"
#include "line.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// --- Helper functions ---

void remove_comments(char *line) {
    char *comment_pos = strchr(line, ';');
    if (comment_pos)
        *comment_pos = '\0';
    // Remove any trailing whitespace after comment removal
    int len = strlen(line);
    while(len > 0 && isspace(line[len-1]))
        line[--len] = '\0';
}

void trim_trailing_whitespace(char *line) {
    int len = strlen(line);
    while(len > 0 && isspace(line[len-1]))
        line[--len] = '\0';
}

int validate_label_format(char *token) {
    if (token[0] != ':') return 0;
    for (int i = 1; token[i] != '\0'; i++) {
        if (!isalnum(token[i]) && token[i] != '_')
            return 0;
    }
    return 1;
}

int validate_opcode(char *token) {
    // A simple check: allow letters only (could be extended)
    for (int i = 0; token[i] != '\0'; i++) {
        if (!isalpha(token[i]))
            return 0;
    }
    return 1;
}

int validate_macro(char *token) {
    const char *valid_macros[] = {"clr", "push", "pop", "halt", "call", "return", NULL};
    for (int i = 0; valid_macros[i] != NULL; i++) {
        if (strcmp(token, valid_macros[i]) == 0)
            return 1;
    }
    return 0;
}

int validate_register(char *token) {
    if (token[0] != 'r') return 0;
    int reg = atoi(token + 1);
    if (reg < 0 || reg > 31) return 0;
    return 1;
}

int validate_literal(char *token) {
    int i = (token[0]=='-') ? 1 : 0;
    for (; token[i] != '\0'; i++) {
        if (!isdigit(token[i]))
            return 0;
    }
    return 1;
}

void report_error(const char *message, const char *line) {
    printf("%s: %s\n", message, line);
}

// --- Processing and tokenizing the input file ---
// For simplicity we assume tokens are separated by spaces.
int process_file(const char *input_filename, ArrayList *lines, LabelTable **labels) {
    FILE *fp = fopen(input_filename, "r");
    if (!fp) {
        printf("Error: Could not open input file %s\n", input_filename);
        return 1;
    }
    
    char buffer[256];
    int address = 0x1000;         // Start of code
    int in_code_section = 1;      // 1 = .code, 0 = .data
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        remove_comments(buffer);
        trim_trailing_whitespace(buffer);
        if (strlen(buffer) == 0)
            continue;
        
        // Section directives
        if (strncmp(buffer, ".code", 5) == 0) {
            in_code_section = 1;
            continue;
        }
        if (strncmp(buffer, ".data", 5) == 0) {
            in_code_section = 0;
            continue;
        }
        
        Line line_entry;
        memset(&line_entry, 0, sizeof(Line));
        line_entry.program_counter = address;
        line_entry.type = in_code_section ? 'I' : 'D';
        line_entry.from_call = 0;
        
        // If a label line (starts with a colon)
        if (buffer[0] == ':') {
            if (!validate_label_format(buffer)) {
                report_error("Syntax Error: Invalid label format", buffer);
                fclose(fp);
                return 1;
            }
            // Store label (remove the leading ':')
            strncpy(line_entry.label, buffer+1, sizeof(line_entry.label)-1);
            line_entry.is_label = 1;
            store_label(labels, line_entry.label, address, in_code_section);
            // Do not add a label line to the output list.
            continue;
        }
        
        // Tokenize the line (split on spaces)
        char *token = strtok(buffer, " \t");
        if (!token) {
            report_error("Syntax Error: Empty instruction", buffer);
            fclose(fp);
            return 1;
        }
        
        // Check for macro first
        if (validate_macro(token)) {
            // Store the macro name in opcode and then tokens for operands.
            strncpy(line_entry.opcode, token, sizeof(line_entry.opcode)-1);
            int op_count = 0;
            while ((token = strtok(NULL, " \t")) != NULL && op_count < 4) {
                strncpy(line_entry.operands[op_count], token, sizeof(line_entry.operands[op_count])-1);
                op_count++;
            }
            line_entry.operand_count = op_count;
            // Expand the macro (this function will add one or more instructions to our list
            // and update the address accordingly)
            expand_macro(&line_entry, lines, &address, in_code_section);
            continue;
        }
        
        // Otherwise, assume it’s a normal instruction or a data literal.
        // If in code section, the first token is the opcode.
        if (in_code_section) {
            strncpy(line_entry.opcode, token, sizeof(line_entry.opcode)-1);
            int op_count = 0;
            while ((token = strtok(NULL, " \t,")) != NULL && op_count < 4) {
                strncpy(line_entry.operands[op_count], token, sizeof(line_entry.operands[op_count])-1);
                // If token is a register, store in registers array
                if (token[0]=='r' && validate_register(token)) {
                    strncpy(line_entry.registers[op_count], token, sizeof(line_entry.registers[op_count])-1);
                }
                // If token is numeric, store as literal.
                else if (isdigit(token[0]) || token[0]=='-') {
                    line_entry.literal = atoi(token);
                }
                // If token is a label operand (starts with ':')
                else if (token[0]==':') {
                    strncpy(line_entry.label, token, sizeof(line_entry.label)-1);
                }
                op_count++;
            }
            line_entry.operand_count = op_count;
        } else { 
            // In data section, the line is expected to be a literal.
            if (validate_literal(token)) {
                line_entry.literal = atoi(token);
            } else {
                report_error("Syntax Error in data literal", token);
                fclose(fp);
                return 1;
            }
        }
        
        // Add this line to the instruction list.
        add_to_arraylist(lines, line_entry);
        
        // Increment address: 4 bytes for code, 8 bytes for data.
        address += in_code_section ? 4 : 8;
    }
    
    fclose(fp);
    return 0;
}

// --- Macro Expansion ---
// The function below expands known macros into one or more instructions.
// Note that it uses the current section (in_code_section) to decide on the instruction size (always 4 in code).
void expand_macro(Line *line_entry, ArrayList *instruction_list, int *address, int in_code_section) {
    Line new_entry;
    memset(&new_entry, 0, sizeof(Line));
    new_entry.type = 'I';
    new_entry.from_call = 0;
    
    // --- clr rX -> xor rX, rX, rX ---
    if (strcmp(line_entry->opcode, "clr") == 0) {
        strcpy(new_entry.opcode, "xor");
        // The operand is in line_entry->operands[0]
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        strncpy(new_entry.registers[1], line_entry->operands[0], sizeof(new_entry.registers[1])-1);
        strncpy(new_entry.registers[2], line_entry->operands[0], sizeof(new_entry.registers[2])-1);
        new_entry.operand_count = 3;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    
    // --- push rX -> subi r30, r30, 8; st rX, r30, 0 ---
    if (strcmp(line_entry->opcode, "push") == 0) {
        // First: subi r30, r30, 8
        strcpy(new_entry.opcode, "subi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        // Second: st rX, r30, 0
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "st");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    
    // --- pop rX -> ld rX, r30, 0; addi r30, r30, 8 ---
    if (strcmp(line_entry->opcode, "pop") == 0) {
        // First: ld rX, r30, 0
        strcpy(new_entry.opcode, "ld");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        // Second: addi r30, r30, 8
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "addi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    
    // --- halt -> trap 0 ---
    if (strcmp(line_entry->opcode, "halt") == 0) {
        strcpy(new_entry.opcode, "trap");
        new_entry.literal = 0;
        new_entry.operand_count = 1;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    
    // --- call :label -> subi r30, r30, 8; st r31, r30, 0; br :label ---
    if (strcmp(line_entry->opcode, "call") == 0) {
        // First: subi r30, r30, 8
        strcpy(new_entry.opcode, "subi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        // Second: st r31, r30, 0
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "st");
        strcpy(new_entry.registers[0], "r31");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        // Third: br <label>
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "br");
        // Save the label operand (for example, ":func")
        strncpy(new_entry.label, line_entry->operands[0], sizeof(new_entry.label)-1);
        new_entry.operand_count = 0;
        new_entry.from_call = 1;  // Mark that this branch came from a call macro
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    
    // --- return -> ld r31, r30, 0; addi r30, r30, 8; br r31 ---
    if (strcmp(line_entry->opcode, "return") == 0) {
        // First: ld r31, r30, 0
        strcpy(new_entry.opcode, "ld");
        strcpy(new_entry.registers[0], "r31");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        // Second: addi r30, r30, 8
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "addi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        // Third: br r31
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "br");
        strcpy(new_entry.registers[0], "r31");
        new_entry.operand_count = 1;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
}

// --- Second Pass: Resolve label operands ---
// For every instruction that has a label operand (starting with ':'),
// look up the label in the label table and replace it with its hexadecimal address.
// For branch instructions generated by a call macro (from_call==1), subtract 8 from the resolved address.
void resolve_labels(ArrayList *instructions, LabelTable *labels) {
    for (int i = 0; i < instructions->size; i++) {
        Line *line = &instructions->lines[i];
        if (line->label[0] == ':') {
            char label_name[20];
            strcpy(label_name, line->label + 1);
            int addr = get_label_address(labels, label_name);
            if (addr == -1) {
                fprintf(stderr, "Error: Undefined label %s\n", line->label);
            } else {
                // If this branch came from a call macro, adjust the address by subtracting 8.
                if (line->from_call)
                    addr -= 8;
                snprintf(line->label, sizeof(line->label), "0x%X", addr);
            }
        }
    }
}

// --- Write final output file ---
// Each line is printed with its PC address (in hex) followed by the instruction or data literal.
// In this output, we do not reinsert section directives; the entire output is a list of addresses.
void write_output_file(const char *output_filename, ArrayList *instructions) {
    FILE *fp = fopen(output_filename, "w");
    if (!fp) {
        perror("Error opening output file");
        return;
    }
    
    for (int i = 0; i < instructions->size; i++) {
        Line *line = &instructions->lines[i];
        // Print the address
        fprintf(fp, "0x%04X   ", line->program_counter);
        // Print the instruction or data in the proper format.
        if (line->type == 'I') {
            if (strcmp(line->opcode, "xor") == 0) {
                fprintf(fp, "%s %s, %s, %s", line->opcode,
                        line->registers[0], line->registers[1], line->registers[2]);
            } else if (strcmp(line->opcode, "subi") == 0 || strcmp(line->opcode, "addi") == 0) {
                fprintf(fp, "%s %s, %s, %d", line->opcode,
                        line->registers[0], line->registers[1], line->literal);
            } else if (strcmp(line->opcode, "st") == 0 || strcmp(line->opcode, "ld") == 0) {
                fprintf(fp, "%s %s, %s, %d", line->opcode,
                        line->registers[0], line->registers[1], line->literal);
            } else if (strcmp(line->opcode, "trap") == 0) {
                fprintf(fp, "%s %d", line->opcode, line->literal);
            } else if (strcmp(line->opcode, "br") == 0) {
                if (line->label[0] != '\0')
                    fprintf(fp, "%s %s", line->opcode, line->label);
                else
                    fprintf(fp, "%s %s", line->opcode, line->registers[0]);
            } else {
                fprintf(fp, "%s", line->opcode);
            }
        } else if (line->type == 'D') {
            fprintf(fp, "%d", line->literal);
        }
        fprintf(fp, "\n");
    }
    
    fclose(fp);
}
