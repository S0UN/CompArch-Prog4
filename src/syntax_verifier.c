#include "syntax_verifier.h"
#include "arraylist.h"
#include "label_table.h"
#include "line.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// --- Helper functions ---

// Remove both leading and trailing whitespace.
void trim_whitespace(char *line) {
    int start = 0;
    while(line[start] && isspace((unsigned char)line[start])) start++;
    if (start > 0) {
        memmove(line, line + start, strlen(line + start) + 1);
    }
    int len = strlen(line);
    while (len > 0 && isspace((unsigned char)line[len - 1]))
        line[--len] = '\0';
}

void remove_comments(char *line) {
    char *comment_pos = strchr(line, ';');
    if (comment_pos)
        *comment_pos = '\0';
    int len = strlen(line);
    while(len > 0 && isspace((unsigned char)line[len-1]))
        line[--len] = '\0';
}

void trim_trailing_whitespace(char *line) {
    int len = strlen(line);
    while(len > 0 && isspace((unsigned char)line[len-1]))
        line[--len] = '\0';
}

int validate_label_format(char *token) {
    if (token[0] != ':') return 0;
    for (int i = 1; token[i] != '\0'; i++) {
        if (!isalnum((unsigned char)token[i]) && token[i] != '_')
            return 0;
    }
    return 1;
}

int validate_opcode(char *token) {
    for (int i = 0; token[i] != '\0'; i++) {
        if (!isalpha((unsigned char)token[i]))
            return 0;
    }
    return 1;
}

int validate_macro(char *token) {
    // Extended list to include "in", "out", and "ld"
    const char *valid_macros[] = {"in", "out", "clr", "ld", "push", "pop", "halt", "call", "return", NULL};
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
        if (!isdigit((unsigned char)token[i]))
            return 0;
    }
    return 1;
}

void report_error(const char *message, const char *line) {
    printf("%s: %s\n", message, line);
}

// --- NEW: Helper to detect memory operands ---
// Returns 1 if operand matches pattern (rx)(literal), 0 otherwise.
int is_memory_operand(const char *operand) {
    char reg[10];
    int lit;
    if (sscanf(operand, "(%[^)])(%d)", reg, &lit) == 2)
        return 1;
    return 0;
}

// --- Processing and tokenizing the input file ---
// (Tokens are assumed to be separated by spaces and/or tabs.)
int process_file(const char *input_filename, ArrayList *lines, LabelTable **labels) {
    FILE *fp = fopen(input_filename, "r");
    if (!fp) {
        printf("Error: Could not open input file %s\n", input_filename);
        return 1;
    }
    
    char buffer[256];
    int address = 0x1000;         // Start address for code
    int in_code_section = 1;      // 1 = .code; 0 = .data
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        remove_comments(buffer);
        trim_whitespace(buffer);
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
        
        if (buffer[0] == ':') {
            if (!validate_label_format(buffer)) {
                report_error("Syntax Error: Invalid label format", buffer);
                fclose(fp);
                return 1;
            }
            strncpy(line_entry.label, buffer + 1, sizeof(line_entry.label)-1);
            line_entry.is_label = 1;
            store_label(labels, line_entry.label, address, in_code_section);
            continue;
        }
        
        char *token = strtok(buffer, " \t");
        if (!token) {
            report_error("Syntax Error: Empty instruction", buffer);
            fclose(fp);
            return 1;
        }
        
        // For macros, do expansion as before.
        if (validate_macro(token)) {
            strncpy(line_entry.opcode, token, sizeof(line_entry.opcode)-1);
            int op_count = 0;
            while ((token = strtok(NULL, " \t")) != NULL && op_count < 4) {
                strncpy(line_entry.operands[op_count], token, sizeof(line_entry.operands[op_count])-1);
                op_count++;
            }
            line_entry.operand_count = op_count;
            // For single–instruction tests, you may choose to expand or not.
            // Here we call expand_macro as before.
            expand_macro(&line_entry, lines, &address, in_code_section);
            continue;
        }
        
        // Otherwise, process as a normal instruction (or data literal).
        if (in_code_section) {
            strncpy(line_entry.opcode, token, sizeof(line_entry.opcode)-1);
            int op_count = 0;
            while ((token = strtok(NULL, " \t,")) != NULL && op_count < 4) {
                // If token is a memory operand, leave it intact.
                if (is_memory_operand(token)) {
                    strncpy(line_entry.operands[op_count], token, sizeof(line_entry.operands[op_count])-1);
                }
                else if (token[0] == 'r' && validate_register(token)) {
                    strncpy(line_entry.registers[op_count], token, sizeof(line_entry.registers[op_count])-1);
                    strncpy(line_entry.operands[op_count], token, sizeof(line_entry.operands[op_count])-1);
                }
                else if (isdigit(token[0]) || token[0]=='-') {
                    line_entry.literal = atoi(token);
                    strncpy(line_entry.operands[op_count], token, sizeof(line_entry.operands[op_count])-1);
                }
                else if (token[0] == ':') {
                    strncpy(line_entry.label, token, sizeof(line_entry.label)-1);
                    strncpy(line_entry.operands[op_count], token, sizeof(line_entry.operands[op_count])-1);
                }
                else {
                    strncpy(line_entry.operands[op_count], token, sizeof(line_entry.operands[op_count])-1);
                }
                op_count++;
            }
            line_entry.operand_count = op_count;
        } else {
            if (validate_literal(token)) {
                line_entry.literal = atoi(token);
            } else {
                report_error("Syntax Error in data literal", token);
                fclose(fp);
                return 1;
            }
        }
        
        add_to_arraylist(lines, line_entry);
        address += in_code_section ? 4 : 8;
    }
    
    fclose(fp);
    return 0;
}

// --- Macro Expansion ---
// I did not change the expansion for most macros except for the ones tested below.
// For call and return, I removed the subtraction adjustment in resolve_labels.
void expand_macro(Line *line_entry, ArrayList *instruction_list, int *address, int in_code_section) {
    Line new_entry;
    memset(&new_entry, 0, sizeof(Line));
    new_entry.type = 'I';
    new_entry.from_call = 0;
    
    // --- in rd, rs -> priv rd, rs, r0, 0x3 ---
    if (strcmp(line_entry->opcode, "in") == 0) {
        if (!validate_register(line_entry->operands[0]) || !validate_register(line_entry->operands[1])) {
            report_error("Syntax Error: Invalid register operand for in", line_entry->operands[0]);
            return;
        }
        strcpy(new_entry.opcode, "priv");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        strncpy(new_entry.registers[1], line_entry->operands[1], sizeof(new_entry.registers[1])-1);
        strcpy(new_entry.registers[2], "r0");
        new_entry.literal = 0x3;
        new_entry.operand_count = 0;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    
    // --- out rd, rs -> priv rd, rs, r0, 0x4 ---
    if (strcmp(line_entry->opcode, "out") == 0) {
        if (!validate_register(line_entry->operands[0]) || !validate_register(line_entry->operands[1])) {
            report_error("Syntax Error: Invalid register operand for out", line_entry->operands[0]);
            return;
        }
        strcpy(new_entry.opcode, "priv");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        strncpy(new_entry.registers[1], line_entry->operands[1], sizeof(new_entry.registers[1])-1);
        strcpy(new_entry.registers[2], "r0");
        new_entry.literal = 0x4;
        new_entry.operand_count = 0;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    
    // --- ld rX, literal -> load immediate into rX ---
    if (strcmp(line_entry->opcode, "ld") == 0) {
        if (!validate_register(line_entry->operands[0])) {
            report_error("Syntax Error: Invalid register operand for ld", line_entry->operands[0]);
            return;
        }
        if (!validate_literal(line_entry->operands[1])) {
            report_error("ld macro: only immediate numbers are supported", line_entry->operands[1]);
            return;
        }
        long long value = atoll(line_entry->operands[1]);
        // Clear register: xor rX, rX, rX
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "xor");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        strncpy(new_entry.registers[1], line_entry->operands[0], sizeof(new_entry.registers[1])-1);
        strncpy(new_entry.registers[2], line_entry->operands[0], sizeof(new_entry.registers[2])-1);
        new_entry.operand_count = 3;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "addi");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        strncpy(new_entry.registers[1], line_entry->operands[0], sizeof(new_entry.registers[1])-1);
        new_entry.literal = (value >> 52) & 0xFFF;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        
        for (int shift = 40; shift >= 4; shift -= 12) {
            memset(&new_entry, 0, sizeof(Line));
            new_entry.type = 'I';
            strcpy(new_entry.opcode, "shftli");
            strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
            new_entry.operand_count = 1;
            new_entry.program_counter = (*address);
            add_to_arraylist(instruction_list, new_entry);
            (*address) += 4;
            
            memset(&new_entry, 0, sizeof(Line));
            new_entry.type = 'I';
            strcpy(new_entry.opcode, "addi");
            strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
            strncpy(new_entry.registers[1], line_entry->operands[0], sizeof(new_entry.registers[1])-1);
            new_entry.literal = (value >> shift) & 0xFFF;
            new_entry.operand_count = 2;
            new_entry.program_counter = (*address);
            add_to_arraylist(instruction_list, new_entry);
            (*address) += 4;
        }
        
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "shftli");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        new_entry.operand_count = 1;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "addi");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        strncpy(new_entry.registers[1], line_entry->operands[0], sizeof(new_entry.registers[1])-1);
        new_entry.literal = value & 0xF;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    
    // --- clr rX -> xor rX, rX, rX ---
    if (strcmp(line_entry->opcode, "clr") == 0) {
        strcpy(new_entry.opcode, "xor");
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
        strcpy(new_entry.opcode, "subi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        
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
        strcpy(new_entry.opcode, "ld");
        strncpy(new_entry.registers[0], line_entry->operands[0], sizeof(new_entry.registers[0])-1);
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        
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
    
    // --- call :label -> subi r30, r30, 8; st r31, r30, 0; br <resolved label> ---
    if (strcmp(line_entry->opcode, "call") == 0) {
        strcpy(new_entry.opcode, "subi");
        strcpy(new_entry.registers[0], "r30");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 8;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        
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
        
        memset(&new_entry, 0, sizeof(Line));
        new_entry.type = 'I';
        strcpy(new_entry.opcode, "br");
        // For single–instruction tests, do not adjust the branch operand.
        strncpy(new_entry.label, line_entry->operands[0], sizeof(new_entry.label)-1);
        new_entry.operand_count = 0;
        new_entry.from_call = 0; // Remove adjustment flag
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        return;
    }
    
    // --- return -> ld r31, r30, 0; addi r30, r30, 8; br r31 ---
    if (strcmp(line_entry->opcode, "return") == 0) {
        strcpy(new_entry.opcode, "ld");
        strcpy(new_entry.registers[0], "r31");
        strcpy(new_entry.registers[1], "r30");
        new_entry.literal = 0;
        new_entry.operand_count = 2;
        new_entry.program_counter = (*address);
        add_to_arraylist(instruction_list, new_entry);
        (*address) += 4;
        
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
// For instructions with a label operand (starting with ':'), look it up and replace it.
// (Note: For single–instruction tests, no branch adjustment is done.)
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
                snprintf(line->label, sizeof(line->label), "0x%X", addr);
            }
        }
    }
}

// --- Write final output file ---
// Instead of printing addresses, output proper assembly with section directives and a tab indent.
void write_output_file(const char *output_filename, ArrayList *instructions) {
    FILE *fp = fopen(output_filename, "w");
    if (!fp) {
        perror("Error opening output file");
        return;
    }
    
    char current_section = '\0';
    for (int i = 0; i < instructions->size; i++) {
        Line *line = &instructions->lines[i];
        if (line->type != current_section) {
            if (line->type == 'I')
                fprintf(fp, ".code\n");
            else if (line->type == 'D')
                fprintf(fp, ".data\n");
            current_section = line->type;
        }
        fprintf(fp, "\t");
        // Special formatting for addi/subi: if only 2 operands, print as "addi rd, literal"
        if ((strcmp(line->opcode, "addi") == 0 || strcmp(line->opcode, "subi") == 0) && line->operand_count == 2) {
            fprintf(fp, "%s %s, %d", line->opcode, line->registers[0], line->literal);
        }
        // Special formatting for mov: if opcode is "mov" and exactly 2 operands, print them as is.
        else if (strcmp(line->opcode, "mov") == 0 && line->operand_count == 2) {
            fprintf(fp, "mov %s, %s", line->operands[0], line->operands[1]);
        }
        else if (strcmp(line->opcode, "xor") == 0) {
            fprintf(fp, "xor %s, %s, %s", line->registers[0], line->registers[1], line->registers[2]);
        }
        else if (strcmp(line->opcode, "st") == 0 || strcmp(line->opcode, "ld") == 0) {
            fprintf(fp, "%s %s, %s, %d", line->opcode, line->registers[0], line->registers[1], line->literal);
        }
        else if (strcmp(line->opcode, "trap") == 0) {
            fprintf(fp, "trap %d", line->literal);
        }
        else if (strcmp(line->opcode, "br") == 0) {
            if (line->label[0] != '\0')
                fprintf(fp, "br %s", line->label);
            else
                fprintf(fp, "br %s", line->registers[0]);
        }
        else {
            fprintf(fp, "%s", line->opcode);
            for (int j = 0; j < line->operand_count; j++) {
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
