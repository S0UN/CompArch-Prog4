#ifndef LINE_H
#define LINE_H
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <strings.h>
#include <stdio.h>

// Structure to store an instruction, label, or data entry
typedef struct {
    char type;             // 'I' = instruction, 'D' = data
    char opcode[10];       // Opcode (e.g., "add", "ld")
    char registers[3][20];  // Up to 3 registers (e.g., "r1", "r2", "r3")
    uint64_t literal;           // Literal value (if any)
    char label[20];        // Label operand (if any, e.g., ":L1")
    int program_counter;   // Memory address for the instruction or data
    int size;              // 4 bytes for instructions, 8 bytes for data items
    int operand_count;     // Number of operands from tokenization
    char operands[4][30];  // Operand strings
    int is_label;          // 1 if this line is only a label declaration
    int from_call;         // Flag for macro expansion (if needed)
} Line;

// Debug print function (for debugging purposes)
void print_line(Line *line);

#endif // LINE_H
