#ifndef LINE_H
#define LINE_H

#include <stdio.h>
#include <string.h>

// Structure to store an instruction, label, or data entry
typedef struct {
    char type;             // 'I' = instruction, 'D' = data, 'L' = label
    char opcode[10];       // Opcode (e.g., "add", "ld"), empty for data
    char registers[3][5];  // Up to 3 registers (e.g., "r1", "r2", "r3")
    int literal;           // Literal value (used for both instructions & data)
    char label[20];        // Label reference (if applicable)
    int program_counter;   // Memory address of the instruction or literal
    int size;              // 4 bytes for instructions, 8 bytes for literals
    int operand_count;     // Number of operands
    char operands[4][10];  // Explicit operand storage
    int is_label;          // ✅ Fix: Added field to indicate if it's a label
} Line;

// Function declarations
void print_line(Line *line);  // Print function for debugging

#endif // LINE_H
