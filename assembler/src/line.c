#include "line.h"

// Print function for debugging
void print_line(Line *line) {
    if (!line) return;

    printf("PC: 0x%X | Type: %c | Size: %d | Opcode: %s | ", 
           line->program_counter, line->type, line->size, line->opcode);

    if (line->type == 'I') {
        printf("Registers: %s, %s, %s | ", 
               line->registers[0], line->registers[1], line->registers[2]);

        if (line->literal != 0) {
            printf("Literal: %d | ", line->literal);
        }
        if (strlen(line->label) > 0) {
            printf("Label: %s", line->label);
        }
    } 
    else if (line->type == 'D') {
        printf("Data: %d", line->literal);
    }

    printf("\n");
}
