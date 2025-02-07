#include "line.h"
#include <stdio.h>

void print_line(Line *line) {
    if (!line) return;
    printf("PC: 0x%X | Type: %c | Size: %d | Opcode: %s | ", 
           line->program_counter, line->type, line->size, line->opcode);
    if (line->type == 'I') {
        printf("Operands: ");
        for (int i = 0; i < line->operand_count; i++) {
            printf("%s ", line->operands[i]);
        }
        if (line->literal || (line->literal == 0)) { // Even a literal of 0 may be valid
            printf("| Literal: %d ", line->literal);
        }
        if (line->label[0] != '\0') {
            printf("| Label: %s", line->label);
        }
    } else if (line->type == 'D') {
        printf("Data: %d", line->literal);
    }
    printf("\n");
}
