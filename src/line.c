#include "line.h"
#include <stdio.h>

void print_line(Line *line) {
    if (!line) return;
    printf("PC: 0x%04X | Type: %c | Opcode: %s | ", 
           line->program_counter, line->type, line->opcode);
    if (line->type == 'I') {
        if (strcmp(line->opcode, "xor") == 0) {
            printf("%s, %s, %s", line->registers[0], line->registers[1], line->registers[2]);
        } else if (strcmp(line->opcode, "subi") == 0 || strcmp(line->opcode, "addi") == 0) {
            printf("%s, %s, %d", line->registers[0], line->registers[1], line->literal);
        } else if (strcmp(line->opcode, "st") == 0 || strcmp(line->opcode, "ld") == 0) {
            printf("%s, %s, %d", line->registers[0], line->registers[1], line->literal);
        } else if (strcmp(line->opcode, "trap") == 0) {
            printf("%d", line->literal);
        } else if (strcmp(line->opcode, "br") == 0) {
            if (line->label[0] != '\0')
                printf("%s", line->label);
            else
                printf("%s", line->registers[0]);
        } else {
            // Default: print the opcode and any operands stored.
            printf("%s", line->opcode);
        }
    } else if (line->type == 'D') {
        printf("%d", line->literal);
    }
    printf("\n");
}
