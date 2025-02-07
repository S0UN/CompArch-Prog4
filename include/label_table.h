#ifndef LABEL_TABLE_H
#define LABEL_TABLE_H

#include "uthash.h"

typedef struct {
    char label[20];       // Label name (e.g., "L1")
    int address;          // Memory address (e.g., 0x100C)
    int in_code_section;  // 1 if in .code section, 0 if in .data section
    UT_hash_handle hh;    // Hash table handle
} LabelTable;

void store_label(LabelTable **labels, const char *label, int address, int in_code_section);
int get_label_address(LabelTable *labels, const char *label);
int is_label_in_code(LabelTable *labels, const char *label);
void free_label_table(LabelTable *labels);

#endif
