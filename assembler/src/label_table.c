#include "label_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Store a label and its corresponding memory address
void store_label(LabelTable **labels, const char *label, int address, int in_code_section) {
    LabelTable *entry;
    HASH_FIND_STR(*labels, label, entry);

    if (entry != NULL) {
        printf("Error: Duplicate label definition '%s'\n", label);
        return;
    }

    entry = (LabelTable *)malloc(sizeof(LabelTable));
    strcpy(entry->label, label);
    entry->address = address;
    entry->in_code_section = in_code_section;  // Store whether label is in .code or .data

    HASH_ADD_STR(*labels, label, entry);
}

// Retrieve the memory address for a given label
int get_label_address(LabelTable *labels, const char *label) {
    LabelTable *entry;
    HASH_FIND_STR(labels, label, entry);
    return (entry) ? entry->address : -1;
}

// Check if a label belongs to the .code section
int is_label_in_code(LabelTable *labels, const char *label) {
    LabelTable *entry;
    HASH_FIND_STR(labels, label, entry);
    return (entry) ? entry->in_code_section : -1; // Return -1 if label not found
}

// Free the label table
void free_label_table(LabelTable *labels) {
    LabelTable *current, *tmp;
    HASH_ITER(hh, labels, current, tmp) {
        HASH_DEL(labels, current);
        free(current);
    }
}
