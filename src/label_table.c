#include "label_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void store_label(LabelTable **labels, const char *label, int address, int in_code_section) {
    LabelTable *entry;
    HASH_FIND_STR(*labels, label, entry);
    if (entry != NULL) {
        printf("Error: Duplicate label definition '%s'\n", label);
        return;
    }
    entry = (LabelTable *)malloc(sizeof(LabelTable));
    if (!entry) {
        perror("Memory allocation error for label");
        exit(EXIT_FAILURE);
    }
    strcpy(entry->label, label);
    entry->address = address;
    entry->in_code_section = in_code_section;  
    HASH_ADD_STR(*labels, label, entry);
}

// Function to initialize and return an empty label table
LabelTable *create_label_table() {
    return NULL;  // Since we're using uthash, the table starts as NULL
}
int get_label_address(LabelTable *labels, const char *label) {
    LabelTable *entry;
    HASH_FIND_STR(labels, label, entry);
    return (entry) ? entry->address : -1;
}

int is_label_in_code(LabelTable *labels, const char *label) {
    LabelTable *entry;
    HASH_FIND_STR(labels, label, entry);
    return (entry) ? entry->in_code_section : -1;
}

void free_label_table(LabelTable *labels) {
    LabelTable *current, *tmp;
    HASH_ITER(hh, labels, current, tmp) {
        HASH_DEL(labels, current);
        free(current);
    }
}
