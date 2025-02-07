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

    char clean_label[20];
    strncpy(clean_label, label, sizeof(clean_label) - 1);
    clean_label[sizeof(clean_label) - 1] = '\0'; 

    strcpy(entry->label, clean_label);
    entry->address = address;
    entry->in_code_section = in_code_section;

    HASH_ADD_STR(*labels, label, entry);

    printf("DEBUG: Stored Label -> '%s' at address %d\n", entry->label, entry->address);
}



int get_label_address(LabelTable *labels, const char *label) {
    printf("DEBUG: Looking up label: '%s'\n", label); // <-- Print the label being searched

    LabelTable *entry;
    
    // Print all stored labels for debugging
    for (entry = labels; entry != NULL; entry = entry->hh.next) {
        printf("DEBUG: Stored Label -> '%s' at address %d\n", entry->label, entry->address);
    }

    HASH_FIND_STR(labels, label, entry); // Look up the label

    if (entry) {
        printf("DEBUG: Label '%s' found at address %d\n", label, entry->address);
        return entry->address;
    } else {
        printf("ERROR: Label '%s' NOT FOUND!\n", label);
        return -1;
    }
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
