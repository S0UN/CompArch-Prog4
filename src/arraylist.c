#include "arraylist.h"
#include <stdio.h>
#include <string.h>

// Create a new ArrayList
void initialize_arraylist(ArrayList *arr) {
    arr->capacity = 10;
    arr->size = 0;
    arr->lines = (Line *)malloc(arr->capacity * sizeof(Line));
}

// Add an instruction or literal to the ArrayList
void add_to_arraylist(ArrayList *arr, Line entry) {
    if (arr->size >= arr->capacity) {
        arr->capacity *= 2;
        arr->lines = (Line *)realloc(arr->lines, arr->capacity * sizeof(Line));
    }
    arr->lines[arr->size++] = entry;
}

// Free the ArrayList
void free_arraylist(ArrayList *arr) {
    free(arr->lines);
    arr->size = 0;
    arr->capacity = 0;
}
