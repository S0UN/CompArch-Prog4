#ifndef ARRAYLIST_H
#define ARRAYLIST_H

#include "line.h"
#include <stdlib.h>

typedef struct {
    Line *lines;    // Array of instructions & data items
    int size;       // Number of elements stored
    int capacity;   // Total allocated space
} ArrayList;

void initialize_arraylist(ArrayList *arr);
void add_to_arraylist(ArrayList *arr, Line entry);
void free_arraylist(ArrayList *arr);

#endif
