#include <stdio.h>
#include <stdlib.h>
#include "syntax_verifier.h"
#include "arraylist.h"
#include "label_table.h"
#include "line.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input_file.tk> <output_file.tk>\n", argv[0]);
        return 1;
    }
    
    const char *input_filename = argv[1];
    const char *output_filename = argv[2];
    
    // Initialize storage for instructions and data.
    ArrayList instructions;
    initialize_arraylist(&instructions);
    
    // Initialize label table.
    LabelTable *labels = NULL;
    
    // FIRST PASS: Process the file.
    if (process_file(input_filename, &instructions, &labels) != 0) {
        printf("Error processing file.\n");
        free_arraylist(&instructions);
        free_label_table(labels);
        return 1;
    }
    
    // SECOND PASS: Resolve label references in the instructions.
    resolve_labels(&instructions, labels);
    
    // Write the final output to a .tk file.
    write_output_file(output_filename, &instructions, labels);
    
    // (Optional) Print out the final instructions for debugging.
    printf("\n=== Final Assembler Output ===\n");
    for (int i = 0; i < instructions.size; i++) {
        print_line(&instructions.lines[i]);
    }
    
    // Clean up allocated memory.
    free_arraylist(&instructions);
    free_label_table(labels);
    
    return 0;
}
