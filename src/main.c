#include <stdio.h>
#include <stdlib.h>
#include "syntax_verifier.h"
#include "arraylist.h"
#include "label_table.h"
#include "line.h"
int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    ArrayList instructions;
    initialize_arraylist(&instructions);

    LabelTable *labels = NULL; // initialize label table (using uthash)

    if (process_file(argv[1], &instructions, &labels) != 0) {
        printf("Error processing file.\n");
        free_arraylist(&instructions);
        free_label_table(labels);
        return 1;
    }

    // IMPORTANT: Resolve all label operands before writing output.
    resolve_labels(&instructions, labels);

    write_output_file(argv[2], &instructions);

    free_arraylist(&instructions);
    free_label_table(labels);

    return 0;
}
