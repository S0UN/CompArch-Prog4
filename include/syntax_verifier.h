#ifndef SYNTAX_VERIFIER_H
#define SYNTAX_VERIFIER_H

#include <stdbool.h> // Add this line

#include "arraylist.h"
#include "label_table.h"
#include "line.h"

/* Processes the input file, populating the ArrayList of instructions/data
   and the LabelTable for label definitions.
*/
int process_file(const char *input_filename, ArrayList *lines, LabelTable **labels);

/* Validates the syntax of a non-macro instruction using direct if/else logic.
   (This function is called from within process_file for non-macro lines.)
*/
bool validate_instruction(const char *line);
void trim_whitespace(char *line);
void remove_comments(char *line) ;
bool isValidRegister(const char* reg) ;
bool isValidImmediate(const char *imm, bool allow_negative, int bit_size);
bool isMemoryOperand(const char* operand);
void error(const char *message);


bool isLabelSyntax(const char* operand);

/* Expands macro instructions (clr, push, pop, out, in, ld) into multiple instructions.
*/
void expand_macro(Line *line_entry, ArrayList *instruction_list, int *address);

/* Resolves label operands by replacing them with their hexadecimal addresses.
*/
void resolve_labels(ArrayList *instructions, LabelTable *labels);

/* Writes the final assembly output to a file with section directives and tab indents.
*/
void write_output_file(const char *output_filename, ArrayList *instructions);

int process_file(const char *input_filename, ArrayList *lines, LabelTable **labels);


#endif
