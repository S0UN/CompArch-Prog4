#ifndef SYNTAX_VERIFIER_H
#define SYNTAX_VERIFIER_H

#include "arraylist.h"
#include "label_table.h"
#include "line.h"

int process_file(const char *input_filename, ArrayList *lines, LabelTable **labels);
void remove_comments(char *line);
void trim_trailing_whitespace(char *line);
int validate_label_format(char *token);
int validate_opcode(char *token);
int validate_macro(char *token);
int validate_register(char *token);
int validate_literal(char *token);
void report_error(const char *message, const char *line);

// NEW: Macro expansion function
void expand_macro(Line *line_entry, ArrayList *instruction_list, int *address, int in_code_section);

// NEW: Second pass label resolution function
void resolve_labels(ArrayList *instructions, LabelTable *labels);

// NEW: Write final output file function
void write_output_file(const char *output_filename, ArrayList *instructions);

#endif
