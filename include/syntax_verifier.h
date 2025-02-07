#ifndef SYNTAX_VERIFIER_H
#define SYNTAX_VERIFIER_H

#include "arraylist.h"
#include "label_table.h"
#include "line.h"

int process_file(const char *input_filename, ArrayList *lines, LabelTable **labels);
int validate_line_type(char *line);
int validate_label(char *line);
int validate_spacing(char *line);
int validate_instruction(char *line);
int validate_register(char *token);
int validate_literal(char *token);
void remove_comments(char *line);
void trim_trailing_whitespace(char *line);
void write_output_file(const char *output_filename, ArrayList *instructions, LabelTable *labels);
int validate_label_format(char *token);
int validate_opcode(char *token);
void expand_macro(Line *line_entry, ArrayList *instruction_list, int *address);
void report_error(const char *message, const char *line);
void tokenize_and_print(char *line_buffer);
int validate_memory_operand(char *token);
int validate_macro(char *token);

// New functions for second pass resolution
void resolve_labels(ArrayList *instructions, LabelTable *labels);

#endif
