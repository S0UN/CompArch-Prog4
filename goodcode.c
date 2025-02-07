#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <strings.h>  

#define MAXLINE 1024
#define MAXLABELS 1000
#define MAXMACROS 100
#define MEMORYSIZE 524288  
#define START 0x1000

void error(char *message) {
    fprintf(stderr, "Error: %s\n", message);
    exit(1);
}

char* trim(char* str) {
    // Trim leading whitespace
    while (isspace((unsigned char)*str)) str++;
    return str; // Return the trimmed string
}


typedef struct {
    char name[MAXLINE];
    int address;
} Label;

typedef struct {
    Label* items;
    int size;
    int capacity;
} LabelArray;


LabelArray* createLabelArray(int initial_capacity) {
    LabelArray* array = malloc(sizeof(LabelArray));
    if (!array){
        error("Memory allocation failed");
    }
    array->items = malloc(sizeof(Label) * initial_capacity);

    if (!array->items){
        error("Memory allocation failed");
    }
    array->size = 0;
    array->capacity = initial_capacity;
    return array;
}

void newLabel(LabelArray* array, char* name, int address) {
    if (array->size >= array->capacity) {
        array->capacity *= 2;
        Label* new_items = realloc(array->items, sizeof(Label) * array->capacity);
        if (!new_items) {
            error("Memory reallocation failed");
        }
        array->items = new_items;
    }
    strcpy(array->items[array->size].name, name);
    array->items[array->size].address = address;
    array->size++;
}

int findLabel(LabelArray* array, char* name) {
    for (int i = 0; i < array->size; i++) {
        if (strcmp(array->items[i].name, name) == 0) {
            return array->items[i].address;
        }
    }
    return -1;
}

void freeLabels(LabelArray* array) {
    free(array->items);
    free(array);
}

// Macro structures and operations
typedef struct {
    char name[MAXLINE];
    char expansion[MAXLINE];
} Macro;

typedef struct {
    Macro* items;
    int size;
    int capacity;
} MacroArray;

MacroArray* createMacroArray(int initial_capacity) {
    MacroArray* array = malloc(sizeof(MacroArray));
    if (!array) error("Memory allocation failed");
    array->items = malloc(sizeof(Macro) * initial_capacity);
    if (!array->items) error("Memory allocation failed");
    array->size = 0;
    array->capacity = initial_capacity;
    return array;
}

void newMacro(MacroArray* array, char* name) {
    if (array->size >= array->capacity) {
        array->capacity *= 2;
        Macro* new_items = realloc(array->items, sizeof(Macro) * array->capacity);
        if (!new_items) error("Memory reallocation failed");
        array->items = new_items;
    }
    strcpy(array->items[array->size].name, name);
    array->size++;
}

Macro* findMacro(MacroArray* array, char* name) {
    for (int i = 0; i < array->size; i++) {
        if (strcmp(array->items[i].name, name) == 0) {
            return &array->items[i];
        }
    }
    return NULL;
}

void freeMacros(MacroArray* array) {
    free(array->items);
    free(array);
}

// Global variables needed by the assembler
unsigned char memory[MEMORYSIZE];
int currentAddress = START;
LabelArray* labels;
MacroArray* macros;

void addLabel(char *line, int address) {
    if (line[0] != ':') {
        error("Internal Error: Label definition must start with ':'");
    }
    
    char labelName[MAXLINE];
    int i = 0;
    char *extract = line + 1;  //skip colon
    
    while (*extract && !isspace(*extract)) {
        labelName[i++] = *extract++;
    }
    labelName[i] = '\0';
    
    newLabel(labels, labelName, address);
}

bool isLabelSyntax(const char* operand) {
    return operand[0] == ':';
}

int resolveLabel(char *label) {
    int address = findLabel(labels, label);
    if (address == -1) {
        char errorMessage[MAXLINE];
        snprintf(errorMessage, MAXLINE, "Undefined label: %s", label);
        error(errorMessage);
    }
    return address;
}

// Macro initialization and expansion
void setMacros(void) {
    newMacro(macros, "in");
    newMacro(macros, "out");
    newMacro(macros, "clr");
    newMacro(macros, "ld");
    newMacro(macros, "push");
    newMacro(macros, "pop");
    newMacro(macros, "halt");
}

typedef enum {
    CMD_UNKNOWN,
    CMD_MOV,
    CMD_ADD,
    CMD_ADDI,
    CMD_SUB,
    CMD_SUBI,
    CMD_MUL,
    CMD_DIV,
    CMD_AND,
    CMD_OR,
    CMD_XOR,
    CMD_NOT,
    CMD_SHL,
    CMD_SHLI,
    CMD_SHR,
    CMD_SHRI,
    CMD_BR,
    CMD_BRR,
    CMD_BEQ,
    CMD_BNE,
    CMD_BRNZ,
    CMD_BRGT,
    CMD_CALL,
    CMD_RET,
    CMD_PRIV,
    CMD_ADDF,
    CMD_SUBF,
    CMD_MULF,
    CMD_DIVF,
    // Macro commands
    MAC_IN,
    MAC_OUT,
    MAC_CLR,
    MAC_LD,
    MAC_PUSH,
    MAC_POP,
    MAC_HALT
} CommandType;

// Add these instruction format enums
typedef enum {
    FMT_RRR,     // rd, rs, rt
    FMT_RRL,     // rd, rs, literal
    FMT_RR,      // rd, rs
    FMT_RL,      // rd, literal
    FMT_R,       // rd
    FMT_L,       // literal
    FMT_NONE,    // no operands
    FMT_MEM_RRL, // rd, (rs)(literal)
    FMT_MEM_RLR  // (rd)(literal), rs
} InstructionFormat;

// Update the Command struct
typedef struct {
    const char* name;
    CommandType type;
    InstructionFormat format;
    const char* syntax;
    bool isMacro;
} Command;

// Update the command table with proper formats
static const Command COMMANDS[] = {
    // Regular instructions
    {"add",     CMD_ADD,    FMT_RRR,     "rd, rs, rt",         false},
    {"addi",    CMD_ADDI,   FMT_RL,      "rd, literal",        false},
    {"sub",     CMD_SUB,    FMT_RRR,     "rd, rs, rt",         false},
    {"subi",    CMD_SUBI,   FMT_RL,      "rd, literal",        false},
    {"mul",     CMD_MUL,    FMT_RRR,     "rd, rs, rt",         false},
    {"div",     CMD_DIV,    FMT_RRR,     "rd, rs, rt",         false},
    {"and",     CMD_AND,    FMT_RRR,     "rd, rs, rt",         false},
    {"or",      CMD_OR,     FMT_RRR,     "rd, rs, rt",         false},
    {"xor",     CMD_XOR,    FMT_RRR,     "rd, rs, rt",         false},
    {"not",     CMD_NOT,    FMT_RR,      "rd, rs",             false},
    {"shftr",  CMD_SHR,    FMT_RRR,     "rd, rs, rt",         false},
    {"shftri", CMD_SHRI,   FMT_RL,      "rd, literal",        false},
    {"shftl",  CMD_SHL,    FMT_RRR,     "rd, rs, rt",         false},
    {"shftli", CMD_SHLI,   FMT_RL,      "rd, literal",        false},
    {"br",      CMD_BR,     FMT_R,       "rd",                 false},
    {"brr",     CMD_BRR,    FMT_R,       "rd",                 false},
    {"brr",     CMD_BRR,    FMT_L,       "literal",            false},//dupe
    {"brnz",    CMD_BRNZ,   FMT_RR,      "rd, rs",             false},
    {"call",    CMD_CALL,   FMT_R,       "rd",                 false},
    {"return",  CMD_RET,    FMT_NONE,    "",                   false},
    {"brgt",    CMD_BRGT,   FMT_RRR,     "rd, rs, rt",         false},
    {"priv",    CMD_PRIV,   FMT_RRL,     "rd, rs, rt, literal",false},
    {"mov",     CMD_MOV,    FMT_MEM_RRL, "rd, (rs)(literal)",  false}, //dupes v 
    {"mov",     CMD_MOV,    FMT_RR,      "rd, rs",             false},
    {"mov",     CMD_MOV,    FMT_RL,      "rd, literal",        false},
    {"mov",     CMD_MOV,    FMT_MEM_RLR, "(rd)(literal), rs",  false},
    {"addf",    CMD_ADDF,   FMT_RRR,     "rd, rs, rt",         false},
    {"subf",    CMD_SUBF,   FMT_RRR,     "rd, rs, rt",         false},
    {"mulf",    CMD_MULF,   FMT_RRR,     "rd, rs, rt",         false},
    {"divf",    CMD_DIVF,   FMT_RRR,     "rd, rs, rt",         false},
    // Macros
    {"in",      MAC_IN,     FMT_RR,      "rd, rs",             true},
    {"out",     MAC_OUT,    FMT_RR,      "rd, rs",             true},
    {"clr",     MAC_CLR,    FMT_R,       "rd",                 true},
    {"ld",      MAC_LD,     FMT_RL,     "rd, literal",        true},
    {"push",    MAC_PUSH,   FMT_R,       "rd",                 true},
    {"pop",     MAC_POP,    FMT_R,       "rd",                 true},
    {"halt",    MAC_HALT,   FMT_NONE,    "",                   true},
    {NULL,      CMD_UNKNOWN,FMT_NONE,    NULL,                 false}
};

// Add these helper functions
CommandType getCommandType(const char* instruction) {
    for (int i = 0; COMMANDS[i].name != NULL; i++) {
        if (strcasecmp(instruction, COMMANDS[i].name) == 0) {
            return COMMANDS[i].type;
        }
    }
    return CMD_UNKNOWN;
}

const Command* getCommand(const char* instruction) {
    for (int i = 0; COMMANDS[i].name != NULL; i++) {
        if (strcasecmp(instruction, COMMANDS[i].name) == 0) {
            return &COMMANDS[i];
        }
    }
    return NULL;
}

// Helper function to validate register
bool isValidRegister(const char* reg) {
    if (reg[0] != 'r' && reg[0] != 'R') return false;
    char* endptr;
    long num = strtol(reg + 1, &endptr, 10);
    return *endptr == '\0' && num >= 0 && num <= 31;
}

// Helper function to validate immediate value
bool isValidImmediate(const char* imm) {
    // Skip leading whitespace
    while (isspace((unsigned char)*imm)) imm++;
    
    // Check for empty string
    if (*imm == '\0') return false;
    
    // Check for negative sign
    bool isNegative = false;
    if (*imm == '-') {
        isNegative = true;
        imm++;
    }
    
    // Handle hex numbers
    if (imm[0] == '0' && (imm[1] == 'x' || imm[1] == 'X')) {
        char* endptr;
        long value = strtol(imm + 2, &endptr, 16);
        
        // Check if the entire string was parsed and value is within 12-bit range
        if (*endptr != '\0') return false;
        
        // For Tinker's 12-bit immediate field
        if (isNegative) value = -value;
        return (value >= -2048 && value <= 2047);  // 12-bit signed range
    }
    
    // Handle decimal numbers
    char* endptr;
    long value = strtol(imm, &endptr, 10);
    
    // Check if the entire string was parsed and value is within 12-bit range
    if (*endptr != '\0') return false;
    
    // For Tinker's 12-bit immediate field
    return (value >= -2048 && value <= 2047);  // 12-bit signed range
}

// Add these helper functions for syntax verification
bool isMemoryOperand(const char* operand) {
    // Check if operand matches pattern (rx)(literal)
    char reg[10];
    int literal;
    return sscanf(operand, "(%[^)])(0x%x)", reg, &literal) == 2 ||
           sscanf(operand, "(%[^)])(%d)", reg, &literal) == 2;
}

bool validateOperands(const Command* cmd, char** operands, int count) {
    switch (cmd->format) {
        case FMT_RRR:
            if (count != 3) return false;
            return isValidRegister(operands[0]) &&
                   isValidRegister(operands[1]) &&
                   isValidRegister(operands[2]);

        case FMT_RRL:
            if (count != 4) return false;  // For priv instruction
            return isValidRegister(operands[0]) &&
                   isValidRegister(operands[1]) &&
                   isValidRegister(operands[2]) &&
                   (isValidImmediate(operands[3]) || isLabelSyntax(operands[3]));

        case FMT_RR:
            if (count != 2) return false;
            return isValidRegister(operands[0]) &&
                   isValidRegister(operands[1]);

        case FMT_RL:
            if (count != 2) return false;
            return isValidRegister(operands[0]);

        case FMT_R:
            if (count != 1) return false;
            return isValidRegister(operands[0]);

        case FMT_L:
            if (count != 1) return false;
            return isValidImmediate(operands[0]) || isLabelSyntax(operands[0]);

        case FMT_NONE:
            return count == 0;

        case FMT_MEM_RRL:
            if (count != 2) return false;
            return isValidRegister(operands[0]) && isMemoryOperand(operands[1]);

        case FMT_MEM_RLR:
            if (count != 2) return false;
            return isMemoryOperand(operands[0]) && isValidRegister(operands[1]);
        default:
            return false;
    }
}

// Reimplement expandMacro with the new parser
void expandMacro(char* line, FILE* output) {
    char instruction[MAXLINE];
    char operands[MAXLINE] = "";
    char* operandArray[4] = {NULL};
    int operandCount = 0;
    
    // Parse instruction and operands
    sscanf(line, "%s %[^\n]", instruction, operands);
    
    // Get command info
    const Command* cmd = getCommand(instruction);
    if (!cmd) {
        char errorMessage[MAXLINE];
        snprintf(errorMessage, MAXLINE, "Unknown instruction: %s", instruction);
        error(errorMessage);
    }
    
    // Parse operands
    if (strlen(operands) > 0) {
        char* token = strtok(operands, ",");
        while (token && operandCount < 4) {
            operandArray[operandCount++] = trim(token);
            token = strtok(NULL, ",");
        }
    }
    
    // Validate syntax
    if (!validateOperands(cmd, operandArray, operandCount)) {
        char errorMessage[MAXLINE];
        snprintf(errorMessage, MAXLINE, "Invalid syntax for %s. Expected: %s",
                cmd->name, cmd->syntax);
        error(errorMessage);
    }
    
    // Handle each command type
    switch (cmd->type) {
        case MAC_CLR:
            if (!isValidRegister(operandArray[0])) {
                error("Invalid register operand for clr");
            }
            fprintf(output, "\txor %s, %s, %s\n", operandArray[0], operandArray[0], operandArray[0]);
            break;
            
        case MAC_IN:
        case MAC_OUT:
            if (!isValidRegister(operandArray[0]) || !isValidRegister(operandArray[1])) {
                error("Invalid register operands for in/out");
            }
            fprintf(output, "\tpriv %s, %s, r0, 0x%x\n", 
                    operandArray[0], operandArray[1], 
                    (cmd->type == MAC_IN) ? 0x3 : 0x4);
            break;
            
        case MAC_LD:
            if (!isValidRegister(operandArray[0])) {
                error("Invalid register operand for ld");
            }
            
            // Handle label or immediate value
            long long value;  // For 64-bit support
            if (operandArray[1][0] == ':') {
                value = resolveLabel(operandArray[1] + 1);
            } else {
                char* endptr;
                value = strtoll(operandArray[1], &endptr, 0);
            }
            
            // Clear the register first
            fprintf(output, "\txor %s, %s, %s\n", operandArray[0], operandArray[0], operandArray[0]);
            
            // Load first chunk without checking if it's zero
            fprintf(output, "\taddi %s, %lld\n", operandArray[0], (value >> 52) & 0xFFF);
            
            // Process remaining chunks
            for (int shift = 40; shift >= 4; shift -= 12) {
                fprintf(output, "\tshftli %s, 12\n", operandArray[0]);
                fprintf(output, "\taddi %s, %lld\n", operandArray[0], (value >> shift) & 0xFFF);
            }
            fprintf(output, "\tshftli %s, 4\n", operandArray[0]);
            fprintf(output, "\taddi %s, %lld\n", operandArray[0], value & 0xF);
            break;
        
        case MAC_PUSH:
                if (!isValidRegister(operandArray[0])) {
                    error("Invalid register operand for push");
                }
                fprintf(output, "\tmov (r31)(-8), %s\n", operandArray[0]);
                fprintf(output, "\tsubi r31, 8\n");
            break;
            
        case MAC_POP:
            if (!isValidRegister(operandArray[0])) {
                error("Invalid register operand for pop");
            }
            fprintf(output, "\tmov %s, (r31)(0)\n", operandArray[0]);
            fprintf(output, "\taddi r31, 8\n");
            break;
        case MAC_HALT:
            fprintf(output, "\tpriv r0, r0, r0, 0x%x\n", 0x0);
            break;
            
        default:
            fprintf(output, "\t%s\n", line);
            break;
    }
}

// Add this function declaration at the top with other declarations (after includes)
bool parseInstruction(const char* line, char* instruction, char** operandArray, int* operandCount);

// Move the parseInstruction implementation before parse()
bool parseInstruction(const char* line, char* instruction, char** operandArray, int* operandCount) {
    // Parse instruction and operands
    char operands[MAXLINE] = "";
    sscanf(line, "%s %[^\n]", instruction, operands);
    *operandCount = 0;
    
    // Parse operands if present
    if (strlen(operands) > 0) {
        char* token = strtok(operands, ",");
        while (token && *operandCount < 4) {
            // Only trim spaces after commas, not tabs
            while (*token == ' ') token++;
            operandArray[*operandCount] = token;
            (*operandCount)++;
            token = strtok(NULL, ",");
        }
    }
    
    // For mov instruction, try all possible formats
    if (strcasecmp(instruction, "mov") == 0) {
        for (int i = 0; COMMANDS[i].name != NULL; i++) {
            if (strcasecmp(COMMANDS[i].name, "mov") == 0) {
                // Print format for debugging
                //printf("Checking mov format: %s\n", COMMANDS[i].syntax);
                if (validateOperands(&COMMANDS[i], operandArray, *operandCount)) {
                    //printf("Valid syntax found\n");
                    return true;

                }
            }
        }
        error("Invalid syntax for mov instruction");
        return false;
    }

    if (strcasecmp(instruction, "brr") == 0) {
        for (int i = 0; COMMANDS[i].name != NULL; i++) {
            if (strcasecmp(COMMANDS[i].name, "brr") == 0) {
                if (validateOperands(&COMMANDS[i], operandArray, *operandCount)) {
                    return true;
                }
            }
        }
        error("Invalid syntax for brr instruction");
        return false;
    }
    
    
    // For other instructions, use existing behavior
    const Command* cmd = getCommand(instruction);
    if (!cmd) {
        char errorMessage[MAXLINE];
        snprintf(errorMessage, MAXLINE, "Unknown instruction: %s", instruction);
        error(errorMessage);
        return false;
    }
    
    if (!validateOperands(cmd, operandArray, *operandCount)) {
        char errorMessage[MAXLINE];
        snprintf(errorMessage, MAXLINE, "Invalid syntax for %s. Expected: %s",
                cmd->name, cmd->syntax);
        error(errorMessage);
        return false;
    }
    
    return true;
}

// First pass: collect labels and write to temp file
void firstPass(FILE *input, FILE *temp) {
    char line[MAXLINE];
    int code = 0;
    int data = 0;
    int codePresent = 0;
    
    while (fgets(line, MAXLINE, input)) {
        // Remove newline if present
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        if (line[0] == '\0' || line[0] == ';') {
            continue;
        }

        switch (line[0]) {
            case ':':  // Label definition
                addLabel(line, currentAddress);
                break;
                
            case '\t':  // Tab
            case ' ':   // Space
                // Skip if it's not 4 spaces
                if (line[0] == ' ' && (line[1] != ' ' || line[2] != ' ' || line[3] != ' ')) {
                    error("Unrecognized character at start of line");
                }
                
                if (!code && !data) {
                    error("Instruction/data must be in .code or .data section");
                }
                
                // Skip tab or 4 spaces
                char* contentStart = (line[0] == '\t') ? line + 1 : line + 4;
                
                if (code) {
                    if (strncmp(contentStart, "ld", 2) == 0) {
                        currentAddress += 48;
                    } else if (strncmp(contentStart, "push", 4) == 0 || strncmp(contentStart, "pop", 3) == 0){
                        currentAddress += 8;
                    } else {
                        currentAddress += 4;  // Only increment address for code
                    }
                    fprintf(temp, "\t%s\n", contentStart);
                } else if (data) {
                    fprintf(temp, "\t%s\n", contentStart);  // Write data lines 
                    currentAddress += 8;
                }
                break;
                
            case '.': 
                if (strncmp(line, ".code", 5) == 0) {
                    if(code){
                        continue;
                    } else {
                        code = 1;
                        data = 0;
                        codePresent = 1;
                        fprintf(temp, "%s\n", line);
                    }
                } else if (strncmp(line, ".data", 5) == 0) {
                    if(data){
                        continue;
                    } else {
                        code = 0;
                        data = 1;
                        fprintf(temp, "%s\n", line);
                    }
                }
                break;
                
            default:  
                error("Unrecognized character at start of line");
        }
    }
    
    if (!codePresent) {
        error("File must contain at least one .code directive");
    }
}

// Second pass: process instructions with resolved labels
void secondPass(FILE *temp, FILE *output) {
    char line[MAXLINE];
    currentAddress = START;  // Reset address counter

    int code =  0;
    int data = 0;
    
    while (fgets(line, MAXLINE, temp)) {
        // Skip empty lines and directives
        if (line[0] == '\n' || line[0] == '\0' || line[0] == '.') {
            if(strncmp(line, ".code", 5) == 0){
                code = 1;
                data = 0;
            } else if (strncmp(line, ".data", 5) == 0){
                code = 0;
                data = 1;
            }
            fprintf(output, "%s", line);
            continue;
        }

        // Process instruction
        char instruction[MAXLINE];
        char* operandArray[4] = {NULL};
        int operandCount = 0;
        
        // Skip tab
        char* instrStart = line + 1;
        
        if (code) {
            if (!parseInstruction(instrStart, instruction, operandArray, &operandCount)) {
                error("Invalid instruction");
            }
            // Check if it's a macro
            Macro* macro = findMacro(macros, instruction);
            if (macro) {
                expandMacro(instrStart, output);
            } else {
                fprintf(output, "%s", line);
            }
        } else if (data) {
            fprintf(output, "%s", line);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s input_file output_file\n", argv[0]);
        return 1;
    }

    FILE *input = fopen(argv[1], "r");
    FILE *output = fopen(argv[2], "w");
    FILE *temp = tmpfile();

    if (!input || !output || !temp) {
        error("Error: Error opening files.");
        return 1;
    }

    labels = createLabelArray(10);
    macros = createMacroArray(10);
    setMacros();

    // First pass: collect labels
    firstPass(input, temp);
    
    // Prepare for second pass
    rewind(temp);
    
    // Second pass: process instructions
    secondPass(temp, output);

    freeLabels(labels);
    freeMacros(macros);
    fclose(input);
    fclose(output);
    fclose(temp);
    return 0;
}
