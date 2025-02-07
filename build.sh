#!/bin/bash

FILENAME="hw4"

# Compile the source files (excluding goodcode.c)
gcc -o $FILENAME -Iinclude src/arraylist.c src/label_table.c src/line.c src/main.c src/syntax_verifier.c

# Move the compiled executable to the script's directory
mv $FILENAME "$(dirname "$0")"

# Make the executable runnable
chmod +x $FILENAME

