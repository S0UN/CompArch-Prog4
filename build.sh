#!/bin/bash

# Compile the unified executable (syntax_verifier.c now includes binary conversion)
gcc -o hw4 -Iinclude src/arraylist.c src/label_table.c src/line.c src/syntax_verifier.c

# Move the compiled executable to the script's directory (if it's not already there)
mv hw4 "$(dirname "$0")"

# Make the executable runnable
chmod +x hw4
