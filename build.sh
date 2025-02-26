#!/bin/bash

# Compile the unified executable (syntax_verifier.c now includes binary conversion)
gcc -o hw5 -Iinclude src/arraylist.c src/label_table.c src/line.c src/syntax_verifier.c

# Move the compiled executable to the script's directory (if it's not already there)
mv hw5 "$(dirname "$0")"

# Make the executable runnable
chmod +x hw5