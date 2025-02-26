#!/bin/bash

# Compile the unified executable (syntax_verifier.c now includes binary conversion)
gcc -o hw7-asm -Iinclude src/arraylist.c src/label_table.c src/line.c src/syntax_verifier.c

# Move the compiled executable to the script's directory (if it's not already there)
mv hw7-asm "$(dirname "$0")"

# Make the executable runnable
chmod +x hw7-asm


# Compile the unified executable (syntax_verifier.c now includes binary conversion)
gcc -o hw7-sim -Iinclude src/tinker3.c 

# Move the compiled executable to the script's directory (if it's not already there)
mv hw7-sim "$(dirname "$0")"

# Make the executable runnable
chmod +x hw7-sim