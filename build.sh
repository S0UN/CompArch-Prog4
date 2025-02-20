#!/bin/bash

# Compile the unified executable (syntax_verifier.c now includes binary conversion)
gcc -o hw6 src/tinker3.c 

# Move the compiled executable to the script's directory (if it's not already there)
mv hw6 "$(dirname "$0")"

# Make the executable runnable
chmod +x hw6
