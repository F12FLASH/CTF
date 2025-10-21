#!/bin/bash

echo "Building Ouroboros Challenge (Linux/macOS)"
echo

echo "Installing Python dependencies..."
pip install pycryptodome

echo
echo "Building C extensions..."
python build_extension.py build_ext --inplace

echo
echo "Build complete!"
echo
echo "To run challenge:"
echo "  python main.py"
echo
echo "To solve (extremely difficult):"
echo "  python solve.py"
echo

# For Linux/macOS, we don't use pause like in Windows
# Instead, we can wait for user input if needed
read -p "Press any key to continue..." -n1 -s
echo