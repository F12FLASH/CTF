@echo off
echo Building Ouroboros Challenge (Windows)
echo.

echo Installing Python dependencies...
pip install pycryptodome

echo.
echo Building C extensions...
python build_extension.py build_ext --inplace

echo.
echo Build complete!
echo.
echo To run challenge:
echo   python main.py
echo.
echo To solve (extremely difficult):
echo   python solve.py
echo.
pause