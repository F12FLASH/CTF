@echo off
echo ========================================
echo   Building Ouroboros C Extensions
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo Installing Python dependencies...
python -m pip install pycryptodome

echo.
echo Building C extensions...
python build_extension.py build_ext --inplace

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    echo.
    echo Make sure you have Microsoft Visual C++ Build Tools installed.
    echo Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo.
    echo Required components:
    echo   - MSVC v143 or later
    echo   - Windows SDK
    echo   - C++ CMake tools
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Build completed successfully!
echo ========================================
echo.
echo To run the challenge:
echo   python src\main.py
echo.
echo Or with demo mode (no anti-debugging):
echo   set OUROBOROS_DEMO=1
echo   python src\main.py
echo.
pause
