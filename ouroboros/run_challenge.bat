@echo off
echo ========================================
echo   Ouroboros CTF Challenge
echo ========================================
echo.

REM Check if extensions are built
if not exist "crypto_extension.pyd" (
    echo ERROR: C extensions not found!
    echo Please run build_simple.bat first to build the extensions.
    echo.
    pause
    exit /b 1
)

REM Copy main.py to root if not exists
if not exist main.py (
    copy src\main.py main.py >nul
)

echo Starting challenge...
echo.
python main.py

echo.
pause
