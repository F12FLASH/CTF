@echo off
echo ========================================
echo   Building Ouroboros Challenge to EXE
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo Step 1: Installing Python dependencies...
python -m pip install --upgrade pip
python -m pip install pycryptodome pyinstaller

echo.
echo Step 2: Building C extensions...
python build_extension.py build_ext --inplace
if errorlevel 1 (
    echo ERROR: Failed to build C extensions
    echo Make sure you have Microsoft Visual C++ Build Tools installed
    echo Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
    pause
    exit /b 1
)

echo.
echo Step 3: Packaging to standalone executable...
REM Copy main.py to root if not exists
if not exist main.py (
    copy src\main.py main.py
)

REM Create executable with PyInstaller
pyinstaller --onefile --name=ouroboros_challenge ^
    --hidden-import=crypto_extension ^
    --hidden-import=fragments ^
    --hidden-import=anti_analysis ^
    --hidden-import=self_modify ^
    --add-binary="crypto_extension.pyd;." ^
    --add-binary="fragments.pyd;." ^
    --add-binary="anti_analysis.pyd;." ^
    --add-binary="self_modify.pyd;." ^
    --console ^
    main.py

if errorlevel 1 (
    echo ERROR: Failed to create executable
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Build completed successfully!
echo ========================================
echo.
echo Executable location: dist\ouroboros_challenge.exe
echo.
echo To test the challenge:
echo   cd dist
echo   ouroboros_challenge.exe
echo.
pause
