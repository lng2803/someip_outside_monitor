@echo off
:: ============================================================
::  build_windows.bat  --  Build SomeipMonitor.exe for Windows
:: ============================================================
::
::  Prerequisites:
::    pip install pyinstaller PySide6
::
::  Usage:
::    build_windows.bat
::
::  Output:
::    dist\SomeipMonitor\SomeipMonitor.exe   (folder-based distribution)
:: ============================================================

setlocal EnableDelayedExpansion

echo [1/4] Checking for PyInstaller...
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo  ERROR: PyInstaller not found. Install it with:
    echo         pip install pyinstaller
    exit /b 1
)

echo [2/4] Cleaning previous build artefacts...
if exist build   rmdir /s /q build
if exist dist    rmdir /s /q dist

echo [3/4] Running PyInstaller...
python -m PyInstaller SomeipMonitor.spec --noconfirm

if errorlevel 1 (
    echo.
    echo  ERROR: PyInstaller failed. See output above for details.
    exit /b 1
)

echo [4/4] Done!
echo.
echo  Executable:  dist\SomeipMonitor\SomeipMonitor.exe
echo  Directory:   dist\SomeipMonitor\
echo.
pause
