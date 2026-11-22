@echo off
rem ---------------------------------------------------------------------------
rem  Build a single-file Windows executable.
rem
rem  Output: dist\ReconifyX.exe
rem
rem  The build is driven by ReconifyX.spec (not by command-line flags) so that
rem  CI, `make build-exe` and this script all produce the same binary.
rem  Keep this file ASCII-only: cmd.exe parses .bat with the OEM code page.
rem  ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set "PYTHON=python"
where python >nul 2>nul
if errorlevel 1 (
    where py >nul 2>nul
    if errorlevel 1 (
        echo   [error] Python not found. Install Python 3.10+ and add it to PATH.
        pause
        exit /b 1
    )
    set "PYTHON=py"
)

echo.
echo   [1/2] Installing / upgrading PyInstaller...
%PYTHON% -m pip install --upgrade pyinstaller
if errorlevel 1 (
    echo   [error] Failed to install PyInstaller.
    pause
    exit /b 1
)

echo   [2/2] Building dist\ReconifyX.exe ...
%PYTHON% -m PyInstaller --noconfirm --clean ReconifyX.spec
if errorlevel 1 (
    echo.
    echo   [error] Build failed.
    pause
    exit /b 1
)

echo.
echo   Build complete: dist\ReconifyX.exe
echo.
echo   Run it by double-clicking (serves on 127.0.0.1 and opens the browser),
echo   or from a terminal:
echo       dist\ReconifyX.exe scan example.com -p ultra
echo.
dir /b dist
endlocal
