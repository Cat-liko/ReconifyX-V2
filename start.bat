@echo off
rem ---------------------------------------------------------------------------
rem  ReconifyX launcher (Windows)
rem
rem  本文件刻意只用 ASCII 字符:cmd.exe 会按当前代码页解析 .bat,中文注释在
rem  非 936 代码页的控制台上会变成乱码(甚至吃掉后面的引号)。所有中文提示都
rem  由 Python 侧输出,那里用 UTF-8 是可靠的。
rem  ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

rem 让 Python 的中文输出在当前控制台正常显示
chcp 65001 >nul 2>nul

echo.
echo   ============================================================
echo     ReconifyX - local attack surface management
echo   ============================================================
echo.

rem ---- 1) 找到 Python -------------------------------------------------------
set "PYTHON=python"
where python >nul 2>nul
if errorlevel 1 (
    where py >nul 2>nul
    if errorlevel 1 (
        echo   [error] Python not found.
        echo   Install Python 3.10+ from https://www.python.org/downloads/
        echo   and tick "Add python.exe to PATH".
        echo.
        pause
        exit /b 1
    )
    set "PYTHON=py"
)

rem ---- 2) 首次运行自动装依赖 ------------------------------------------------
%PYTHON% -c "import fastapi, uvicorn, httpx, dns" >nul 2>nul
if errorlevel 1 (
    echo   [setup] Installing dependencies, this may take a minute...
    %PYTHON% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo   [error] Dependency installation failed. Run manually:
        echo     %PYTHON% -m pip install -r requirements.txt
        echo.
        pause
        exit /b 1
    )
)

rem ---- 3) 启动(端口选择 / 打开浏览器 / 关闭都由 launcher.py 负责)---------
rem  额外参数会原样透传,例如:
rem      start.bat --port 9000
rem      start.bat scan example.com -p ultra
%PYTHON% -X utf8 launcher.py %*

if errorlevel 1 (
    echo.
    echo   [exit] Process ended with an error.
    pause
)
endlocal
