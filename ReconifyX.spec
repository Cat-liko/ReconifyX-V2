# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置 —— 单文件 Windows 可执行程序。

用法:
    python -m pip install pyinstaller
    python -m PyInstaller --noconfirm --clean ReconifyX.spec
产物:
    dist/ReconifyX.exe

三个要点(改之前先看清楚):

1. ``datas`` 把整个 ``app/static`` 目录打进去 —— 前端是 4 个文件
   (index.html / app.js / style.css / favicon.svg),少一个 UI 就白屏。
   ``app/main.py::_static_dir()`` 在 frozen 模式下从 ``sys._MEIPASS`` 取。

2. ``hiddenimports`` 里是**静态分析看不见**的导入:
   - ``reconifyx.cli`` 只在 launcher 的分支里按需导入;
   - uvicorn 的协议 / 循环后端是运行时按平台字符串选出来的,模块图扫不到。
   漏掉它们不会在构建期报错,而是在双击 exe 后运行时才炸。

3. ``console=True`` 是刻意的:同一个 exe 既是"双击起服务",也是
   ``ReconifyX.exe scan example.com`` 的命令行工具。要无窗口双击体验的话,
   应该另做一个 windowed 版本,而不是把 CLI 阉掉。
"""

a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=[],
    datas=[('app/static', 'app/static')],
    hiddenimports=[
        'reconifyx',
        'reconifyx.cli',
        # uvicorn 运行时按平台选后端,模块图看不到
        'uvicorn.logging',
        'uvicorn.loops.auto',
        'uvicorn.loops.asyncio',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.http.h11_impl',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan.on',
        'uvicorn.lifespan.off',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ReconifyX',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
