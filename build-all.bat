@echo off
setlocal EnableExtensions

if /i "%~1"=="--worker" goto worker

where cargo >nul 2>&1
if errorlevel 1 (
    echo Error: cargo was not found in PATH.
    exit /b 1
)

where zig >nul 2>&1
if errorlevel 1 (
    echo Error: Zig was not found in PATH.
    exit /b 1
)

where cargo-zigbuild >nul 2>&1
if errorlevel 1 (
    echo Error: cargo-zigbuild is not installed.
    echo Install it with: cargo install --locked cargo-zigbuild
    exit /b 1
)

rustup target list --installed | findstr /c:"x86_64-pc-windows-msvc" >nul
if errorlevel 1 (
    echo Error: Rust target x86_64-pc-windows-msvc is not installed.
    echo Install it with: rustup target add x86_64-pc-windows-msvc
    exit /b 1
)

rustup target list --installed | findstr /c:"x86_64-unknown-linux-gnu" >nul
if errorlevel 1 (
    echo Error: Rust target x86_64-unknown-linux-gnu is not installed.
    echo Install it with: rustup target add x86_64-unknown-linux-gnu
    exit /b 1
)

:create_state_directory
set "BUILD_STATE=%TEMP%\verihash-build-%RANDOM%-%RANDOM%"
if exist "%BUILD_STATE%" goto create_state_directory
mkdir "%BUILD_STATE%" >nul 2>&1
if errorlevel 1 (
    echo Error: could not create build state directory.
    exit /b 1
)

echo Starting Windows and Linux release builds in separate windows...
start "VeriHash Windows Build" "%ComSpec%" /d /c ""%~f0" --worker windows "%BUILD_STATE%\windows.exit""
start "VeriHash Linux Build" "%ComSpec%" /d /c ""%~f0" --worker linux "%BUILD_STATE%\linux.exit""

for /l %%N in (1,1,15) do (
    if exist "%BUILD_STATE%\windows.exit.started" if exist "%BUILD_STATE%\linux.exit.started" goto workers_started
    ping 127.0.0.1 -n 2 >nul
)

echo Error: one or more build windows failed to start.
rmdir /s /q "%BUILD_STATE%" >nul 2>&1
exit /b 1

:workers_started
echo Waiting for both builds to finish...
:wait_for_builds
if not exist "%BUILD_STATE%\windows.exit" goto wait_one_second
if not exist "%BUILD_STATE%\linux.exit" goto wait_one_second
goto builds_finished

:wait_one_second
ping 127.0.0.1 -n 2 >nul
goto wait_for_builds

:builds_finished
set /p WINDOWS_EXIT=<"%BUILD_STATE%\windows.exit"
set /p LINUX_EXIT=<"%BUILD_STATE%\linux.exit"
rmdir /s /q "%BUILD_STATE%" >nul 2>&1

echo.
if not "%WINDOWS_EXIT%"=="0" echo Windows build failed with exit code %WINDOWS_EXIT%.
if not "%LINUX_EXIT%"=="0" echo Linux build failed with exit code %LINUX_EXIT%.
if not "%WINDOWS_EXIT%"=="0" exit /b 1
if not "%LINUX_EXIT%"=="0" exit /b 1

echo Build complete:
echo   Windows: target\build-windows\x86_64-pc-windows-msvc\release\verihash.exe
echo   Linux:   target\build-linux\x86_64-unknown-linux-gnu\release\verihash
exit /b 0

:worker
set "BUILD_PLATFORM=%~2"
set "BUILD_STATUS=%~3"
>"%BUILD_STATUS%.started" echo started
cd /d "%~dp0"
if errorlevel 1 (
    >"%BUILD_STATUS%" echo 1
    exit /b 1
)

if /i "%BUILD_PLATFORM%"=="windows" (
    cargo build --locked --release --target x86_64-pc-windows-msvc --target-dir target/build-windows
) else if /i "%BUILD_PLATFORM%"=="linux" (
    set "ZIG_GLOBAL_CACHE_DIR=%~dp0target\zig-cache-global"
    set "ZIG_LOCAL_CACHE_DIR=%~dp0target\zig-cache-local"
    cargo zigbuild --locked --release --target x86_64-unknown-linux-gnu --target-dir target/build-linux
) else (
    echo Error: unknown build platform "%BUILD_PLATFORM%".
    >"%BUILD_STATUS%" echo 1
    exit /b 1
)

set "BUILD_EXIT=%ERRORLEVEL%"
>"%BUILD_STATUS%" echo %BUILD_EXIT%

echo.
if "%BUILD_EXIT%"=="0" (
    echo %BUILD_PLATFORM% build complete. This window will close in 3 seconds.
    ping 127.0.0.1 -n 4 >nul
) else (
    echo %BUILD_PLATFORM% build failed with exit code %BUILD_EXIT%.
    pause
)
exit /b %BUILD_EXIT%
