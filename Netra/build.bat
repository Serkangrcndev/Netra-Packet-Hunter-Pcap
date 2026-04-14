@echo off
REM Build script for Netra project (Windows)

setlocal enabledelayedexpansion

REM Colors won't work in cmd, but we can use clear messages
echo ================================================
echo Netra Build System (Windows)
echo ================================================
echo.

REM Check for CMake
cmake --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: CMake not found! Please install CMake 3.20 or higher.
    exit /b 1
)

REM Check for Ninja
ninja --version >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Ninja not found. Using default generator.
)

REM Default values
set BUILD_TYPE=Debug
set BUILD_PRESET=debug

REM Parse arguments
:parse_args
if "%1"=="" goto done_parsing
if "%1"=="-r" set BUILD_TYPE=Release & shift & goto parse_args
if "%1"=="--release" set BUILD_TYPE=Release & shift & goto parse_args
if "%1"=="-d" set BUILD_TYPE=Debug & shift & goto parse_args
if "%1"=="--debug" set BUILD_TYPE=Debug & shift & goto parse_args
if "%1"=="-h" goto show_help
if "%1"=="--help" goto show_help
shift
goto parse_args

:show_help
echo Build script for Netra
echo Usage: build.bat [options]
echo.
echo Options:
echo   -r, --release     Build Release version
echo   -d, --debug       Build Debug version (default)
echo   -h, --help        Show this help message
exit /b 0

:done_parsing
if /I "%BUILD_TYPE%"=="Release" set BUILD_PRESET=release
if /I "%BUILD_TYPE%"=="Debug" set BUILD_PRESET=debug
echo Build Configuration:
echo   Build Type: %BUILD_TYPE%
echo   CMake Preset: %BUILD_PRESET%
echo.

REM Create build directory
if not exist build mkdir build

REM Configure
echo Configuring project...
cmake --preset %BUILD_PRESET% -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if %errorlevel% neq 0 (
    echo Configuration failed!
    exit /b 1
)

REM Build
echo Building project...
cmake --build --preset %BUILD_PRESET%
if %errorlevel% neq 0 (
    echo Build failed!
    exit /b 1
)

REM Run tests
echo Running tests...
cd build\%BUILD_PRESET%
ctest --output-on-failure -C %BUILD_TYPE%
cd ..
cd ..

echo.
echo ================================================
echo Build completed successfully!
echo ================================================
echo.
echo Executable location: build\%BUILD_PRESET%\bin\netra.exe
echo.
