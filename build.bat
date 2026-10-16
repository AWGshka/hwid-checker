@echo off
rem Builds the release binary and copies just the exe to out\
setlocal
cd /d "%~dp0"

cargo build --release || exit /b 1

if not exist out mkdir out
copy /y target\release\hwid_checker.exe out\hwid_checker.exe > nul || exit /b 1
echo Built: %~dp0out\hwid_checker.exe
