
@echo off
cd /D "%~dp0"

REM check for custom node version
IF EXIST "%~dp0..\nodejs\node.exe" (
  SET "PATH=%~dp0..\nodejs;%PATH%"
)

node .\cronicle.js --echo --foreground --color