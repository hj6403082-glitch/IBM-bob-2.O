@echo off
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto usepython
py -3 start.py %*
goto done
:usepython
where python >nul 2>nul
if errorlevel 1 goto missing
python start.py %*
goto done
:missing
echo Python was not found. Install Python 3.11 or newer from python.org.
echo Enable Add Python to PATH during installation, then run this file again.
:done
pause
