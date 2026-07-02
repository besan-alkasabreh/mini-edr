@echo off
title Build Mini EDR Agent Setup - UI Task Version
echo ---------------------------------------------
echo Building Mini EDR Agent Setup Wizard
echo ----------------------------------

python -m pip install --upgrade pyinstaller

pyinstaller --onefile --noconsole ^
  --name MiniEDR-Agent-Setup ^
  agent_setup.py

echo.
echo Build complete.
echo Output:
echo dist\MiniEDR-Agent-Setup.exe
pause
