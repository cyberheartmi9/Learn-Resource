# IPTABLES
Rules--> chains

### special values

|target|means|
|-------|------|
|accept|allow packet pass through|
|drop|stop packet pass through|
|return|stop packet from traveling and tell it to go back to previous rules|
|LOG|Sends packet information to rsyslogd daemon for logging.|


### filters
|filter|means|
|----|----|
|input|control incoming packets to server|
|output|filter out packet that go out from server|
|forward|filter incoming packet that will be forwarded somewhere else|


### NAT 

|NAT|means|
|---|--|
|PREROUTING|Packets will enter in this chain before a routing decision is made|
|POSTROUTING|Packets enters in this chain just before handing them off to the hardware. At this point routing decision has been made.|
|OUTPUT|NAT for locally generated packets on the firewall.|



#### example

<br>eth0-> wlan
<br>eth1-> lan
```bash
sudo iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE
sudo iptables --append FORWARD --in-interface eth1 -j ACCEPT
sudo service iptables restart
```

### Mangle(TCP header modification)

|mangle|means|
|-|-|
|PREROUTING, POSTROUTING,OUTPUT, INPUT, FORWARD|Modification of the TCP packet and set quality of service bits before routing occurs.|

### Defining rules (A)
```bash
sudo iptables -A
```

#### options
|option|mean|
|----|---|
|-A|append chain(input,output,forward|
|-i|inferface(eth0,tun0,..)|
|-p|protocol icmp,udp,..|
|-s|address from which traffic comes from|
|--dport|destination port(22,21,..)|
|-j|target(accept,drop,return|
|--src-range|ip range 10.10.10.1-10.10.10.255|
|-m|match (iprange)|


```bash
sudo iptables -A <chain> -i <interface> -p <protocol (tcp/udp) > -s <source> --dport <port no.>  -j <target>
```

#### enable traffic on localhost
```bash
sudo iptables -A INPUT -i lo -j ACCEPT
```

### enable http(s)/ssh
```bash

sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT

```


### Deleting Rules

```bash

sudo iptables -F
sudo iptables -L --line-numbers

Chain INPUT (policy ACCEPT)

num  target     prot opt source               destination

1    ACCEPT     all -- 192.168.9.104          anywhere
2    ACCEPT     tcp -- anywhere             anywhere tcp dpt:https
3    ACCEPT     tcp -- anywhere             anywhere tcp dpt:http
4    ACCEPT     tcp -- anywhere             anywhere tcp dpt:ssh


sudo iptables -D INPUT [num]
sudo iptables -D INPUT 3

```

### Save changes

```bash
sudo /sbin/iptables-save
````


### track connection status
```bash
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```



