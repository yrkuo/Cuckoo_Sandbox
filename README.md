# Cuckoo_Sandbox
Record how to install Cuckoo Sandbox

## 基本環境
```
* Host OS: Ubuntu 18.04 LST
* Guest OS: Windows 7 x64 Professional SP1
* Cuckoo: 2.0.6
* Virtualization software: VirtualBox 5.2.18
* Python Version: 2.7.15rc1
```
## 安裝套件
```bash
$ sudo apt-get install git mongodb libffi-dev build-essential python-django python python-dev python-pip python-pil python-sqlalchemy python-bson python-dpkt python-jinja2 python-magic python -pymongo python-gridfs python-libvirt python-bottle python-pefile python-chardet tcpdump
$ sudo apt-get install python python-pip python-dev libffi-dev libssl-dev
$ sudo apt-get install python-virtualenv python-setuptools
$ sudo apt-get install libjpeg-dev zlib1g-dev swig
```
## install tcpdump
```bash
$ sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
$ getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
## install Pydeep
```bash
$ wget http://sourceforge.net/projects/ssdeep/files/ssdeep-2.13/ssdeep-2.13.tar.gz/download
$ mv dowonload download.tar.gz
$ tar -zxf download.tar.gz
$ cd ssdeep-2.13
$ ./configure
$ make
$ sudo make install
# 確認安裝無誤
$ ssdeep -V(大寫) 
2.13

$ sudo pip install pydeep
$ sudo pip show pydeep
---
Name: pydeep
Version: 0.4 
Summary: Python bindings for ssdeep
Home-page: http://www.github.com/kbandla/pydeep
Author: Kiran Bandla
Author-email: [email protected]
License: BSD 
Location: /usr/local/lib/python2.7/dist-packages
Requires: 
```
## install Volatility
```bash
# 安裝前置套件
$ sudo pip install openpyxl
$ sudo pip install ujson
$ sudo pip install pycrypto
$ sudo pip install distorm3
$ sudo pip install pytz

$ git clone https://github.com/volatilityfoundation/volatility.git
$ cd volatility
$ python setup.py build
$ python setup.py install
# 確認安裝無誤
$ python vol.py -h
```
## install M2Crypto
```bash
$ sudo pip install m2crypto==0.24.0(官方)
$ sudo apt-get install python-m2crypto(自身)
```
## Network Configuration
```bash
# 建立IP轉發
$ sudo vim /etc/sysctl.conf
  將底下這段的註解取消
  # Uncomment the next line to enable packet forwarding for IPv4
  net.ipv4.ip_forward=1

# 建立iptables
$ sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
# Default drop.
$ sudo iptables -P FORWARD DROP
# Existing connections.
$ sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
# Accept connections from vboxnet to the whole internet.
$ sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
# Internal traffic.
$ sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
# Log stuff that reaches this point (could be noisy).
$ sudo iptables -A FORWARD -j LOG

# 更改網卡名稱(不確定)
在原先的設定下,網卡名稱是以eno1表示,但傳統是以eth0表示,在未改名稱前,會有虛擬機可連外網但host無法連的狀況
```
## install Cuckoo
```bash
$ pip install cuckoo
```
## install VituralBox
```bash
$ sudo apt-get install virtualbox
# 執行virtualbox
$ virtualbox
```
## Guest配置
```
創建一虛擬機器，作業系統為win7。
網路配置：
* 檔案->主機網路管理員->建立vboxnet(host-only)(不使用DHCP，值為預設)
* (Guest虛擬機)設定值->網路->將NAT改成Host-only介面卡(vboxnet)
* 開啟Guest虛擬機->手動設定IP
  * ip      : 192.168.56.101
  * mask    : 255.255.255.0
  * gateway : 192.168.56.1
  * dns     : 8.8.8.8
  
環境配置：
* 安裝python 2.7.15rc
* 安裝Pillow(pip install Pillow)
* 安裝PDF readers，Office，Adobe Flash，瀏覽器等可能觸發惡意樣本行爲的軟體
* 關閉自動更新
* 關閉防火牆
* 關閉UAC

agent.py配置:
+ 將Cuckoo的agent.py設定爲開機自啓動
  + 該文件原始位置在Host OS的CWD子目錄中，預設在~/.cuckoo/agent/agent.py(在host端先執行一次`$cuckoo`，失敗沒關係，目的在產生.cuckoo資料夾)
  + 複製並將agent.py檔名修改爲agent.pyw，避免啓動時的執行視窗
  + 將agent.pyw移入Guest OS的下列指定目錄內
    + C:\Users[USER]\AppData\Roaming\MicroSoft\Windows\Start Menu\Programs\Startup\
      [USER]是指Windows user名稱
      例如: C:\Users\analyzer\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
      AppData爲隱藏目錄，記得打開顯示隱藏目錄的Windows選項
+ 配置系統開機自動登入
  + 使用Administrator權限啓動cmd，並依序在cmd中輸入以下指令
  + [USERNAME]與[PASSWORD]需替換爲登入的Windows user與對應的password
  ===
  $ reg add "hklm\software\Miscrosoft\Windows NT\CurrentVersion\WinLogon" /v DefaultUserName /d <USERNAME> /t REG_SZ /f
  $ reg add "hklm\software\Miscrosoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword /d <PASSWORD> /t REG_SZ /f
  $ reg add "hklm\software\Miscrosoft\Windows NT\CurrentVersion\WinLogon" /v AutoAdminLogon /d 1 /t REG_SZ /f
  $ reg add "hklm\system\CurrentControlSet\Control\TerminalServer" /v AllowRemoteRPC /d 0x01 /t REG_DWORD /f
  $ reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /d 0x01 /t REG_DWORD /f
  ===
```
## Cuckoo配置
```
參考連結1
```
## 參考文件
[Cuckoo Installation](https://0x90e.github.io/cuckoo-installation/)

