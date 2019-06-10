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
$ sudo apt-get install python-sqlalchemy python-bson python-dpkt python-bottle python-jinja2 python-magic python-pymongo python-gridfs build-essential python-django python-pil python-pefile python-chardet
$ sudo apt-get install python python-pip python-dev libffi-dev libssl-dev
$ sudo apt-get install python-virtualenv python-setuptools
$ sudo apt-get install libjpeg-dev zlib1g-dev swig
$ sudo apt-get install mongodb
$ sudo apt-get install postgresql libpq-dev
```
## install YARA
```bash
$ sudo apt-get install libtool automake libmagic-dev
$ wget https://github.com/VirusTotal/yara/archive/v3.10.0.tar.gz
$ tar -zxf v3.10.0.tar.gz
$ cd yara-3.10.0
$ ./bootstrap.sh
$ ./configure
$ make
$ sudo make install
#啟用模組
$ ./configure --enable-cuckoo
$ ./configure --enable-magic
```
## install tcpdump
```bash
$ sudo apt-get install tcpdumpd
# 權限設定
$ sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
# 確認設定
$ getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
# 如果沒有setcap套件
$ sudo apt-get install libcap2-bin
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
$ sudo vim /etc/default/grub
GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"
$ sudo grub-mkconfig -o /boot/grub/grub.cfg
$ restart(重啟系統)
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
  $ reg add "hklm\software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultUserName /d <USERNAME> /t REG_SZ /f
  $ reg add "hklm\software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword /d <PASSWORD> /t REG_SZ /f
  $ reg add "hklm\software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v AutoAdminLogon /d 1 /t REG_SZ /f
  $ reg add "hklm\system\CurrentControlSet\Control\TerminalServer" /v AllowRemoteRPC /d 0x01 /t REG_DWORD /f
  $ reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /d 0x01 /t REG_DWORD /f
  ===
```
## Cuckoo配置
```
參考連結1
```
## 配置多台虛擬機
```bash
安裝MySQL(參考連結4)
$ sudo apt-get update
$ sudo apt-get install python-mysqldb
$ sudo spt-get install mysql-server
$ sudo mysql_secure_installation(皆選擇yes，密碼強度設定為LOW)
$ sudo mysql -u root -p(第一次要加sudo)
#建立給cuckoo用的資料庫
mysql>create database cuckoo;
#登入設定
mysql>select user,host,plugin from mysql.user;
mysql>alter user 'root'@'localhost' identified with mysql_native_password by '密碼';
mysql>flush privileges;

#更改cuckoo.conf
[database]
connection = mysql://root:密碼@localhost/cuckoo

#更改virtualbox.conf
[virtualbox]
machines = sample,cuckoo2,cuckoo3(依想設定的數量而定，名稱也可以自行設定，只需對應好標籤即可)

EX:
[sample]
label = 虛擬機名稱(例:Analysis_winxp)
platform = windows
ip = 192.168.56.101(自行設定)
snapshot = 快照名稱

```
## 參考文件
[Cuckoo Installation](https://0x90e.github.io/cuckoo-installation/)
[官方文件](https://cuckoo.sh/docs/installation/index.html)
[Cuckoo SandBox V2.0.6安裝指南](https://www.itread01.com/content/1542834127.html)
[MySQL安裝與設定](https://blog.csdn.net/weixx3/article/details/80782479)


