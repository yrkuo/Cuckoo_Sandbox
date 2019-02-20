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
$sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
$getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
## install Pydeep
```bash
$wget http://sourceforge.net/projects/ssdeep/files/ssdeep-2.13/ssdeep-2.13.tar.gz/download
$mv dowonload download.tar.gz
$tar -zxf download.tar.gz
$cd ssdeep-2.13
$./configure
$make
$sudo make install
#確認安裝無誤
$ssdeep -V(大寫) 
2.13

$sudo pip install pydeep
$sudo pip show pydeep
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
