#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Name: SSAuther
Author: K4YT3X
Date Created: July 15, 2017
Description: Authenticator for shadowsocks, anti-firewall gadget
"""

import hashlib
import os
import socket
import time
import subprocess

try:
    import avalon_framework as avalon
except ImportError:
    while True:
        install = input('\033[31m\033[1mAVALON Framework not installed! Install now? [Y/n] \033[0m')
        if len(install) == 0 or install[0].upper() == 'Y':
            try:
                if os.path.isfile('/usr/bin/pip3'):
                    print('Installing using method 1')
                    os.system('pip3 install avalon_framework')
                elif os.path.isfile('/usr/bin/wget'):
                    print('Installing using method 2')
                    os.system('wget -O - https://bootstrap.pypa.io/get-pip.py | python3')
                    os.system('pip3 install avalon_framework')
                else:
                    print('Installing using method 3')
                    import urllib.request
                    content = urllib.request.urlopen('https://bootstrap.pypa.io/get-pip.py')
                    with open('/tmp/get-pip.py', 'w') as getpip:
                        getpip.write(content.read().decode())
                        getpip.close()
                    os.system('python3 /tmp/get-pip.py')
                    os.system('pip3 install avalon_framework')
                    os.remove('/tmp/get-pip.py')
            except Exception as e:
                print('\033[31mInstallation failed!: ' + str(e))
                print('Please check your Internet connectivity')
                exit(0)
            print('\033[32mInstallation Succeed!\033[0m')
            print('\033[32mPlease restart the program\033[0m')
            exit(0)
        elif install[0].upper() == 'N':
            print('\033[31m\033[1mSCUTUMM requires avalon framework to run!\033[0m')
            print('\033[33mAborting..\033[0m')
            exit(0)
        else:
            print('\033[31m\033[1mInvalid Input!\033[0m')


AUTHED_ADDR = []


# -------------------------------- Classes --------------------------------

class iptables():
    """iptables command handler"""
    def allow(addr):
        avalon.subLevelTimeInfo('Allowing ' + addr)
        os.system('iptables -A INPUT -p tcp --dport 1080 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT -s ' + addr)
        AUTHED_ADDR.append(addr)

    def expire(addr):
        output = subprocess.Popen(['iptables', '-L', '--line-numbers'], stdout=subprocess.PIPE).communicate()[0]
        output = output.decode().split('\n')
        for line in output:
            if addr in line:
                avalon.subLevelTimeInfo('Disallowing ' + addr)
                os.system('iptables -D INPUT ' + line.split(' ')[0])
                AUTHED_ADDR.pop(AUTHED_ADDR.index(addr))


# -------------------------------- Functions --------------------------------

def meha(prehash, seed):
    finhash = ''
    seed = str(seed)
    for idn in range(len(seed)):
        if seed[idn] == '1':
            if len(finhash) == 0:
                finhash = hashlib.md5(prehash.encode("UTF-8")).hexdigest()
            else:
                finhash = hashlib.md5(finhash.encode("UTF-8")).hexdigest()
        elif seed[idn] == '2':
            if len(finhash) == 0:
                finhash = hashlib.sha256(prehash.encode("UTF-8")).hexdigest()
            else:
                finhash = hashlib.sha256(finhash.encode("UTF-8")).hexdigest()
        elif seed[idn] == '3':
            if len(finhash) == 0:
                finhash = hashlib.sha384(prehash.encode("UTF-8")).hexdigest()
            else:
                finhash = hashlib.sha384(finhash.encode("UTF-8")).hexdigest()
        elif seed[idn] == '4':
            if len(finhash) == 0:
                finhash = hashlib.sha512(prehash.encode("UTF-8")).hexdigest()
            else:
                finhash = hashlib.sha512(finhash.encode("UTF-8")).hexdigest()
    return finhash


def sockDaemon():
    while True:
        sock0 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock0.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock0.bind(('0.0.0.0', 12022))
        sock0.listen(1)
        while True:
            try:
                conn, (rip, rport) = sock0.accept()
                avalon.subLevelTimeInfo('Client connected from ' + str(rip) + ':' + str(rport))
                recvd = conn.recv(1024).decode()
                if recvd.replace('\n', '') == PASSWD:
                    iptables.allow(rip)
                print(recvd)
                conn.close()
            except OSError:
                avalon.error('Socket port is being used!')
                sock0.close()
                avalon.info('Fail-Safe: Trying to reassign socket...')
                break
            except Exception as e:
                avalon.error('Socket: ' + str(e))
                sock0.close()
                avalon.info('Fail-Safe: Trying to reload socket daemon...')
            finally:
                conn.close()
                time.sleep(0.5)


def connectionWatchdog():
    while True:
        output = subprocess.Popen(['netstat', '-antp'], stdout=subprocess.PIPE).communicate()[0]
        output = output.decode()
        for addr in AUTHED_ADDR:
            if addr not in output:
                iptables.expire(addr)
        time.sleep(10)


def iptables_init():
    globalBlocked = False
    output = subprocess.Popen(['iptables', '-nL'], stdout=subprocess.PIPE).communicate()[0]
    output = output.decode().split('\n')
    for line in output:
        if 'dpt:1080' in line:
            globalBlocked = True
    if not globalBlocked:
        os.system('iptables -A INPUT -p tcp --dport 1080 -m conntrack --ctstate NEW,ESTABLISHED -j DROP')


iptables_init()
PASSWD = meha('hello', 1324132)
avalon.info('Service password is ' + PASSWD)
while True:
    try:
        sockDaemon()
    except Exception as e:
        avalon.error(str(e))
