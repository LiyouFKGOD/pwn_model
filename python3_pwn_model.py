#coding:utf-8 
a = '''
██╗     ██████╗      ██╗   ██╗     ██████╗     ██╗    ██╗
██║       ██╔═╝      ╚██╗ ██╔╝   ██╔═════██║   ██║    ██║
██║       ██║         ╚████╔╝    ██║     ██║   ██║    ██║
██║       ██║          ╚██╔╝     ██║     ██║   ██║    ██║
██████╗ ██████╗         ██║       ╚██████╔═╝    ╚██████╔╝
╚═════╝ ╚═════╝         ╚═╝        ╚═════╝       ╚═════╝        V1.0 
    
       ██╗
    ████████╗
       ██╔══╝     作者：李由
       ██║        使用方法：修改pwn1为自己的程序，远程调试地址是IP:PORT，调试远程直接使用python3 xxx.py REMOTE即可
       ╚═╝
    '''
print('\033[1;31;31m''{0}'.format(a))

from pwn import *
import string
import sys,os
from LibcSearcher import LibcSearcher

realchange = str()

def IPportandprocess(pro,ipport='',libcis=''):
    elf = ELF('{0}'.format(pro))
    if args['REMOTE']:
        ip,port="{0}".format(ipport).split(":")
        p = remote(ip,int(port))
    else:
        p = process('{0}'.format(pro))
    if '' in libcis:
        libcis = elf.libc
    else:
        libcis = ELF('{0}'.format(libcis))
    return fileX86orX64(pro),p,elf,libcis

def fileX86orX64(pro): 
    oreal=os.popen('file {0}'.format(pro)).read()
    if '32-bit' in oreal:
        realchange = 1
    else:
        realchange = 2
    return realchange

def pld(*payload):
    global realchange
    if realchange == 1:
        return eval('flat({0})'.format([x for x in payload]))
    else:
        return eval('flat({0},arch=\'amd64\')'.format([x for x in payload]))

def debugg():
    global realchange
    print("是否开启debug模式?:1、YES  2、NO\n")
    debugis = input()
    try:
        if int(debugis) == 1 and int(realchange) == 1:
            return context(arch = 'i386',os = 'linux',log_level ='DEBUG',terminal=['gnome-terminal','-x','sh','-c'])
        elif int(debugis) == 1 and int(realchange) == 2:
            return context(arch = 'amd64', os = 'linux', log_level = 'DEBUG',terminal=['gnome-terminal','-x','sh','-c'])
        else:
            context(terminal=['gnome-terminal','-x','sh','-c'])
            pass
    except:
        print("输入有误，请重新输入：\n")
        debugg()

def fmtfuck(number,addr,addrvalue):
    return fmtstr_payload(number, {addr: addrvalue})
    #number偏移量，addr需要修改的地址，addrvalue需要修改的值



sd      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sda     = lambda delim,data         :p.sendafter(delim, data)
rcn     = lambda numb=4096          :p.recv(numb, timeout = 3)
rl      = lambda                    :p.recvline()
ru      = lambda delims			    :p.recvuntil(delims)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
li      = lambda tag, addr          :log.info(tag + ': {:#x}'.format(addr))
ls      = lambda tag, addr          :log.success(tag + ': {:#x}'.format(addr))
lsh     = lambda tag, addr          :LibcSearcher(tag, addr)
interactive = lambda                :p.interactive()
printf  = lambda index              :success(hex(index))
getadd  = lambda                    :u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))


if __name__ == "__main__":
    realchange,p,elf,libc = IPportandprocess('./pwn1',ipport='pwn.challenge.ctf.show:28156',libcis='')
    debugg()
    #leak = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
    #key_addr = 0x0804a048
    #key_value = 35795746
    #sd(pld(fmtfuck(12,key_addr,key_value)))
    
    
    interactive()
    



    
