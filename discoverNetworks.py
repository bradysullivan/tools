from _winreg import *

def printNets():
    net = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"+\
            "\NetworkList\Signatures\Unmanaged"
    key = OpenKey(HKEY_LOCAL_MACHINE, net)
    print '\n[*] Networks That Have Been Joined'
    for i in range(100):
        try:
            guid = EnumKey(key, i)
            netKey = OpenKey(key, str(guid))
            (n, addr, t) = EnumValue(netKey, 5)
            (n, name, t) = EnumValue(netKey, 4)
            macAddr = hex2mac(addr)
            netName = str(name)
            print '[+] ' + netName + ' ' + macAddr
            CloseKey(netKey)
        except:
            break

def hex2mac(val):
    addr = ""
    for ch in val:
        addr += ("%02x " % ord(ch))
    addr = addr.strip(' ').replace(' ', ':')[0:17]
    return addr

def main():
    printNets()

if __name__ == "__main__":
    main()

