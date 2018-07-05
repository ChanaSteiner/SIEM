from scapy.all import *
from datetime import datetime

"""def get_interfaces():
#returns a list of available network interfaces
    interfaces = []
    for iface_name in sorted(ifaces.data.keys()):
        dev = ifaces.data[iface_name]

        i = name=str(dev.name).ljust(4)

        interfaces.append(i)
    return interfaces"""

def PacketsToLog(pkt):
    pkt_time = str(datetime.now()).split(',')[0]
    print '{} {} {} {} {}' .format(pkt_time,
                                pkt [IP].src,
                                pkt[IP].dst,
                                pkt[TCP].dport,
                                "PASS")


def Sniffa():
    sniff(iface='Intel(R) Centrino(R) Advanced-N 6205',
          prn= PacketsToLog,
          lfilter=lambda pkt:IP in pkt and TCP in pkt)
Sniffa()



#def main():
    #print get_interfaces()

#if __name__ == '__main__':
   # main()