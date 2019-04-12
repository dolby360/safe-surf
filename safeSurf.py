from scapy.all import *
from multiprocessing import Process, Queue
from Black_list_analyzer import blackListAnalyze
import time
import socket
import fcntl
import struct
import sys
from requestDataHolder import reqDataHolder 
import netifaces

# disable verbose mode
conf.verb = 0

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
thisComputerIP = str(s.getsockname()[0])
s.close()
# thisComputerIP = socket.gethostbyname(socket.gethostname())
# print thisComputerIP

q = Queue()
_blackListAnalyze = blackListAnalyze()
p = Process(target=_blackListAnalyze.analyze_IP, args=(q,))
q_as_reducer = Queue()
p.start()

def reduceRedundantQuery(q_reducer):
        global q
        while True:
                collector = []
                while not q_reducer.empty():
                        enterElem = True
                        popped = q_reducer.get()
                        for i in range(0,len(collector)):
                                if popped.queryName == collector[i].queryName:
                                        enterElem = False
                                        break
                        if enterElem == True:                
                                collector.append(popped)
                        time.sleep(.300)
                for elem in collector:
                        q.put(elem)  
                time.sleep(.300)
                        
delayed_process = Process(target=reduceRedundantQuery,args=(q_as_reducer,))
delayed_process.start()

def ShowDns(pkt):
        global q_as_reducer
        """poison dns request, search.yahoo.com and www.google.com will be 192.168.1.108 """
        """ parse dns request / response packet """
        if pkt and pkt.haslayer('UDP') and pkt.haslayer('DNS'):
                try:
                        ip = pkt['IP']
                        eth = pkt['Ether']
                except:
                        return
                udp = pkt['UDP']
                dns = pkt['DNS']

        # dns query packet
        if int(udp.dport) == 53 and ip.src != thisComputerIP: 
                qname = dns.qd.qname
                domain = qname[:-1]
                t = strftime("%A,%d,%b,%Y,%H,%M,%S", gmtime()).split(',')

                dataHolder = reqDataHolder(sys.argv[1])
                dataHolder.ip_src = ip.src
                dataHolder.udp_src_port = udp.sport 
                dataHolder.ip_dst = ip.dst 
                dataHolder.udp_dst_port = udp.dport
                dataHolder.queryName = qname
                dataHolder.day_in_week = t[0]
                dataHolder.day_in_month = t[1]
                dataHolder.month = t[2]
                dataHolder.year = t[3]
                dataHolder.hour = t[4]
                dataHolder.minutes = t[5]
                dataHolder.seconde = t[6]
                dataHolder.computerName = socket.gethostbyaddr(ip.src)[0]
                dataHolder.MAC = eth.src
                q_as_reducer.put(dataHolder)

# This function never called 
# For debugging only
def dns_sniff(pkt):
    """ parse dns request / response packet """
    if pkt and pkt.haslayer('UDP') and pkt.haslayer('DNS'):
        ip = pkt['IP']
        udp = pkt['UDP']
        dns = pkt['DNS']

        # dns query packet
        if int(udp.dport) == 53:
                qname = dns.qd.qname

                print ("\n[*] request: %s:%d -> %s:%d : %s" % (
                ip.src, udp.sport, ip.dst, udp.dport, qname))

        # dns reply packet
        elif int(udp.sport) == 53:
                # dns DNSRR count (answer count)
                for i in range(dns.ancount):
                        dnsrr = dns.an[i]
                        print ("[*] response: %s:%s <- %s:%d : %s - %s" % (
                        ip.dst, udp.dport,
                        ip.src, udp.sport,
                        dnsrr.rrname, dnsrr.rdata))

def main():
        # capture dns request and response
        # sniff(filter="udp port 53", prn=dns_sniff)
        sniff(filter="udp port 53", prn=ShowDns)

if __name__ == "__main__":
        main()