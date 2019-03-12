from scapy.all import *
from multiprocessing import Process, Queue
from Black_list_analyzer import blackListAnalyze

# disable verbose mode
conf.verb = 0

q = Queue()
_blackListAnalyze = blackListAnalyze()
p = Process(target=_blackListAnalyze.analyze_IP, args=(q,))
p.start()

def ShowDns(pkt):
        global q
        """posion dns request, search.yahoo.com and www.google.com will be 192.168.1.108 """
        """ parse dns request / response packet """
        if pkt and pkt.haslayer('UDP') and pkt.haslayer('DNS'):
                try:
                        ip = pkt['IP']
                except:
                        return
                udp = pkt['UDP']
                dns = pkt['DNS']

        # dns query packet
        if int(udp.dport) == 53:
                qname = dns.qd.qname
                domain = qname[:-1]

                print("\n[*] request: %s:%d -> %s:%d : %s" % (ip.src, udp.sport, ip.dst, udp.dport, qname))
                q.put(qname)

                # # match posion domain (demo, maybe not explicit)
                # if domain.lower() in (posion_table.keys()):

                #         posion_ip = posion_table[domain]

                #         # send a response packet to (dns request src host)
                #         pkt_ip = IP(src=ip.dst,
                #                 dst=ip.src)

                #         pkt_udp = UDP(sport=udp.dport, dport=udp.sport)

                #         # if id is 0 (default value) ;; Warning: ID mismatch
                #         pkt_dns = DNS(id=dns.id,
                #               qr=1,
                #               qd=dns.qd,
                #               an=DNSRR(rrname=qname, rdata=posion_ip))

                #         print "[*] response: %s:%s <- %s:%d : %s - %s" % (
                #         pkt_ip.dst, pkt_udp.dport,
                #         pkt_ip.src, pkt_udp.sport,
                #         pkt_dns['DNS'].an.rrname,
                #         pkt_dns['DNS'].an.rdata)

                #         send(pkt_ip/pkt_udp/pkt_dns)


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