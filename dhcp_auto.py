import threading
import time
import re
from scapy.all import *
from scapy.layers.l2 import Ether
import binascii
from queue import Queue
import subprocess
 
DISCOVER_THREADS_NUM = 5
REQUEST_THREADS_NUM = 5
INTERFACE = "eno2"
 
dhcp_offer_queue = Queue()
mac_ip_queue = Queue()


def pingtest(ip):
    result = subprocess.run(['ping', '-c', '3', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode('utf-8')

    if '0 received'  in output:
        return True

class DhcpDiscoverThread(threading.Thread):
    def __init__(self, mac):
        super().__init__()
        self.mac = mac

    def run(self):
        xid = random.randint(0, 0xFFFFFFFF)
        srcmac=binascii.a2b_hex(self.mac.replace(":",""))
        #print("arcmac%s"%srcmac)
        options = binascii.a2b_hex("63825363")
        discover_pkt = Ether(dst = "FF:FF:FF:FF:FF:FF",src = srcmac)\
             /scapy.all.IP(tos = None,len = None,id = 1,flags = "",frag = 0,ttl = 64 ,proto = 17,chksum = None,src ="0.0.0.0",dst = "255.255.255.255")\
             /scapy.all.UDP(sport = 68,dport = 67,len = None,chksum = None)\
             /scapy.all.BOOTP(op = 1,xid = xid,htype = 1,hlen = 6,hops = 0,secs = 0,flags = "B",ciaddr = "0.0.0.0",yiaddr = "0.0.0.0",siaddr = "0.0.0.0",giaddr = "0.0.0.0",chaddr = srcmac,sname = "",file = "",options = options)\
             /scapy.all.DHCP(options=[("message-type","discover"),("client_id",b"\x01"+srcmac),("param_req_list",[1, 2, 3, 4, 5, 6, 12, 13, 15, 17, 18, 22, 23, 28, 40, 41, 42, 43, 50, 51, 54, 58, 59, 60, 66, 67, 97, 128, 129, 130, 131, 132, 133, 134, 135]),"end"])
        offers = []
        def offer_handler(pkt):
            #convert ascii mac-address to hex
            c_mac = pkt["BOOTP"].chaddr
            c_mac_hex = ":".join([binascii.hexlify(c_mac[i:i+1]).decode('utf-8') for i in range(0, 6)])
            if pkt.getlayer("DHCP").options[0][1] == 2 and c_mac_hex.startswith("00:11"):
                offers.append(pkt)
                #print("already received offer from test mac %s" % c_mac_hex)
        #print("start to send discover...")
        sendp(discover_pkt, iface=INTERFACE ,verbose=False)
        sniff(prn=offer_handler, iface=INTERFACE, filter="udp and (port 67 or port 68)", timeout=10)
        dhcp_offer_queue.put(offers)
 
def start_dhcp_discover_threads(mac_addresses):
    threads = []
    count = 0
    
    for mac in mac_addresses:
        thread = DhcpDiscoverThread(mac)
        thread.start()
        threads.append(thread)
        count += 1
        if count % DISCOVER_THREADS_NUM == 0 or count == len(mac_addresses):
            for t in threads:
                t.join()
            threads = []
            offers = []
            while not dhcp_offer_queue.empty():
                offers += dhcp_offer_queue.get()
            for offer in offers:
                requested_ip = offer["BOOTP"].yiaddr
                client_mac = offer["BOOTP"].chaddr
                #convert ascii mac-address to hex
                client_mac_hex = ":".join([binascii.hexlify(client_mac[i:i+1]).decode('utf-8') for i in range(0, 6)])
                if pingtest(requested_ip):
                    print("############ available ip ##########")
                    print (requested_ip, client_mac_hex)
        # dhcp_offer_queue = queue.Queue()
        time.sleep(10)
            

            
# def start_dhcp_request_threads(offers):
#     # print(6666666666)
#     # print(offers)
#     threads = []
#     count = 0
#     mac_ip_list = []
#     for offer in offers:
#         xid = offer["BOOTP"].xid
#         dhcp_server_ip = offer["BOOTP"].siaddr
#         requested_ip = offer["BOOTP"].yiaddr
#         mac_address = offer["BOOTP"].chaddr
#         mac_ip_list.append((requested_ip, dhcp_server_ip, xid, mac_address))
#     mac_ip_list=list(set(mac_ip_list))
#     #print(mac_ip_list)
#     for mac in mac_ip_list:
#          print (requested_ip)
#          thread = DhcpRequestThread(mac)
#          thread.start()
#          threads.append(thread)
#          count += 1
#          if count % REQUEST_THREADS_NUM == 0 or count == len(mac_addresses):
#             for t in threads:
#                 t.join()
#             threads = []

# class DhcpRequestThread(threading.Thread):
#     def __init__(self,mac):
#         super().__init__()
#         self.requestip=mac[0]
#         self.dhcpserver=mac[1]
#         self.xid=mac[2]
#         self.srcmac=mac[3]
    
#     def run(self):
#         src_mac = ":".join([binascii.hexlify(self.srcmac[i:i+1]).decode() for i in range(0, 6)])
#         # formatted_mac = ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))
#         # srcmac=binascii.a2b_hex(self.srcmac.replace(":",""))
#         options = binascii.a2b_hex("63825363")
#         srcmac=binascii.a2b_hex(src_mac.replace(":",""))
#         # print("testest%s"%srcmac)
#         pkt_dhcp_quest = Ether(dst = "FF:FF:FF:FF:FF:FF",src = src_mac)\
#                          /scapy.all.IP(tos = None,len = None,id = 1,flags = "",frag = 0,ttl = 64 ,proto = 17,chksum = None,src ="0.0.0.0",dst = "255.255.255.255")\
#                          /scapy.all.UDP(sport = 68,dport = 67,len = None,chksum = None)\
#                          /scapy.all.BOOTP(op = 1,htype = 1,hlen = 6,hops = 0,xid =  self.xid,secs = 0,flags = "B",ciaddr = "0.0.0.0",yiaddr = "0.0.0.0",siaddr = "0.0.0.0",giaddr = "0.0.0.0",chaddr = self.srcmac,sname = "",file = "",options = options)\
#                          /scapy.all.DHCP(options=[("message-type","request"),("client_id",b"\x01"+ srcmac),("requested_addr",self.requestip),("server_id",self.dhcpserver),("param_req_list",[1, 2, 3, 6, 12, 15, 26, 28, 40, 41, 42, 119, 121]),"end"])
#         sendp(pkt_dhcp_quest,iface=INTERFACE,verbose=False)


if __name__ == "__main__":
    print("***Please wait quietly for an available IP address to appear...***")
    mac_addresses = []
    for i in range(50):
        mac_address = "{:012x}".format(int("001122334455", 16) + 1 * i)
        mac_address = re.sub("(.{2})", "\\1:", mac_address, 0)[:-1]
        mac_addresses.append(mac_address)
    #print(mac_addresses)
 
    offers = start_dhcp_discover_threads(mac_addresses)
    #print(offers)
    #start_dhcp_request_threads(offers)

