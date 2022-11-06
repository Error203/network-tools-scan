import socket
import ip_address_resolver
import lxml
import requests
from scapy.all import IP, ICMP, TCP, sr1
from bs4 import BeautifulSoup

class SSDPScanner:


	def __init__(self, interface=None, verbose=False):
		ipaddrres = ip_address_resolver.IPAddressResolver(verbose="debug" if verbose else "info")
		self.machine_ip = ipaddrres.resolve_ip(interface)
		self.gateway_ip = ipaddrres.resolve_gateway(interface)


	def scan_broadcast(self):
		if self.check_ssdp_port():
			header = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\nMX: 2\r\nMAN:\"ssdp:discover\"\r\n\r\n"
			responses = list()
			client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			client.settimeout(2)
			client.bind((self.machine_ip, 9876))
			client.sendto(bytes(header, "utf-8"), (self.gateway_ip, 1900))
			while True:
				try:
					buff = client.recvfrom(60000)[0]
					if buff:
						responses.append(buff.decode())
				except TimeoutError:
					if responses:
						del(buff)
						print("packets received")
					else:
						print("timed out without response")
					break

			xml_page = requests.get(self.handle_response(responses)).content.decode()
			self.extract_from_xml(xml_page)


	def handle_response(self, responses):
		for response in responses:
			for line in response.split("\r\n"):
				if line[0:8] == "LOCATION":
					location = line[10:]
				if line[0:2] == "ST":
					if line[4:].lower() == "upnp:rootdevice":
						return location
						


	def extract_from_xml(self, input_data):
		bs = BeautifulSoup(input_data, "xml")
		print("\r\n----- ROUTER DATA -----")
		print("router name: " + bs.find("friendlyName").text)
		print("model name: " + bs.find("modelName").text)
		print("model number: " + bs.find("modelNumber").text)
		print("URL to control panel: " + bs.find("presentationURL").text)
		print("manufacturer: " + bs.find("manufacturer").text)
		print("serial number: " + bs.find("serialNumber").text)
		print("----- THE END -----\r\n")


	def check_ssdp_port(self):
		resp = sr1(IP(dst=self.gateway_ip) / TCP(dport=1900, flags="S"), timeout=1, verbose=0,)

		if resp is None:
			print("SSDP port 1900 is filtered")

			return False

		elif resp.haslayer(TCP):
			if resp[TCP].flags == 0x12:
				send_rst = sr1(IP(dst=self.gateway_ip) / TCP(dport=1900, flags="R"), timeout=1, verbose=0,) # sending close connection

				return True
			
			elif resp[TCP].flags == 0x14:
				print("SSDP port 1900 is closed")

				return False

		elif resp.haslayer(ICMP):
			if (int(resp[ICMP].type) == 3 and int(resp[ICMP].code) in [1, 2, 3, 9, 10, 13]):
				print("SSDP port 1900 is filtered")

				return False


if __name__ == '__main__':
	ssdpscanner = SSDPScanner(interface="eth0", verbose=True)
	ssdpscanner.scan_broadcast()
