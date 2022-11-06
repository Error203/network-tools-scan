import socket
import qlogger
import netifaces
import sys
from scapy.all import conf


class IPAddressResolver:
	def __init__(self, verbose=False):
		self.logger = qlogger.Logger(level="debug" if verbose else "info", file_stream=False).get_logger("ip_address_resolver")


	def resolve_ip(self, interface=None):
		if not interface:
			self.logger.debug(f"machine's ip address: {conf.iface.ip}")
			return conf.iface.ip

		else:
			try:
				self.logger.debug(f"machine's ip address: {conf.ifaces[interface].ip}")
				return conf.ifaces[interface].ip

			except Exception as e:
				self.logger.error("failed to resolve machine's ip address")
				self.logger.exception(e)
				sys.exit()


	def resolve_gateway(self, interface=None):
		try:
			self.logger.debug(f"gateway's ip address: {netifaces.gateways()['default'][2][0]}")
			return netifaces.gateways()["default"][2][0]

		except Exception as e:
			self.logger.error("failed to resolve gateway's ip address")
			self.logger.exception(e)
			sys.exit()


if __name__ == '__main__':
	ipaddrres = IPAddressResolver(verbose=True)
	ipaddrres.resolve_ip("eth0")
	ipaddrres.resolve_gateway("eth0")
