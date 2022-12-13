import warnings
warnings.filterwarnings("ignore")
with warnings.catch_warnings():
    warnings.simplefilter("ignore", category=DeprecationWarning)
    import scapy.all as scapy
    import multiprocessing
    import socket
    import numpy as np
    from iterator_proto import get_ips
    import subprocess
    from getmac import get_mac_address as gma
    import re
    import json
    from OuiLookup import OuiLookup
    import datetime
    import sys
    import time


scapy.conf.layers.filter([scapy.Ether, scapy.ARP])


class Scanner:
    def __init__(self, options):
        self.__ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        today = datetime.datetime.now()
        self.__session = f"{today.year}_{today.month}_{today.day}"

        self.options = options

    def generate_packets(self, **kwargs):
        ips = get_ips(kwargs['address'])
        packets = list(map(lambda ip: self.__ether / scapy.ARP(pdst=ip), ips))
        return packets

    def extract_data(self, result):
        for sent, received in result:
            information = {'ip': received.psrc, 'mac': received.hwsrc, 'hostname': None, 'device_distributor': 'Unknown'}
            try:
                if self.options['verbose']:
                    information['device_distributor'] = list(OuiLookup().query(information['mac'])[0].values())[0]
                    information['hostname'] = socket.gethostbyaddr(received.psrc)[0]
                else:
                    information['device_distributor'] = ""
                    information['hostname'] = ""

            except socket.herror:
                information['hostname'] = "NaN"
            return information

    def get_response(self, packet):
        result = scapy.srp(packet, timeout=1, verbose=0)[0]
        return self.extract_data(result)

    def generate_responses(self, packets):
        print("Generating responses...")
        start = time.time()
        pool = multiprocessing.Pool(processes=20)
        responses = list(pool.map(self.get_response, packets))
        end = time.time()
        print(f"Finished in {end-start} seconds.")
        return list(filter(lambda x: x is not None, responses))

    def write_file(self, information, network):
        with open(f"logs/{network.split('/')[0]}_{self.__session}.json", 'w') as f:
            f.write(json.dumps(information) + "\n")

    def format_data(self, information, **kwargs):
        if kwargs['save']:
            self.write_file(information, kwargs['address'])
        print(f"{'IP':<15}{'MAC':<22}{'Hostname':<30}{'Distributor'}")
        for host in information:
            print(f"{host['ip']:<15}{host['mac']:<22}{host['hostname']:<30}{host['device_distributor']}")

    def main(self):
        information = self.generate_responses(self.generate_packets(**self.options))
        self.format_data(information, **self.options)




    
