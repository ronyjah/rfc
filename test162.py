import logging
import logging.config
import logging.handlers
from configparser import ConfigParser
from threading import Thread
from subprocess import call
import sys
import argparse
from scapy.all import *
from config import Config
import time
from packetsniffer import PacketSniffer

# - Seleciona a interface
# - recebe thread de captura das mensagens já iniciada na main
# - inicia a captura
# - recebe o pacote e armazena numa lista
# - analisa o pacote recebido e armazenado na lista
# - 

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")


class Test162:

    def __init__(self,config):
        self.__queue = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__valid = False
        self.__result = None
        self.__device_lan_tn1 = None
        self.__lan_mac_tn1 = None
 
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('multicast','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','1.6.2')
        self.__packet_sniffer = PacketSniffer(self.__queue,self,self.__config)
        self.__packet_sniffer.daemon=True
        self.__packet_sniffer.start()

    #recebe o pacote
    #packetSniffer return pkt


    def set_result(self, valor):
        self.__result = valor
        
    def get_result(self):
        return self.__result

    def send_icmpv6_ra(self,pkt):
        et = Ether(src=self.__wan_mac_tr1)#,\
                   #dst=pkt[Ether].src)
        ip = IPv6(src=self.__link_local_addr,\
                  dst=self.__all_nodes_addr)
        icmp_ra = ICMPv6ND_RA()
        sendp(et/ip/icmp_ra,iface=self.__wan_device_tr1)

    def run(self):
        
        logging.info(self.__test_desc)
        logging.info(self.__queue.qsize())
        while not self.__queue.full():
            pkt = self.__queue.get()
            if pkt.haslayer(ICMPv6ND_RS):
                self.send_icmpv6_ra(pkt)
                #self.__valid = True
            #elif pkt.haslayer(ICMPv6ND_RA) and self.__valid == False:
                #print('theardoffFalse')
                #self.turn_off_thread()
             #   return False
            #else:
                
                #print('theardofftrue')
                #self.turn_off_thread()
             #   return True
        