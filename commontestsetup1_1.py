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

class CommonTestSetup1_1:

    def __init__(self,config):
        #self.self_testing = self
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        logging.info('self.__queue_size_inicio162')
        logging.info(self.__queue_wan.qsize())
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__valid = False
        self.__result = None
        self.__device_lan_tn1 = None
        self.__lan_mac_tn1 = None
        self.__ceRouter_mac_addr = None
        self.__flag_M = 1
        self.__flag_O = 0
        self.__flag_chlim = 64
        self.__flag_L = 1
        self.__flag_A = 0
        self.__flag_R = 0
        self.__validlifetime = 600
        self.__preferredlifetime = 600
        self.__interval = 1
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__global_addr = self.__config.get('wan','global_addr')
        self.__test_desc = self.__config.get('tests','1.6.2')


    def set_flags_common_setup(self,test_flags):
        self.__flag_M = test_flags.get_flag_M()
        self.__flag_O = test_flags.get_flag_O()
        self.__flag_chlim = test_flags.get_flag_chlim()
        self.__flag_L = test_flags.get_flag_L()
        self.__flag_A = test_flags.get_flag_A()
        self.__flag_R = test_flags.get_flag_R()
        self.__validlifetime = test_flags.get_validlifetime()
        self.__preferredlifetime = test_flags.get_preferredlifetime()
        self.__routerlifetime = test_flags.get_routerlifetime()
        self.__intervalo = test_flags.get_interval()

# TR1 transmits a Router Advertisement to the all-nodes multicast address with the M and O Flag
    def send_tr1_RA(self):
        tr1_et = Ether(src=self.__wan_mac_tr1)
        tr1_ip = IPv6(src=self.__link_local_addr,\
                      dst=self.__all_nodes_addr)
        tr1_rs = ICMPv6ND_RA(M=self.__flag_M,\
                            O=self.__flag_O,\
                            routerlifetime=self.__routerlifetime,\
                            chlim=self.__flag_chlim)
        tr1_pd = ICMPv6NDOptPrefixInfo(L=self.__flag_L,\
                                        A=self.__flag_A,\
                                        R=self.__flag_R,\
                                        validlifetime=self.__validlifetime,\
                                        preferredlifetime=self.__preferredlifetime,\
                                        prefix=self.__global_addr)
        sendp(tr1_et/tr1_ip/tr1_rs/tr1_pd,iface=self.__wan_device_tr1)