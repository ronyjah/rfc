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
from commontestsetup1_1 import CommonTestSetup1_1
from sendmsgs import SendMsgs
from configsetup1_1 import ConfigSetup1_1

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test163a:

    def __init__(self,config):
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__local_addr_ceRouter =None
        self.__sendmsgs = SendMsgs(self.__config)
        self.__config_setup1_1 = ConfigSetup1_1(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','1.6.3a')
        

    def run(self):
        self.__packet_sniffer_wan = PacketSniffer('test163a',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        logging.info(self.__test_desc)
        while not self.__queue_wan.full():
            pkt = self.__queue_wan.get()
            logging.info(pkt.show())
            if not self.__config_setup1_1.get_setup1_1_OK():
                self.__config_setup1_1.run_setup1_1(pkt)
            
            if self.__config_setup1_1.get_ND_local_OK():
                if pkt.haslayer(DHCP6_Solicit):
                    self.__packet_sniffer_wan.stop()
                    while not self.__queue_wan.empty():
                        pkt = self.__queue_wan.get() 
                    return True
        # while not pkt.haslayer(IPv6):
        #     pkt = self.__queue_wan.get()      
        self.__packet_sniffer_wan.stop()
        return True
     
        