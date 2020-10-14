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

class Test163d:

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
        self.__test_desc = self.__config.get('tests','1.6.3d')

    def run(self):
        self.__packet_sniffer_wan = PacketSniffer('test163d',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        while not self.__queue_wan.full():
            #print('1')
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_wan.get()
            print(self.__config_setup1_1.get_setup1_1_OK())
            if not self.__config_setup1_1.get_setup1_1_OK():

                self.__config_setup1_1.run_setup1_1(pkt)

            if self.__config_setup1_1.get_setup1_1_OK():
                self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','dhcp_relay_agents_and_servers_addr'))
                self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
                self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_ether_dst())
                self.__config_setup1_1.set_dhcp_reconf_type(self.__config.get('t1.6.3','msg_type'))

                if pkt.haslayer(DHCP6_Renew):
                    logging.info(pkt.show())
                    return False
                elif time_over:
                    return True

                if not sent_reconfigure:

                    self.__sendmsgs.send_dhcp_reconfigure_no_auth(self.__config_setup1_1)

                    sent_reconfigure = True
            

                # if pkt.haslayer(DHCP6_Solicit):
                #     self.__packet_sniffer_wan.stop()
                #     while not self.__queue_wan.empty():
                #         pkt = self.__queue_wan.get() 
                #     return True
        # while not pkt.haslayer(IPv6):
        #     pkt = self.__queue_wan.get()      
        self.__packet_sniffer_wan.stop()
        return False
     
        