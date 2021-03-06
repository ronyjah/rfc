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
import pdb

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test163b:

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
        self.__test_desc = self.__config.get('tests','1.6.3b')


    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.3','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.3','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.3','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.3','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.3','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.3','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.3','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t1.6.3','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t1.6.3','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t1.6.3','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.3','intervalo'))

    def run(self):
        self.__packet_sniffer_wan = PacketSniffer('test163b',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__config_setup1_1.flags_partA()
        self.__packet_sniffer_wan.start()
        self.set_flags()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False

        time_over = False        
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 3000:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_wan.get()
           
            if not self.__config_setup1_1.get_setup1_1_OK():

                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                    print('aqui')
                else:
                    print('aqui1')
                    self.__packet_sniffer_wan.stop() 
                    logging.info('Reprovado Teste 1.6.3.c - Falha em completar o Common Setup 1.1 da RFC')
                    return False

                #self.__config_setup1_1.run_setup1_1(pkt)
            else:
                

                # self.__config_setup1_1.set_xid()
                if pkt.haslayer(DHCP6_Renew):
                    print('aqui2')
                    logging.info(pkt.show())
                    print('aqui3')
                    self.__packet_sniffer_wan.stop()
                    print('aqui33333')
                    
                    logging.info('Aprovado: Teste 1.6.3.b.')
                    return True

                elif time_over :
                    print('aqui4')
                    if not sent_reconfigure:
                        print('aqui5')
                        pass
                        #self.__packet_sniffer_wan.stop()
                        logging.info('Falha: Teste 1.6.3.b. Tempo finalizado e Não Enviou DHCP Reconfigure')
                        return False
                    else:
                        print('aqui6')
                        self.__packet_sniffer_wan.stop()
                        logging.info('Reprovado: Teste 1.6.3.b. Tempo finalizado e Não recebeu DHCP6 Renew')

                        return False

                if not sent_reconfigure:
                    time.sleep(3)
                    print('aqui7')
                    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                    print('aqui8')
                    self.__config_setup1_1.set_ipv6_dst(self.__config_setup1_1.get_local_addr_ceRouter())
                    print('aqui10')
                    self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
                    print('aqui11')
                    self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_mac_ceRouter())
                    print('aqui12')
                    self.__config_setup1_1.set_dhcp_reconf_type(self.__config.get('t1.6.3','msg_type'))
                    print('aqui13')
                    self.__config_setup1_1.set_udp_sport('547')
                    self.__config_setup1_1.set_udp_dport('546')
                    self.__sendmsgs.send_dhcp_reconfigure(self.__config_setup1_1)
                    print('aqui14')
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
     
        