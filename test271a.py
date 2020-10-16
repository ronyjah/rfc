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
from configsetup1_1_lan import ConfigSetup1_1_Lan
format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")

class Test271a:

    def __init__(self,config):
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__local_addr_ceRouter =None
        self.__sendmsgs = SendMsgs(self.__config)
        self.__config_setup1_1 = ConfigSetup1_1(self.__config)
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__lan_device = self.__config.get('lan','lan_device')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','2.7.1a')
        self.__t_lan = None
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)


    def runLan():
        self.__config_setup_lan_.flags_partA()
        logging.info('Thread da LAN')
        t_test = 0
        sent_reconfigure = False
        time_over = False
        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_lan.get()

            if not self.__config_setup_lan.get_setup_OK():
                if not self.__config_setup_lan.get_disapproved():
                    self.__config_setup_lan.run_setup1_1(pkt)
                else:
                    logging.info('Reprovado Teste 2.7.1.a - Falha em completar o Common Setup 1.1 da RFC')
                    self.__packet_sniffer_wan.stop() 
                    return False       

    def run(self):
        self.__t_lan =  Thread(target=self.run_lan,setName='LAN_Thread')
        self.__t_lan.start()
        
        self.__packet_sniffer_wan = PacketSniffer('Test271a-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test271a-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        self.__packet_sniffer_lan.start()
        
        self.__config_setup1_1.flags_partA()
        logging.info(self.__test_desc)
        t_test = 0
        sent_reconfigure = False
        time_over = False
        while not self.__queue_wan.full():
            while self.__queue_wan.empty():
                if t_test < 60:
                    time.sleep(1)
                    t_test = t_test + 1
                else:
                    time_over = True
            pkt = self.__queue_wan.get()

            if not self.__config_setup1_1.get_setup1_1_OK():

                if not self.__config_setup1_1.get_disapproved():
                    self.__config_setup1_1.run_setup1_1(pkt)
                else:
                    logging.info('Reprovado Teste 2.7.1.a - Falha em completar o Common Setup 1.1 da RFC')
                    self.__packet_sniffer_wan.stop() 
                    return False

            else: 


                if pkt.haslayer(DHCP6_Renew):
                    logging.info(pkt.show())
                    logging.info('Reprovado Teste 2.7.1.d - Respondeu ao DHCP6 reconfigure de chave falsa')

                    self.__packet_sniffer_wan.stop()
                    return False
                elif time_over :
                    if not sent_reconfigure:
                        self.__packet_sniffer_wan.stop()
                        logging.info('Falha: Teste 2.7.1.a. Tempo finalizado mas Não Enviou DHCP Reconfigure')

                        return False
                    else:
                        self.__packet_sniffer_wan.stop() 
                        logging.info('Aprovado: Teste 2.7.1.a. Tempo finalizado e não recebeu DHCP Renew em DHCP Reconf adulterado')

                        return True
                if not sent_reconfigure:

                    self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                    self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','dhcp_relay_agents_and_servers_addr'))
                    self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
                    self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_ether_dst())
                    self.__config_setup1_1.set_dhcp_reconf_type(self.__config.get('t2.7.1','msg_type'))
                    self.__sendmsgs.send_dhcp_reconfigure_wrong(self.__config_setup1_1)
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
     
        