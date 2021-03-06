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

class Test277c:

    def __init__(self,config):
        self.__queue_wan = Queue()
        self.__queue_lan = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__local_addr_ceRouter =None
        self.__sendmsgs = SendMsgs(self.__config)
        self.__config_setup1_1 = ConfigSetup1_1(self.__config)
        #self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__lan_device = self.__config.get('lan','lan_device')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','2.7.7c')
        self.__t_lan = None
        self.__finish_wan = False
        self.__dhcp_renew_done = False
        self.__config_setup_lan = ConfigSetup1_1_Lan(self.__config,self.__lan_device)



    def set_flags(self):
        self.__config_setup1_1.set_flag_M(self.__config.get('t1.6.6b','flag_m'))
        self.__config_setup1_1.set_flag_0(self.__config.get('t1.6.6b','flag_o'))
        self.__config_setup1_1.set_flag_chlim(self.__config.get('t1.6.6b','flag_chlim'))
        self.__config_setup1_1.set_flag_L(self.__config.get('t1.6.6b','flag_l'))
        self.__config_setup1_1.set_flag_A(self.__config.get('t1.6.6b','flag_a'))
        self.__config_setup1_1.set_flag_R(self.__config.get('t1.6.6b','flag_r'))
        self.__config_setup1_1.set_flag_prf(self.__config.get('t1.6.6b','flag_prf'))
        self.__config_setup1_1.set_validlifetime(self.__config.get('t2.7.7c','validlifetime'))
        self.__config_setup1_1.set_preferredlifetime(self.__config.get('t2.7.7c','preferredlifetime'))
        self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.7c','routerlifetime'))
        self.__config_setup1_1.set_intervalo(self.__config.get('t1.6.6b','intervalo'))
        self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
        self.__config_setup1_1.set_dhcp_t1(self.__config.get('t2.7.7c','dhcp_t1'))
        self.__config_setup1_1.set_dhcp_t2(self.__config.get('t2.7.7c','dhcp_t2'))
        self.__config_setup1_1.set_dhcp_preflft(self.__config.get('t2.7.7c','dhcp_preflft'))
        self.__config_setup1_1.set_dhcp_validlft(self.__config.get('t2.7.7c','dhcp_validlft'))
        self.__config_setup1_1.set_dhcp_plen(self.__config.get('t2.7.7c','dhcp_plen'))
   
    def set_flags_lan(self):
        self.__config_setup_lan.set_elapsetime(self.__config.get('solicitlan','elapsetime'))
        self.__config_setup_lan.set_xid(self.__config.get('solicitlan','xid'))
        self.__config_setup_lan.set_fdqn(self.__config.get('solicitlan','clientfqdn'))
        self.__config_setup_lan.set_vendor_class(self.__config.get('solicitlan','vendorclass'))

        self.__config_setup_lan.set_enterprise(self.__config.get('solicitlan','enterpriseid'))
        self.__config_setup_lan.set_client_duid(self.__config.get('solicitlan','duid'))
        self.__config_setup_lan.set_iaid(self.__config.get('solicitlan','iaid'))

        
    def run_Lan(self):
        #self.__config_setup_lan_.flags_partA()
        logging.info('Thread da LAN inicio')
        t_test = 0
        t_test1= 0
        sent_reconfigure = False
        time_over = False
        send_ra = False
        send_na_lan = False
        self.set_flags_lan()
        self.__config_setup_lan.set_setup_lan_start()
        while not self.__queue_lan.full():
            while self.__queue_lan.empty():
                if t_test1 < 120:
                    time.sleep(1)
                    t_test1 = t_test1 + 1
                    if pkt.haslayer(ICMPv6ND_RA):
                        self.__routerlifetime_CeRouter = pkt[ICMPv6ND_RA].routerlifetime
                        if pkt.haslayer(ICMPv6NDOptPrefixInfo):
                            self.__prefixaddr_ula_CeRouter = pkt[ICMPv6NDOptPrefixInfo].prefix
                            if self.__prefixaddr_ula_CeRouter == self.__config.get('t2.7.7c','prefix_ula'):
                                logging.info(' Teste 2.7.7c: Recebido o prefix ULA esperado.')
                                logging.info('Aprovado Teste2.7.7c.')
                                self.__packet_sniffer_lan.stop()
                                self.__finish_wan = True
                                self.__fail_test = False 
                                return True  
                else:
                    logging.info(' Teste2.7.7c: Prefix ULA Não recebido no tempo de teste')
                    #logging.info(routerlifetime)
                    self.__packet_sniffer_lan.stop()
                    self.__finish_wan = True 
                    self.__fail_test = True
                    return False



#                 logging.info('Thread da LAN time')
#                 time.sleep(1)
                
#                 if self.__config_setup1_1.get_setup1_1_OK():
#                     logging.info('Thread da WAN DONE')
# #                    t_test = t_test + 1
#  #                   if self.__config_setup1_1.get_recvd_dhcp_renew():
#                 #pkt = self.__queue_lan.get()
#                     if t_test < 80:
#                         time.sleep(1)
#                         t_test = t_test + 1
#                         if t_test % 5 ==0:
#                             print('ENVIO RS - 1 LAN')
#                             #self.__config_setup_lan.set_setup_lan_start()
#                             self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
#                             self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
#                             self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
#                             self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
#                             self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
#                             self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)

                        
#                             if self.__config_setup_lan.get_ND_global_OK() and not self.__config_setup_lan.get_global_ping_OK():
#                                 print('ENVIO REQUEST 1 LAN')
#                                 mac_global = self.__config_setup_lan.get_global_mac_ceRouter()
#                                 ip_global = self.__config_setup_lan.get_global_addr_ceRouter()
#                                 self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
#                                 self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
#                                 self.__config_setup_lan.set_ether_dst(mac_global)
#                                 self.__config_setup_lan.set_ipv6_dst(ip_global)
#                                 self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)


#                             #self.__config_setup_lan.set_setup_lan_start()
#                             print('PRINT ENVIO INFORMATION LAN')
#                             self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
#                             self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
#                             self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
#                             self.__config_setup_lan.set_ipv6_dst(self.__config.get('multicast','all_routers_addr'))
#                             self.__config_setup_lan.set_xid(self.__config.get('informationlan','xid'))
#                             #self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
#                             self.__config_setup_lan.set_elapsetime(self.__config.get('informationlan','elapsetime'))
#                             self.__config_setup_lan.set_vendor_class(self.__config.get('informationlan','vendorclass'))
#                             self.__sendmsgs.send_dhcp_information(self.__config_setup_lan)
#                     else: time_over = True

#             pkt = self.__queue_lan.get()
#             if not self.__config_setup_lan.get_global_ping_OK():
#                 print('LOOP PRINCIPAL')
#                 if not self.__config_setup_lan.get_disapproved():
#                     self.__config_setup_lan.run_setup1_1(pkt)
#                 else:
#                     logging.info('Reprovado Teste 2.7.7c - Falha em completar o Common Setup 1.1 da RFC')
#                     self.__packet_sniffer_lan.stop()
#                     self.__finish_wan = True 
#                     return False       
#             else:



                        # self.__l_CeRouter = pkt[ICMPv6NDOptPrefixInfo].L
                        # self.__A_CeRouter = pkt[ICMPv6NDOptPrefixInfo].A
                        # self.__R_CeRouter = pkt[ICMPv6NDOptPrefixInfo].R
                        # self.__validlifetime_CeRouter = pkt[ICMPv6NDOptPrefixInfo].validlifetime
                        # self.__preferredlifetime_CeRouter = pkt[ICMPv6NDOptPrefixInfo].preferredlifetime
                        # self.__prefixlen_CeRouter = pkt[ICMPv6NDOptPrefixInfo].prefixlen
                        # self.send_solicit = True
                        # self.__setup1_1_OK = True
                        #return
                    # print('CHegou RA na LAN')
                    # if pkt.haslayer(ICMPv6NDOptRouteInfo):
                    #     self.__r_prefixaddr_CeRouter = pkt[ICMPv6NDOptRouteInfo].prefix
                    #     self.__r_plen_CeRouter = pkt[ICMPv6NDOptRouteInfo].plen
                    #     self.__r_prf_CeRouter = pkt[ICMPv6NDOptRouteInfo].prf
                    #     self.__r_rtlifetime_CeRouter = pkt[ICMPv6NDOptRouteInfo].rtlifetime

                    # if pkt.haslayer(ICMPv6NDOptRDNSS):
                    #     self.__rdnss_dns_CeRouter = pkt[ICMPv6NDOptRDNSS].dns
                    #     self.__rdnss_lifetime_CeRouter = pkt[ICMPv6NDOptRDNSS].lifetime
                    #     self.__recvd_dhcp_rdnss = True
        
                    # if pkt.haslayer(ICMPv6NDOptDNSSL):
                    #     self.__domainname = pkt[ICMPv6NDOptDNSSL].searchlist
                    #     self.__domainname_lifetime_CeRouter = pkt[ICMPv6NDOptDNSSL].lifetime
                    #     self.__recvd_dhcp_srcladdr = True  

                    # if pkt.haslayer(ICMPv6NDOptSrcLLAddr):
                    #     self.__linklayer_CeRouter = pkt[ICMPv6NDOptSrcLLAddr].lladdr
                        #self.__recvd_dhcp_srcladdr = True  







                # print('LOOP FINAL  ENVIO REQUEST')
                # mac_global = self.__config_setup_lan.get_global_mac_ceRouter()
                # ip_global = self.__config_setup_lan.get_global_addr_ceRouter()
                # self.__config_setup_lan.set_ipv6_src(self.__config.get('t2.7.7c','source_to_ping_tn1'))
                # self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                # self.__config_setup_lan.set_ether_dst(mac_global)
                # self.__config_setup_lan.set_ipv6_dst(self.__config.get('wan','global_wan_addr'))
                # self.__sendmsgs.send_echo_request_lan(self.__config_setup_lan)


                # print('LOOP FINAL')
                # if pkt[Ether].src == self.__config.get('lan','mac_address'): 
                #     continue
                # print('LOOP ECHO REPLY')
                # if pkt.haslayer(ICMPv6EchoReply):
                #     self.__packet_sniffer_lan.stop()
                #     self.__finish_wan = True 
                #     self.__fail_test = True
                #     return False
                # print('LOOP FINAL  NS')
                # if pkt.haslayer(ICMPv6ND_NS):
                #     if pkt[ICMPv6ND_NS].tgt == self.__config.get('t2.7.7c','source_to_ping_tn1'):
                #         print('LOOP FINAL  CEROUTER INVIO NS PARA O PING TN1')
                #         print(pkt[ICMPv6ND_NS].tgt)
                #         if not send_na_lan:
                #             self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','global_wan_addr'))
                #             self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                #             self.__config_setup_lan.set_ether_dst(self.__config_setup_lan.get_global_mac_ceRouter())
                #             self.__config_setup_lan.set_ipv6_dst(self.__config_setup_lan.get_global_addr_ceRouter())
                #             self.__config_setup_lan.set_tgt(self.__config.get('t2.7.7c','source_to_ping_tn1'))
                #             self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                #             send_na_lan = True
                #             self.__sendmsgs.send_icmp_na_lan(self.__config_setup_lan)
                # print('LOOP FINAL  INALCANCAVEL')
                # if pkt.haslayer(ICMPv6DestUnreach):
                #     print('LOOP FINAL  INALCANCAVEL DENTRO')
                #     logging.info(' Teste 2.7.7c: destino TN1 inalcançável.')
                #     logging.info('Aprovado Teste2.7.7c.')
                #     self.__packet_sniffer_lan.stop()
                #     self.__finish_wan = True
                #     self.__fail_test = False 
                #     return True  


                
                # if self.__dhcp_renew_done :
                #     print('DONE CONCLUIDO- VALIDANDO MENSAGEM RA')
                #     if t_test1 < 60:
                #         print('DONE CONCLUIDO- VALIDANDO MENSAGEM RA TEMPO')
                #         time.sleep(1)
                #         t_test1 = t_test1 + 1
                #         #if t_test1 % 10 == 0:
                #             #self.__config_setup_lan.set_setup_lan_start()
                #         self.__config_setup_lan.set_ipv6_src(self.__config.get('lan','lan_local_addr'))
                #         self.__config_setup_lan.set_ether_src(self.__config.get('lan','mac_address'))
                #         self.__config_setup_lan.set_ether_dst(self.__config.get('multicast','all_mac_routers'))
                #         self.__config_setup_lan.set_ipv6_dst(self.__config.get('general','all_routers_address'))
                #         self.__config_setup_lan.set_lla(self.__config.get('lan','mac_address'))
                #         self.__sendmsgs.send_icmp_rs(self.__config_setup_lan)
                    
                #         if pkt.haslayer(ICMPv6ND_RA):
                #             print('DONE CONCLUIDO- VALIDANDO MENSAGEM MENSAGEM RA')    
                #             if pkt.haslayer(ICMPv6NDOptRouteInfo):
                #                 if pkt[ICMPv6NDOptRouteInfo].plen != 60:
                #                     logging.info(' Teste2.7.7c: Reprovado. Tamanho do prefixo diferente do anunciado no DHCP Reconfigure')
                #                     logging.info(pkt[ICMPv6NDOptPrefixInfo].prefixlen)
                #                     logging.info(pkt[ICMPv6NDOptRouteInfo].plen)

                #                     self.__packet_sniffer_lan.stop()
                #                     self.__finish_wan = True 
                #                     self.__fail_test = True
                #                     return False                                
                #                 else: #self.__validlifetime_CeRouter == pkt[ICMPv6NDOptPrefixInfo].validlifetime
                #                     logging.info(' Teste 2.7.7c:Tamanho do prefixo igual ao anunciado na mensagem DHCP Reconfigure.')
                #                     logging.info('Aprovado Teste2.7.7c.')
                #                     self.__packet_sniffer_lan.stop()
                #                     self.__finish_wan = True
                #                     self.__fail_test = False 
                #                     return True       
                #             else: print('DONE CONCLUIDO- SEM PREFIX INFO RA')
                # logging.info('Setup LAN  Concluido')
                # if self.__config_setup_lan.get_recvd_dhcp_srcladdr():
                #     logging.info(' Teste 2.7.7c: Recebido Recursive DNS OK.')
                #     logging.info('Aprovado Teste2.7.7c.')
                #     self.__packet_sniffer_lan.stop()
                #     self.__finish_wan = True
                #     self.__fail_test = False 
                #     return True       
              
                # else:                     
                #     logging.info(' Teste2.7.7c: Reprovado. Não foi recebido')
                #     #logging.info(routerlifetime)
                #     self.__packet_sniffer_lan.stop()
                #     self.__finish_wan = True 
                #     self.__fail_test = True
                #     return False


                
    def run(self):

        
        self.set_flags()
        logging.info(self.__test_desc)
        logging.info('==================================================================================')
        logging.info('Ative a ULA com prefixo: ' +  self.__config.get('t2.7.7c','prefix_ula') + 'e reinicie o Roteador') 
        logging.info('==================================================================================')

        
        time.sleep(20)
        self.__t_lan =  Thread(target=self.run_Lan,name='LAN_Thread')
        self.__t_lan.start()
        
        #self.__packet_sniffer_wan = PacketSniffer('Test273b-WAN',self.__queue_wan,self,self.__config,self.__wan_device_tr1)
        #self.__packet_sniffer_wan.start()
        
        self.__packet_sniffer_lan = PacketSniffer('Test273b-LAN',self.__queue_lan,self,self.__config,self.__lan_device)
        test_lan = self.__packet_sniffer_lan.start()


        # t_test = 0
        # sent_reconfigure = False
        # time_over = False
        # #time.sleep(11111)
        # finish_wan = True
        # self.__config_setup1_1.set_pd_prefixlen(self.__config.get('t2.7.7c','pd_prefixlen')) 
        # self.__config_setup1_1.set_routerlifetime(self.__config.get('t2.7.7c','routerlifetime')) 
        # #self.__config_setup1_1.active_DHCP_no_IA_PD()
        while not self.__queue_wan.full():
        #     while self.__queue_wan.empty():
        #         if t_test < 60:
        #             time.sleep(1)
        #             if t_test % 15 ==0:
                        
        #                 self.__config_setup1_1.set_ether_src(self.__config.get('wan','ra_mac'))
        #                 self.__config_setup1_1.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
        #                 self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','ra_address'))
        #                 self.__config_setup1_1.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
        #                 self.__sendmsgs.send_tr1_RA(self.__config_setup1_1)
        #             t_test = t_test + 1
        #         else:
        #             time_over = True
        #     pkt = self.__queue_wan.get()

        #     if not self.__config_setup1_1.get_setup1_1_OK():

        #         if not self.__config_setup1_1.get_disapproved():
        #             self.__config_setup1_1.run_setup1_1(pkt)
        #         else:
        #             logging.info('Reprovado Teste 2.7.3a - Falha em completar o Common Setup 1.1 da RFC')
        #             self.__packet_sniffer_wan.stop() 
        #             return False

        #     else:
            if not self.__finish_wan: 
                print('WAN - Concluido')
                print('LAN RESULT')
    #                 if not sent_reconfigure:
    #                     time.sleep(25)
    #                     print('aqui7')
    #                     self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
    #                     print('aqui8')
    #                     self.__config_setup1_1.set_ipv6_dst(self.__config_setup1_1.get_local_addr_ceRouter())
    #                     print('aqui10')
    #                     self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
    #                     print('aqui11')
    #                     self.__config_setup1_1.set_ether_dst(self.__config_setup1_1.get_mac_ceRouter())
    #                     print('aqui12')
    #                     self.__config_setup1_1.set_dhcp_reconf_type(self.__config.get('t1.6.3','msg_type'))
    #                     print('aqui13')
    #                     self.__config_setup1_1.set_udp_sport('547')
    #                     self.__config_setup1_1.set_udp_dport('546')
    #                     self.__sendmsgs.send_dhcp_reconfigure(self.__config_setup1_1)
    #                     print('aqui14')
    #                     sent_reconfigure = True 
                        

    #                 if pkt.haslayer(DHCP6_Renew):
    #                     if not self.__dhcp_renew_done:
    # #                        if self.__active_renew_dhcp:
    #                         self.__config_setup1_1.set_mac_ceRouter(pkt[Ether].src)
    #                         self.__config_setup1_1.set_local_addr_ceRouter(pkt[IPv6].src)
    #                         self.__config_setup1_1.set_xid(pkt[DHCP6_Renew].trid)
    #                         self.__config_setup1_1.set_ipv6_src(self.__config.get('wan','link_local_addr'))
    #                         self.__config_setup1_1.set_ipv6_dst(pkt[IPv6].src)
    #                         self.__config_setup1_1.set_ether_src(self.__config.get('wan','link_local_mac'))
    #                         self.__config_setup1_1.set_ether_dst(pkt[Ether].src)
    #                         self.__config_setup1_1.set_dhcp_preflft('100')
    #                         self.__config_setup1_1.set_dhcp_validlft('200')
    #                         self.__config_setup1_1.set_dhcp_plen('60')
    #                         self.__config_setup1_1.set_prefix_addr(self.__config.get('setup1-1_advertise','ia_pd_address'))
    #                         self.__sendmsgs.send_dhcp_reply_v3(self.__config_setup1_1)
    #                         #self.__dhcp_ok = True
    #                         self.__dhcp_renew_done = True
            else:
                self.__packet_sniffer_wan.stop()
                if self.__fail_test:
                    return False
                else:
                    return True
            self.__packet_sniffer_wan.stop()
        return False
     
        