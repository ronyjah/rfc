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
import pdb
class ConfigSetup1_1:

    def __init__(self,config):
        #self.__queue_wan = Queue()
        #self.__queue_lan = Queue()
        #logging.info('self.__queue_size_inicio162')
        #logging.info(self.__queue_wan.qsize())
        self.__config = config
        self.__interface = None
        self.__lla = None
        self.__pkt = None
        self.__valid = False
        self.__result = None
        self.__device_lan_tn1 = None
        self.__lan_mac_tn1 = None
        self.__ceRouter_mac_addr = None
        self.__flag_M = None
        self.__flag_O = None
        self.__flag_chlim = None
        self.__flag_L = None
        self.__flag_A = None
        self.__flag_R = None
        self.__validlifetime = None
        self.__preferredlifetime = None
        self.__interval = None
        self.__routerlifetime = None
        self.__ipv6_dst =None
        self.__ipv6_src = None
        self.__ether_src = None
        self.__ether_dst = None
        self.__xid = None
        self.__server_duid = None
        self.__client_duid = None
        self.__ND_local_OK = False
        self.__setup1_1_OK = False
        self.__local_ping_OK = False
        self.__global_ns_ok = False
        self.__dhcp_ok = False
        self.__active_DHCP_no_IA_PD = False
        self.__iaid = None
        self.__mac_cerouter = None
        self.__flag_prf = None
        self.udp_dport = None
        self.udp_sport = None
        self.__reachabletime = None
        self.__retranstimer = None
        self.__disapproved = False
        self.__dhcp_reconf_type = None
        self.__local_addr_ceRouter =None
        self.__dhcp_t1 = None
        self.__dhcp_t2 = None   
        self.__dhcp_preflft = None
        self.__dhcp_plen = None
        self.__dhcp_validlft = None
        self.__active_renew_dhcp = None
        self.__prefix_addr = None
        self.__set_ra2 = False
        self.__recvd_dhcp_renew = False
        self.__dhcp_renew_done = False
        self.__sendmsgssetup1_1 = SendMsgs(self.__config)
        self.__wan_device_tr1 = self.__config.get('wan','device_wan_tr1')
        self.__wan_mac_tr1 = self.__config.get('wan','wan_mac_tr1')
        self.__link_local_addr = self.__config.get('wan','link_local_addr')
        self.__all_nodes_addr = self.__config.get('multicast','all_nodes_addr')
        self.__test_desc = self.__config.get('tests','1.6.2b')
        
        #self.__packet_sniffer.daemon=True
        

    #recebe o pacote
    #packetSniffer return pkt

    def get_prefix_addr(self):
        return self.__prefix_addr
    def set_prefix_addr(self,valor):
        self.__prefix_addr = valor

    def get_reachabletime(self):
        return int(self.__reachabletime)
    
    def get_retranstimer(self):
        return int(self.__retranstimer)

    def set_reachabletime(self,valor):
        self.__reachabletime = valor
    
    def set_retranstimer(self,valor):
        self.__retranstimer = valor

    def get_recvd_dhcp_renew(self):
        return self.__recvd_dhcp_renew

    def active_DHCP_no_IA_PD(self):
        self.__active_DHCP_no_IA_PD = True

    def get_setup1_1_OK(self):
        return self.__setup1_1_OK

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

    def send_echo_request_lan(self):
        et = Ether(src=self.__wan_mac_tr1,\
                   dst=self.__ceRouter_mac_addr)
        ip = IPv6(src=self.__link_local_addr,\
                  dst=self.__all_nodes_addr)
        icmp_ra = ICMPv6EchoRequest()
        sendp(et/ip/icmp_ra,iface=self.__wan_device_tr1)

    def flags_partA(self):
        self.__flag_M = self.__config.get('t1.6.2_flags_part_a','flag_m')
        self.__flag_O = self.__config.get('t1.6.2_flags_part_a','flag_o')
        self.__flag_chlim = self.__config.get('t1.6.2_flags_part_a','flag_chlim')
        self.__flag_L = self.__config.get('t1.6.2_flags_part_a','flag_l')
        self.__flag_A = self.__config.get('t1.6.2_flags_part_a','flag_a')
        self.__flag_R = self.__config.get('t1.6.2_flags_part_a','flag_r')
        self.__validlifetime = self.__config.get('t1.6.2_flags_part_a','validlifetime')
        self.__preferredlifetime = self.__config.get('t1.6.2_flags_part_a','preferredlifetime')
        self.__routerlifetime = self.__config.get('t1.6.2_flags_part_a','routerlifetime')
        self.__intervalo = self.__config.get('t1.6.2_flags_part_a','intervalo')

    def flags_partB(self):
        self.__flag_M = self.__config.get('t1.6.2_flags_part_b','flag_m')
        self.__flag_O = self.__config.get('t1.6.2_flags_part_b','flag_o')
        self.__flag_chlim = self.__config.get('t1.6.2_flags_part_b','flag_chlim')
        self.__flag_L = self.__config.get('t1.6.2_flags_part_b','flag_l')
        self.__flag_A = self.__config.get('t1.6.2_flags_part_b','flag_a')
        self.__flag_R = self.__config.get('t1.6.2_flags_part_b','flag_r')
        self.__validlifetime = self.__config.get('t1.6.2_flags_part_b','validlifetime')
        self.__preferredlifetime = self.__config.get('t1.6.2_flags_part_b','preferredlifetime')
        self.__routerlifetime = self.__config.get('t1.6.2_flags_part_b','routerlifetime')
        self.__intervalo = self.__config.get('t1.6.2_flags_part_b','intervalo')

    def get_flag_M(self):
        return int(self.__flag_M)

    def set_flag_M(self,valor):
        self.__flag_M = valor

    def get_flag_O(self):
        return int(self.__flag_O)
    def set_flag_O(self,valor):
        self.__flag_O= valor

    def get_flag_prf(self):
        return int(self.__flag_prf)

    def set_flag_prf(self,valor):
        self.__flag_prf = valor

    def set_flag_0(self,valor):
        self.__flag_O = valor

    def set_routerlifetime(self,valor):
        self.__routerlifetime= valor

    def set_flag_L(self,valor):
        self.__flag_L = valor
        
    def set_flag_A(self,valor):
        self.__flag_A = valor

    def set_flag_R(self,valor):
        self.__flag_R = valor

    def set_validlifetime(self,valor):
        self.__validlifetime = valor

    def set_preferredlifetime(self,valor):
        self.__preferredlifetime = valor

    def set_intervalo(self,valor):
        self.__intervalo = valor
        
    def set_flag_chlim(self,valor):
        self.__flag_chlim = valor

    def get_flag_chlim(self):
        return int(self.__flag_chlim)

    def get_flag_L(self):
        return  int(self.__flag_L)

    def get_flag_A(self):
        return int(self.__flag_A)

    def get_flag_R(self):
        return int(self.__flag_R)

    def get_validlifetime(self):
        return int(self.__validlifetime)

    def get_preferredlifetime(self):
        return int(self.__preferredlifetime)

    def get_interval(self):
        return int(self.__intervalo)

    def get_routerlifetime(self):
        return int(self.__routerlifetime)
    
    def set_ipv6_dst(self, valor):
        self.__ipv6_dst = valor

    def get_ipv6_dst(self):
        return self.__ipv6_dst

    def set_ipv6_src(self, valor):
        self.__ipv6_src = valor

    def get_ipv6_src(self):
        return self.__ipv6_src

    def set_ether_dst(self, valor):
        self.__ether_dst = valor

    def get_ether_dst(self):
        return self.__ether_dst

    def set_ether_src(self, valor):
        self.__ether_src = valor
        
    def set_ND_local_OK(self):
        self.__ND_local_OK = True

    def get_ether_src(self):
        return self.__ether_src
    
    def set_local_addr_ceRouter(self,valor):
        self.__local_addr_ceRouter = valor

    def get_local_addr_ceRouter(self):
        return self.__local_addr_ceRouter

    def set_tgt(self,valor):
        self.__tgt = valor

    def get_tgt(self):
        return self.__tgt

    def set_xid(self,valor):
        self.__xid = valor

    def get_xid(self):
        return self.__xid

    def set_client_duid(self,valor):
        self.__client_duid = valor

    def get_client_duid(self):
        return self.__client_duid

    def set_server_duid(self,valor):
        self.__server_duid = valor

    def get_server_duid(self):
        return self.__server_duid

    def set_iaid(self,valor):
        self.__iaid = valor

    def get_iaid(self):
        return self.__iaid
    
    def get_local_ping(self):
        return self.__local_ping_OK

    def get_ND_local_OK(self):
        return  self.__ND_local_OK

    def get_dhcp_reconf_type(self):
        return self.__dhcp_reconf_type
    
    def set_dhcp_reconf_type(self,valor):
        self.__dhcp_reconf_type = valor

    def set_mac_ceRouter(self,valor):
        self.__mac_cerouter = valor

    def get_mac_ceRouter(self):
        return self.__mac_cerouter

    def get_disapproved(self):
        return self.__disapproved

    def get_lla(self):
        return self.__lla

    def set_lla(self,valor):
        self.__lla = valor

    def set_setup1_1_OK(self,valor):
        self.__setup1_1_OK = valor
    
    def get_udp_sport(self):
        return int(self.udp_sport)
    
    def set_udp_sport(self,valor):
        self.udp_sport = valor

    def set_ra2(self):
        self.__set_ra2 = True
    
    def get_udp_dport(self):
        return int(self.udp_dport)
    
    def set_udp_dport(self,valor):
        self.udp_dport = valor

    def set_pd_prefixlen(self,valor):
        self.__pd_prefixlen = valor

    def get_pd_prefixlen(self):
        return int(self.__pd_prefixlen)

    def set_dhcp_t1(self,valor):
        self.__dhcp_t1 = valor
    def set_dhcp_t2(self,valor):
        self.__dhcp_t2 = valor   
    def set_dhcp_preflft(self,valor):
        self.__dhcp_preflft = valor
    def set_dhcp_plen(self,valor):
        self.__dhcp_plen = valor
    def set_dhcp_validlft(self,valor):
        self.__dhcp_validlft = valor

    def get_dhcp_t1(self):
        return int(self.__dhcp_t1)
    def get_dhcp_t2(self):
        return int(self.__dhcp_t2)   
    def get_dhcp_preflft(self):
        return int(self.__dhcp_preflft)
    def get_dhcp_plen(self):
        return int(self.__dhcp_plen)
    def get_dhcp_validlft(self):
        return int(self.__dhcp_validlft)

    def active_renew_dhcp(self):
        self.__active_renew_dhcp = True

    def get_dhcp_renew_done(self):
        return self.__dhcp_renew_done
    

    def check_layers(self,pkt):
        #print('Check REnew')
        if pkt.haslayer(DHCP6_Renew):
            #print('====PACOTE RENEW====')
            self.__recvd_dhcp_renew = True

            if self.__active_renew_dhcp:
                self.set_mac_ceRouter(pkt[Ether].src)
                self.set_local_addr_ceRouter(pkt[IPv6].src)
                self.set_xid(pkt[DHCP6_Renew].trid)
                self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                self.set_ipv6_dst(pkt[IPv6].src)
                self.set_ether_src(self.__config.get('wan','link_local_mac'))
                self.set_ether_dst(pkt[Ether].src)
                self.__sendmsgssetup1_1.send_dhcp_reply_v2(self)
                #self.__dhcp_ok = True
                self.__dhcp_renew_done = True


        # if pkt.haslayer(ICMPv6ND_NS):

        #     self.__recvd_echo_request = True
        #     self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
        #     self.set_ipv6_dst(self.get_local_addr_ceRouter())
        #     self.set_ether_src(self.__config.get('wan','link_local_mac'))
        #     self.set_ether_dst(self.get_mac_ceRouter())
        #     #self.set_tgt(self.get_local_addr_ceRouter())
        #     self.__sendmsgssetup1_1.send_echo_request(self) 


        # if pkt.haslayer(ICMPv6EchoRequest):
        #     self.__recvd_echo_request = True
        #     self.set_ipv6_src(self.__config.get('wan','global_lan_addr'))
        #     self.set_ipv6_dst(pkt.[IPv6].src)
        #     self.set_ether_src(self.__config.get('wan','ra_mac'))
        #     self.set_ether_dst(pkt[Ether].src)
        #     #self.set_tgt(self.get_local_addr_ceRouter())
        #     self.__sendmsgssetup1_1.send_echo_reply(self) 





    def run_setup1_1(self,pkt):

        if pkt[Ether].src == self.__config.get('wan','link_local_mac'):
            return
        if pkt[Ether].src == self.__config.get('wan','ra_mac'):
            return
        if self.__disapproved:
            return False




        if pkt.haslayer(ICMPv6EchoReply):
            #print('DESTINO IPv6:' + pkt[IPv6].dst)
            if pkt[IPv6].dst == self.__config.get('wan','link_local_addr'):
                #print('DESTINO IPv6 OKKKK')
                self.__local_ping_OK = True
                return

        if pkt.haslayer(ICMPv6ND_NS):
            #print('1')
            if pkt[ICMPv6ND_NS].tgt == '::':
                p#rint('11')
                return
            if pkt[IPv6].src == self.__config.get('wan','link_local_addr'):
                #print('111')
                return
            if pkt[IPv6].src == self.__config.get('wan','global_wan_addr'):
                #print('1111')
                return
            if pkt[IPv6].src == self.__config.get('wan','ra_address'):
                return      
            if pkt.haslayer(ICMPv6EchoRequest):
                return

            #     self.__sendmsgssetup1_1.send_icmp_na(self)


            if pkt[ICMPv6ND_NS].tgt == self.__config.get('wan','link_local_addr'):
                if pkt[IPv6].src == self.__config.get('wan','link_local_addr'):
                    return
                if pkt[IPv6].src == self.__config.get('wan','global_wan_addr'):
                    return            
                if pkt[IPv6].src == self.__config.get('wan','ra_address'):
                    return        
                self.set_mac_ceRouter(pkt[Ether].src)

                self.set_local_addr_ceRouter(pkt[IPv6].src)
                self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                self.set_ipv6_dst(pkt[IPv6].src)
                self.set_ether_src(self.__config.get('wan','link_local_mac'))
                self.set_ether_dst(pkt[Ether].src)
                self.set_tgt(self.__config.get('wan','link_local_addr'))
                #self.__sendmsgssetup1_1.send_echo_request(self)
                self.set_lla(self.__config.get('wan','link_local_mac'))
               # print("ENVIOU NAA")
                if not self.__local_ping_OK:
                    self.__sendmsgssetup1_1.send_icmp_na(self)
               # time.sleep(10)
            else:

                self.set_local_addr_ceRouter(pkt[ICMPv6ND_NS].tgt)
                self.set_mac_ceRouter(pkt[Ether].src)

                #print('enviou ICMP NA')

                self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                self.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                self.set_ether_src(self.__config.get('wan','link_local_mac'))
                self.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                self.set_tgt(self.get_local_addr_ceRouter())
                #self.__sendmsgssetup1_1.send_echo_request(self)
                self.set_lla(self.__config.get('wan','link_local_mac'))
                if not self.__ND_local_OK:
                    #print('nao tenho ND LOCAL OK')
                    self.__sendmsgssetup1_1.send_icmp_ns(self)

                    return

        if pkt.haslayer(ICMPv6ND_NA) and not  self.__local_ping_OK:
            
            #self.__ND_local_OK = True
            self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
            self.set_ipv6_dst(self.get_local_addr_ceRouter())
            self.set_ether_src(self.__config.get('wan','link_local_mac'))
            self.set_ether_dst(self.get_mac_ceRouter())
            #self.set_tgt(self.get_local_addr_ceRouter())
            self.__sendmsgssetup1_1.send_echo_request(self)  
            self.__ND_local_OK = True
            #return
        else:
            #self.__ND_local_OK = True
            #print('enviou ICMP NS')
            if not  self.__local_ping_OK:
                self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
                self.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
                self.set_ether_src(self.__config.get('wan','link_local_mac'))
                self.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                #self.set_tgt(self.get_local_addr_ceRouter())
                
                self.set_tgt(self.get_local_addr_ceRouter())
                #self.__sendmsgssetup1_1.send_echo_request(self)
                self.set_lla(self.__config.get('wan','link_local_mac'))
                self.__sendmsgssetup1_1.send_icmp_ns(self)
                #return
        




        if pkt.haslayer(ICMPv6ND_RS):
            if self.__local_ping_OK:
                logging.info('SEND TR1 RA 531')
                self.set_ether_src(self.__config.get('wan','ra_mac'))
                self.set_ether_dst(self.__config.get('multicast','all_mac_nodes'))
                self.set_ipv6_src(self.__config.get('wan','ra_address'))
                self.set_ipv6_dst(self.__config.get('multicast','all_nodes_addr'))
 #               if not self.__active_RA_no_IA_PD:
                #self.set_lla(self.__config.get('wan','ra_mac'))
                if not self.__set_ra2:
                    self.__sendmsgssetup1_1.send_tr1_RA(self)
                else:
                    print('send_RA2')
                    self.__sendmsgssetup1_1.send_tr1_RA2(self)
            else:
                self.set_local_addr_ceRouter(pkt[IPv6].src)
                self.set_mac_ceRouter(pkt[Ether].src)                


       # print('PRE SOLICIT')
        if pkt.haslayer(DHCP6_Solicit) and self.__local_ping_OK:
            logging.info('SEND ADVERTISE 576')
            self.set_xid(pkt[DHCP6_Solicit].trid)
            self.set_client_duid(pkt[DHCP6OptClientId].duid)
            self.set_server_duid((self.__config.get('setup1-1_advertise','server_duid')))
            self.set_iaid(pkt[DHCP6OptIA_NA].iaid)
            self.set_ether_src(self.__config.get('wan','link_local_mac'))
            self.set_ether_dst(pkt[Ether].src)
            self.set_ipv6_dst(pkt[IPv6].src)
            self.set_local_addr_ceRouter(pkt[IPv6].src)
            self.set_mac_ceRouter(pkt[Ether].src)

            self.set_ipv6_src(self.__config.get('wan','link_local_addr'))  
            if not self.__active_DHCP_no_IA_PD:
                self.__sendmsgssetup1_1.send_dhcp_advertise(self)
            else:
                self.__sendmsgssetup1_1.send_dhcp_advertise_no_IA_PD(self)
        elif pkt.haslayer(DHCP6_Solicit):
            self.set_local_addr_ceRouter(pkt[IPv6].src)
            self.set_mac_ceRouter(pkt[Ether].src)


        if pkt.haslayer(DHCP6_Request):
            logging.info('SEND REPLY 616')            

            self.set_mac_ceRouter(pkt[Ether].src)
            self.set_local_addr_ceRouter(pkt[IPv6].src)
            self.set_xid(pkt[DHCP6_Request].trid)
            self.set_ipv6_src(self.__config.get('wan','link_local_addr'))
            self.set_ipv6_dst(pkt[IPv6].src)
            self.set_ether_src(self.__config.get('wan','link_local_mac'))
            self.set_ether_dst(pkt[Ether].src)
            self.__sendmsgssetup1_1.send_dhcp_reply(self)
            self.__dhcp_ok = True
            self.__setup1_1_OK = True
            logging.info("Common Test Setup 1.1 OK")


