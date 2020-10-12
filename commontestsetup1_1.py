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
        self.__test_desc = self.__config.get('tests','common1-1')


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
#sendp(Ether()/IPv6()/UDP()/DHCP6_Advertise()/DHCP6OptClientId()/DHCP6OptServerId()/DHCP6OptIA_NA()/DHCP6OptIA_PD()/DHCP6OptDNSServers()/DHCP6OptDNSDomains(),iface='lo')
# TR1 transmits a Router Advertisement to the all-nodes multicast address with the M and O Flag
    def ether(self):
        return Ether(src=self.__wan_mac_tr1)

    def ipv6(self):
        return IPv6(src=self.__link_local_addr,\
                      dst=self.__all_nodes_addr)
    
    def icmpv6_ra(self):
        return ICMPv6ND_RA(M=self.__flag_M,\
                            O=self.__flag_O,\
                            routerlifetime=self.__routerlifetime,\
                            chlim=self.__flag_chlim)

    def icmpv6_pd(self):
        return ICMPv6NDOptPrefixInfo(L=self.__flag_L,\
                                        A=self.__flag_A,\
                                        R=self.__flag_R,\
                                        validlifetime=self.__validlifetime,\
                                        preferredlifetime=self.__preferredlifetime,\
                                        prefix=self.__global_addr)

    def udp(self):
        return UDP()
    
    def dhcp_advertise(self):
        return DHCP6_Advertise()
    
    def opt_ia_na(self):
        return DHCP6OptIA_NA()
    
    def opt_ia_pd(self):
        # optcode    : ShortEnumField                      = (25)
        # optlen     : FieldLenField                       = (None)
        # iaid       : XIntField                           = (None)
        # T1         : IntField                            = (None)
        # T2         : IntField                            = (None)
        # iapdopt    : PacketListField                     = ([])
        return DHCP6OptIA_PD(iaid = self.__config.get('setup1-1_advertise','iaid'),\
                            T1 = self.__config.get('setup1-1_advertise','t1'),\
                            T2 = self.__config.get('setup1-1_advertise','t2'),\
                            iapdopt=DHCP6OptIAAddress(addr=self.__config.get('setup1-1_advertise','ia_pd_address'),\
                                                        preflft=self.__config.get('setup1-1_advertise','ia_pd_pref_lifetime'),\
                                                        validlft=self.__config.get('setup1-1_advertise','ia_pd_validtime')))

    def opt_dns_server(self):
        return DHCP6OptDNSServers(dnsservers=[self.__config.get('setup1-1_advertise','dns_rec_name_server')])

    def opt_dns_domain(self):
        #dnsdomains : DomainNameListField                 = ([])
        return DHCP6OptDNSDomains(dnsdomains=[self.__config.get('setup1-1_advertise','domain_search')])

    def send_tr1_RA(self):
        # tr1_et = Ether(src=self.__wan_mac_tr1)
        # tr1_ip = IPv6(src=self.__link_local_addr,\
        #               dst=self.__all_nodes_addr)
        # tr1_rs = ICMPv6ND_RA(M=self.__flag_M,\
        #                     O=self.__flag_O,\
        #                     routerlifetime=self.__routerlifetime,\
        #                     chlim=self.__flag_chlim)
        # tr1_pd = ICMPv6NDOptPrefixInfo(L=self.__flag_L,\
        #                                 A=self.__flag_A,\
        #                                 R=self.__flag_R,\
        #                                 validlifetime=self.__validlifetime,\
        #                                 preferredlifetime=self.__preferredlifetime,\
        #                                 prefix=self.__global_addr)
        sendp(self.ether()/\
            self.ipv6()/\
            self.icmpv6_ra()/\
            self.icmpv6_pd(),\
            iface=self.__wan_device_tr1,inter='1')

    def send_dhcp_advertise(self):
        #sendp(Ether()/IPv6()/UDP()/DHCP6_Advertise()/DHCP6OptClientId()/DHCP6OptServerId()/DHCP6OptIA_NA()/DHCP6OptIA_PD()/DHCP6OptDNSServers()/DHCP6OptDNSDomains(),iface='lo')
        sendp(self.ether()/\
            self.ipv6()/\
            self.udp()/\
            self.dhcp_advertise/\
            self.opt_ia_na/\
            self.opt_ia_pd/\
            self.opt_dns_server/\
            self.opt_dns_domain,\
            iface=self.__wan_device_tr1,inter='1')