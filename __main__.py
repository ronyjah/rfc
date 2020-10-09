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

def read_config():
    lan_device = config.get('lan','lan_device')
    return lan_device

class RfcLan():
    def __init__(self,configdir):
        self.load_configuration(configdir)
        self.__view = None
        self.__engine = None
        self.__lan_device = self.__config.get('lan','lan_device')
        self.__src_rs_address = self.__config.get('lan', 'source_rs')
        
    def load_configuration(self, conf_dir):
        configfile = conf_dir + '/rfclan.conf'
        configparser = ConfigParser()
        configparser.read(configfile)
        logging.debug("Configuration loaded")
        
        self.__config = Config(configparser, configfile)
        self.__config.set('directories', 'conf_dir', conf_dir)






    def send_tr1_ping(self):
        while 1:
            time.sleep(1)
            a,b=srp(Ether()/IPv6()/ICMPv6EchoRequest(),iface="lo")
            #a.summary(lambda s,r: r.sprintf("%Ether.src%")) 
            for s,r in a:
                print('a')
                if r[IPv6].type == 129:
                    print("Echo Reply Recebido")
                #print(r[IPv6].type)
                #print(r[IPv6].dst)
        #ans = a.summary(prn=teste s,r: r.sprintf("%ICMPv6EchoReply.type%"))
        #print(ans)
        #if  ans == "Echo Reply":
        #    print("ping OK")

    def threaded_ping_tr1(self):
        q = Queue()
        sniffer = Thread(target = self.send_tr1_ping)
        sniffer.daemon = True
        sniffer.start()

    def threaded_ra_tr1(self):
        q = Queue()
        tr1ra = Thread(target = self.send_tr1_RA)
        tr1ra.daemon = True
        tr1ra.start()

    def threaded_ns_tr1(self):
        q = Queue()
        tr1ns = Thread(target = self.send_tr1_NS)
        tr1ns.daemon = True
        tr1ns.start()

    def send_tr1_RA(self):
        #TR1 Transmits a RA to all nodes multicast address
        #TR1 transmi echo request to de NUT, and response NS from de NUT, wait for a echo reply from NUT.this should cause the N U T to resolve the address
        #of TR1 and create a Neighbor Cache entry for TR1 in state REACHABLE

        #>>> ls(ICMPv6ND_RA)
        #type       : ByteEnumField                       = (134)
        #code       : ByteField                           = (0)
        #cksum      : XShortField                         = (None)
        #chlim      : ByteField                           = (0)
        #M          : BitField  (1 bit)                   = (0)
        #O          : BitField  (1 bit)                   = (0)
        #H          : BitField  (1 bit)                   = (0)
        #prf        : BitEnumField  (2 bits)              = (1)
        #P          : BitField  (1 bit)                   = (0)
        #res        : BitField  (2 bits)                  = (0)
        #routerlifetime : ShortField                          = (1800)
        #reachabletime : IntField                            = (0)
        #retranstimer : IntField                            = (0)
        #>>> ls(ICMPv6NDOptDNSSL)
        #type       : ByteField                           = (31)
        #len        : FieldLenField                       = (None)
        #res        : ShortField                          = (None)
        #lifetime   : IntField                            = (4294967295)
        #searchlist : DomainNameListField                 = ([])
        while 1:
            time.sleep(1)
            tr1_et = Ether(src='00:00:00:00:a0:a0')
            tr1_ip = IPv6(src='fe80::200:ff:fe00:a0a0',dst='ff02::1')
            tr1_rs = ICMPv6ND_RA(M=1,O=1,chlim=64)
            #tr1_op_dns = ICMPv6NDOptDNSSL(lifetime=600)
            #ICMPv6NDOptPrefixInfo
            #type       : ByteField                           = (3)
            # len        : ByteField                           = (4)
            # prefixlen  : ByteField                           = (64)
            # L          : BitField  (1 bit)                   = (1)
            # A          : BitField  (1 bit)                   = (1)
            # R          : BitField  (1 bit)                   = (0)
            # res1       : BitField  (5 bits)                  = (0)
            # validlifetime : XIntField                           = (4294967295)
            # preferredlifetime : XIntField                           = (4294967295)
            # res2       : XIntField                           = (0)
            # prefix     : IP6Field                            = ('::')

            tr1_prefix = ICMPv6NDOptPrefixInfo(L=1,A=0,R=0,validlifetime=600,preferredlifetime=600,\
                                                prefix='3ffe:501:ffff:100::')
            #tr1_op = ICMPv6NDOptDstLLAddr(type=1,lladdr=tr1_et.src)
            sendp(tr1_et/tr1_ip/tr1_rs/tr1_prefix,iface='lo')

    def commonTestSetup11(self):
        #self.send_tr1_RA()
        #self.send_tr1_ping()
        self.threaded_ping_tr1()
        self.threaded_ra_tr1()
        self.threaded_ns_tr1()
       #send_tr1_NS()



    def send_tr1_NS(self):
        while 1:        
            time.sleep(1)    
            tr1_et = Ether(src='84:16:f9:05:43:01')
            tr1_ip = IPv6(src='3ffe:501:ffff:100:200:ff:fe00:a1a1',dst='ff02::1:ff00:a0a0')
            tr1_rs = ICMPv6ND_RS()
            tr1_op = ICMPv6NDOptDstLLAddr(type=1,lladdr=tr1_et.src)
            #sendp(Ether()/IPv6()/ICMPv6ND_NS()/ICMPv6NDOptDstLLAddr(type=1,lladdr=Ether().src),iface=self.__lan_device)
            sendp(tr1_et/tr1_ip/tr1_rs/tr1_op,iface="lo")

    def main(self):
        try:
            self.commonTestSetup11()
            # 
            #TN1 send Router Solicitation to CE Test 2.7.1c
            tn1_et = Ether()
            tn1_ip = IPv6(src=self.__src_rs_address,dst='ff02::2')
            tn1_rs = ICMPv6ND_RS()
            tn1_op = ICMPv6NDOptDstLLAddr(type=1,lladdr=tn1_et.src)
            #sendp(Ether()/IPv6()/ICMPv6ND_NS()/ICMPv6NDOptDstLLAddr(type=1,lladdr=Ether().src),iface=self.__lan_device)
            sendp(tn1_et/tn1_ip/tn1_rs/tn1_op,iface=self.__lan_device)
            while 1:
                pass
            #print(self.__lan_device)
        
        except KeyboardInterrupt:
            logging.info('This is the end.')
            sys.exit(0)
            
        except BaseException as error:
            logging.error(error)
            logging.info('Ooops... Aborting!')

def init_RfcLan(configdir):
    rfclan = RfcLan(configdir)
    rfclan.main()

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--configdir', help='the config directory',type=str)
    args = parser.parse_args()
    if not args.configdir:
        parser.print_help()
        sys.exit(0)
        
    init_RfcLan(args.configdir)

if __name__ == "__main__":
	main()


    