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

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S")
class PacketSniffer(Thread):
    def __init__(self,pass_queue,test,config):
        super(PacketSniffer,self).__init__()
        logging.info('Packet sniffer started')
        self.queue=pass_queue
        self.device_dict={}
        self.not_an_ap={}
        self.__test = test
        self.__interface = config.get('lan','lan_device')

        Thread(name='PacketHandler',target=PacketSniffer.run, daemon =True)

    def run(self):
        #print('run')

        #print (threading.currentThread().getName(), 'Run')
        logging.info('Run')
        sniff(iface=self.__interface,prn=self.PacketHandler)

    def put_queue(self,value):
        self.queue.put(value)

    def get_queue(self):
        return self.queue.get()

    def PacketHandler(self,pkt):
        logging.info('PacketHandler')
        #print (threading.currentThread().getName(), 'PacketHandler')
        #print('OLA MUNDO')
        #if pkt.haslayer(ICMP):
        self.put_queue(pkt)
            #print(pkt.src)
#            self.__test.set_aprovado(1)
        #   sig_str = -(256-ord(pkt.notdecoded[-4:-3]))
        #   mac_addr=""
        #   ssid=""
        try:
            pass
            #print('handler')
            # mac_addr=pkt.addr2
            # ssid=pkt.info
        except:
            return
        # if self.device_dict.has_key(pkt.addr2) and pkt.info!=self.device_dict[pkt.addr2]:
        #     output= "DIS MAC:%s RSSI:%s " %(pkt.addr2,sig_str)
        #     print (output)
        #     self.device_dict.pop(pkt.addr2)
        #     self.not_an_ap[pkt.addr2]=pkt.info
        #     self.queue.put(output)
        # elif pkt.info=="" or pkt.info=="Broadcast":
        #     output= "DIS MAC:%s RSSI:%s " %(pkt.addr2,sig_str)
        #     print (output)
        #     self.queue.put(output)
        # else:
        #     pot_mac=self.not_an_ap.get(pkt.addr2)
        #     if pot_mac == None:
        #         self.device_dict[pkt.addr2]=pkt.info


      