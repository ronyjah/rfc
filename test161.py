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
class Test161:




    def __init__(self,config):
        self.__queue = Queue()
        self.__config = config
        self.__interface = None
        self.__pkt = None
        self.__valid = False
        self.__result = None
        self.__test_desc = self.__config.get('tests','1.6.1')
        self.__packet_sniffer = PacketSniffer(self.__queue,self,self.__config)
        self.__packet_sniffer.daemon=True
        self.__packet_sniffer.start()

    #recebe o pacote
    #packetSniffer return pkt


    def set_result(self, valor):
        self.__result = valor
        
    def get_result(self):
        return self.__result

    def run(self):
        logging.info(self.__test_desc)
        while not self.__queue.full():
            pkt = self.__queue.get()
           # logging.info(pkt[IPv6].src)
            if pkt.haslayer(ICMPv6ND_NS):
                self.__valid = True
            elif pkt.haslayer(ICMPv6ND_RA) and self.__valid == False:
                #print('theardoffFalse')
                #self.turn_off_thread()
                with self.__queue.mutex:
                    self.__queue.clear()
                
                return False
            else:
                with self.__queue.mutex:
                    self.__queue.clear()
                #print('theardofftrue')
                #self.turn_off_thread()
                return True
        
