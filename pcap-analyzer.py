import os, sys, json
import hashlib
#from scapy.all import *
from scapy.all import PcapReader
from scapy.all import sr1,TCP,IP,UDP,DNS,DNSQR,DNSRR
from scapy.all import sniff
import copy

def writeFile(filename, data):
    fh = open(filename, "w")
    fh.write(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))
    fh.close()

def hashTCP(packet, flip=False):
    #tcpHash = hashlib.md5(
        #packet[IP].src + str(packet[IP][TCP].sport) + packet[IP].dst + str(packet[IP][TCP].dport)).hexdigest()
    if flip:
        tcpHash = packet[IP].dst + ":" + str(packet[IP][TCP].dport) + "->" + packet[IP].src + ":" + str(
            packet[IP][TCP].sport)
    else:
        tcpHash = packet[IP].src + ":" + str(packet[IP][TCP].sport) + "->" + packet[IP].dst + ":" + str(packet[IP][TCP].dport)
    return tcpHash


if(len(sys.argv) <2):
    print "You must specify a folder"
    sys.exit(2)

folder = sys.argv[1]

if(not os.path.isdir(folder)):
    print "You must specify a valid folder"
    sys.exit(2)

folder.rstrip("/")

tcpState = {}
dnsMapping={}
objectData={}
for file in os.listdir(folder):
    file = "%s/%s" % (folder, file)
    if ".pcap" in file:
        myreader = PcapReader(file)
        while True:
            packet = myreader.read_packet()
            if packet is None:
                break
            #packet.show()

            if not packet.haslayer("IP"):
                continue

            if packet.haslayer("TCP"):
                #packet.show()
                proto="TCP"
                tcpflags = [x for x in packet.sprintf('%TCP.flags%')]

                if hashTCP(packet) in tcpState:
                    print "Packet src to dst"
                    src = packet[IP].src
                    dst = packet[IP].dst
                    port = packet[TCP].dport
                    flow="upload"
                elif hashTCP(packet, True) in tcpState:
                    print "Packet dst to src"
                    src = packet[IP].dst
                    dst = packet[IP].src
                    port = packet[TCP].sport
                    flow="download"
                else:
                    if tcpflags != ["S"]:
                        print "packet out of sync skipping"
                        continue

                if tcpflags == ["S"]:
                    print "This is connection start"
                    src=packet[IP].src
                    dst=packet[IP].dst
                    flow="upload"
                    tcpState[hashTCP(packet)] = "SYN"
                    port = packet[TCP].dport
            else:
                if packet.haslayer("UDP"):
                    packet.show()
                    proto = "UDP"
                    port = packet[UDP].dport
                else:
                    proto="unknown"
                    port = "unknown"

                flow = "upload"
                src = packet[IP].src
                dst = packet[IP].dst

            if packet.haslayer("DNSRR"):
                #packet.show()
                #print "DNS"
                for x in range(packet[DNS].ancount):
                    dnsMapping[packet[DNSRR][x].rdata] =  packet[DNSRR][x].rrname
                continue

            if src not in objectData:
                objectData[src] = {}

            if proto not in objectData[src]:
                objectData[src][proto] = {}

            if port not in objectData[src][proto]:
                objectData[src][proto][port] = {}

            if dst not in objectData[src][proto][port]:
                objectData[src][proto][port][dst] = {"firstseen" : packet.time, "lastseen": packet.time, "upload": 0, "download": 0}

            #print objectData
            objectData[src][proto][port][dst]["lastseen"] = packet.time
            objectData[src][proto][port][dst][flow] = objectData[src][proto][port][dst][flow] + int(packet.sprintf("%IP.len%"))

#Enrich Data
cpObjectData={}

for objSrc in objectData:
    origSrc = objSrc
    if objSrc in dnsMapping:
        objSrc = dnsMapping[objSrc]
    cpObjectData[objSrc] = {}

    print cpObjectData

    for proto in objectData[objSrc]:
        cpObjectData[objSrc][proto] = {}
        for port in objectData[objSrc][proto]:
            cpObjectData[objSrc][proto][port] = {}
            for host in objectData[objSrc][proto][port]:
                origHost = host
                if host in dnsMapping:
                    host = dnsMapping[host]
                if host in cpObjectData[objSrc][proto][port]:
                    cpObjectData[objSrc][proto][port][host]['download'] = cpObjectData[objSrc][proto][port][host]['download'] + \
                                                                          objectData[origSrc][proto][port][origHost]['download']
                    cpObjectData[objSrc][proto][port][host]['upload'] = cpObjectData[objSrc][proto][port][host]['upload'] + \
                                                                          objectData[origSrc][proto][port][origHost]['upload']

                    if(cpObjectData[objSrc][proto][port][host]['firstseen'] > objectData[origSrc][proto][port][origHost]['firstseen']):
                        cpObjectData[objSrc][proto][port][host]['firstseen'] = objectData[origSrc][proto][port][origHost]['firstseen']

                    if(cpObjectData[objSrc][proto][port][host]['lastseen'] < objectData[origSrc][proto][port][origHost]['lastseen']):
                        cpObjectData[objSrc][proto][port][host]['lastseen'] = objectData[origSrc][proto][port][origHost]['lastseen']

                else:
                    cpObjectData[objSrc][proto][port][host] = {}
                    cpObjectData[objSrc][proto][port][host]['download'] = objectData[origSrc][proto][port][origHost]['download']
                    cpObjectData[objSrc][proto][port][host]['lastseen'] = objectData[origSrc][proto][port][origHost]['lastseen']
                    cpObjectData[objSrc][proto][port][host]['upload'] = objectData[origSrc][proto][port][origHost]['upload']
                    cpObjectData[objSrc][proto][port][host]['firstseen'] = objectData[origSrc][proto][port][origHost]['firstseen']

print dnsMapping
print tcpState
writeFile("output.json", cpObjectData)
writeFile("dnsMapping.json", dnsMapping)
