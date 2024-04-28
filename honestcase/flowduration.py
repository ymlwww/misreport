from scapy.all import *
from numpy import *
import random
import matplotlib.pyplot as plt
import numpy as np
import time
from collections import Counter
import pickle
import sys
import os
'''
   calculate and store the flow duration for each flow
'''
# honest report cdf data generator and rule out the first two epochs
start = time.time() #start timer

fileid = int(sys.argv[1])
poolsize = 10
pkts = PcapReader("data/"+str(fileid)+'.pcap')

#set params
idle_timeout = 10
hostidset={}  # dict of flow id to host 
loadpool = zeros(poolsize) #load of each epoch
time0 = 0.0
counter = 0
timecount = 0
lastsee={}
flowduration = {} #dict of flow to duration, the value is (start time, lastime)
print("load file")
roundhost = np.random.randint(0,high=poolsize)
print("first random host: "+str(roundhost))

for p in pkts:
    if counter==0:
        time0 = p.time
    counter = counter + 1
    if counter%1000000==0:
        print("pkt"+str(counter)+ " is being processed")
    if(p.time - time0 > 1):  #update the time epoch base
        time0 = time0 + 1.0
        timecount = timecount + 1
        while(p.time - time0 > 1):
            time0 = time0 + 1.0
            timecount = timecount + 1
            loadpool = zeros(poolsize)
        candidates = [i for i,x in enumerate(loadpool) if x==min(loadpool)]
        if len(candidates) > 1:
            roundhost = candidates[np.random.randint(0,high = len(candidates))]
        else:
            roundhost = candidates[0]
        loadpool = zeros(poolsize)
    item=[]
    if p.haslayer("IP"):  #ignore ipv6 traffic
        src_ip = p["IP"].src
        dst_ip = p["IP"].dst
        item.append("IP_"+src_ip)
        item.append(dst_ip)
    elif p.haslayer("ARP"):
        src_ip = p["ARP"].psrc
        dst_ip = p["ARP"].pdst
        item.append("ARP_"+src_ip)
        item.append(dst_ip)
    if p.haslayer("TCP"):
        sport = p["TCP"].sport
        dport = p["TCP"].dport
        item.append("TCP_"+str(sport))
        item.append(str(dport))
    elif p.haslayer("UDP"):
        sport = p["UDP"].sport
        dport = p["UDP"].dport
        item.append("UDP_"+str(sport))
        item.append(str(dport))
    if len(item) == 0:
        continue
    tmp = ".".join(item)   #note that this method would classify tcp and its syn to two flows
    if(timecount<=1):
        hostidset[tmp] = 2*poolsize
        lastsee[tmp] = p.time
    else:
        if tmp in hostidset.keys():
            if(p.time - lastsee[tmp]) < idle_timeout:
                if(hostidset[tmp]>poolsize):
                    lastsee[tmp] = p.time
                else:
                    loadpool[hostidset[tmp]] = loadpool[hostidset[tmp]] + p.wirelen
                    lastsee[tmp] = p.time
                    flowduration[tmp][1] = p.time
            else:
                hostidset[tmp] = roundhost
                loadpool[roundhost] = loadpool[roundhost] + p.wirelen
                lastsee[tmp] = p.time
                flowduration[tmp] = [p.time, p.time]
        else:
            hostidset[tmp] = roundhost
            loadpool[roundhost] = loadpool[roundhost] + p.wirelen
            lastsee[tmp] = p.time
            flowduration[tmp] = [p.time, p.time]

f = open('res/flowduration'+str(fileid),'wb')
pickle.dump(flowduration, f, pickle.HIGHEST_PROTOCOL)
f.close()
end = time.time()
print('time used: ',(end - start)/60,'min')
