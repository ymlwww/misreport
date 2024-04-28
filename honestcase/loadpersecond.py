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
import math
'''
calculate the size of new flow of each second and store the results
'''
start = time.time() #time counter start

fileid = int(sys.argv[1])
pkts = PcapReader('data/'+str(fileid)+'.pcap') #read trace file

#set params
poolsize = 10
hostidset={}  # dict of flow id to host 
lastsee={} # dict of the last time that the flow is seen
epochload = {}  # dict of time epoch to load
idle_timeout = 10 # soft time-out is 10s
loadpool = zeros(poolsize) #load of each epoch
flowmatch = {} # table of flow id to start time epoch count each epoch
time0 = 0.0
counter = 0
roundhost = np.random.randint(0,high=poolsize)
print("first random host: "+str(roundhost))
cnt = 0 #time epoch counter

for p in pkts:
    if counter==0:
        time0 = p.time   #record the first packet timestamp
    counter = counter + 1
    if counter%1000000==0:
        print("pkt"+str(counter)+ " is being processed")  #print log every 10^6 packet
    if(p.time - time0 > 1):  #update the time epoch base
        time0 = time0 + 1.0  
        cnt = cnt + 1
        while(p.time - time0 > 1):  #if no packet arrives within 1 second, add zeros to the load report history
            time0 = time0 + 1.0
            cnt = cnt + 1
            loadpool = zeros(poolsize)
        #update the min load host
        candidates = [i for i,x in enumerate(loadpool) if x==min(loadpool)]
        if(len(candidates) > 1):
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
    tmp = ".".join(item)
    if tmp in hostidset.keys():
        if(p.time - lastsee[tmp])<idle_timeout:
            lastsee[tmp] = p.time
            loadpool[hostidset[tmp]] = loadpool[hostidset[tmp]] + p.wirelen
            epochload[flowmatch[tmp]] = epochload[flowmatch[tmp]] + p.wirelen
        else:
            hostidset[tmp] = roundhost
            loadpool[roundhost] = loadpool[roundhost] + p.wirelen
            flowmatch[tmp] = cnt
            if flowmatch[tmp] not in epochload.keys():
                epochload[flowmatch[tmp]] = p.wirelen
            else:
                epochload[flowmatch[tmp]] = epochload[flowmatch[tmp]] + p.wirelen
            lastsee[tmp] = p.time
    else:
        hostidset[tmp] = roundhost
        loadpool[roundhost] = loadpool[roundhost] + p.wirelen
        flowmatch[tmp] = cnt
        if flowmatch[tmp] not in epochload.keys():
            epochload[flowmatch[tmp]] = p.wirelen
        else:
            epochload[flowmatch[tmp]] = epochload[flowmatch[tmp]] + p.wirelen
        lastsee[tmp] = p.time

f = open('epochload'+str(fileid),'wb')
pickle.dump(epochload, f, pickle.HIGHEST_PROTOCOL)
f.close()

end = time.time()
print('time used: ',(end - start)/60,'min')
