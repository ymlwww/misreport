'''
   run the first trace simulation and store the intermediate data
'''
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
start = time.time()
fileid = int(sys.argv[1]) - 1

#get the pcap file list
fileList = os.listdir(os.getcwd())
fileList = sorted([x for x in fileList if "pcap" in x])
print("read file: "+fileList[fileid])
pkts = PcapReader(fileList[fileid])

#constants
poolsize = 10
idle = 10 #idle time out
time0 = 0.0 #initial timestamp

# store the intermediate result for the first 15min of reconnaissance, saving for future second phrase misreporting attack of different parameters and purposes

hostidset={}  # dict of flow to host 
lastsee={} # dict of the last time that the flow is seen
loadpool = zeros(poolsize) #lioad of each epoch
loadhist = []  #  list for the load pool

counter = 0 #pkt counter
roundhost = np.random.randint(0,high=poolsize)
print("first random host: "+str(roundhost))
startrndhost = roundhost
cnt = 0 #time epoch counter
#reconnaissance part
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
            if(cnt > 1):
                loadhist.extend(loadpool)
            loadpool = zeros(poolsize)
        #update the min load host
        candidates = [i for i,x in enumerate(loadpool) if x==min(loadpool)]
        if(len(candidates) > 1):
            roundhost = candidates[np.random.randint(0,high = len(candidates))]
        else:
            roundhost = candidates[0]
        if(cnt > 1):
            loadhist.extend(loadpool)
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
    if len(item) == 0 or len(item) == 1:
        continue
    tmp = ",".join(item)   #note that this method would classify tcp and its syn to two flows
    if(cnt<=1):
        hostidset[tmp] = 2*poolsize
        lastsee[tmp] = p.time
    else:    
        if tmp in hostidset.keys():
            if(p.time - lastsee[tmp])<idle:
                lastsee[tmp] = p.time
                if(hostidset[tmp]<poolsize):
                    loadpool[hostidset[tmp]] = loadpool[hostidset[tmp]] + p.wirelen
            else:
                hostidset[tmp] = roundhost
                loadpool[roundhost] = loadpool[roundhost] + p.wirelen
                lastsee[tmp] = p.time
        else:
            hostidset[tmp] = roundhost
            loadpool[roundhost] = loadpool[roundhost] + p.wirelen
            lastsee[tmp] = p.time
print("reconnaissance part end")

f = open('res/loadpool'+str(fileid),'wb')
pickle.dump(loadpool, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('res/lastsee'+str(fileid),'wb')
pickle.dump(lastsee, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('res/hostidset'+str(fileid),'wb')
pickle.dump(hostidset, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('res/loadhist'+str(fileid),'wb')
pickle.dump(loadhist, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('res/time0'+str(fileid),'wb')
pickle.dump(time0, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('res/roundhost'+str(fileid),'wb')
pickle.dump(roundhost, f, pickle.HIGHEST_PROTOCOL)
f.close()

end = time.time()
print('time used: ',(end - start)/60,'min')
