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
    simulate the case when the malicious switch misreports by trivial or stealthy attack
    the trivial max damage load balance model
    the trivial attack means only misreport 0 
    although there may exist better to way to launch max dmg
    the damage is measured as the percentage of the accumulate load difference over the total traffic load in the subnets
'''
start = time.time() #start timer

fileid = int(sys.argv[1])
pkts = PcapReader('data/'+str(fileid)+'.pcap')

#set params
poolsize = 10
hostidset={}  # dict of flow id to host 
lastsee={} # dict of the last time that the flow is seen
idle_timeout = 10 # soft time-out is 10s
loadpool = zeros(poolsize) #load of each epoch
flowpool = zeros(poolsize) # number of flow each member each epoch
flowhist = [] # history of flow pool 
flowmatch = {}
loadhist = []  #  list for the load of the first host and the average
winhost = []  # the host who wins the time epoch
time0 = 0.0
counter = 0
learn = 600 # seconds to collect load report
collectstart = 100

hostidset0={}  # dict of flow id to host for trivial misreport
loadpool0 = zeros(poolsize) 
flowpool0 = zeros(poolsize)
flowhist0 = []
flowmatch0 = {}
loadhist0 = []
winhost0 = []
cheat0 = []
diff0 = []

hostidset1={}  # dict of flow id to host for stealthy misreport
loadpool1 = zeros(poolsize)
flowpool1 = zeros(poolsize)
flowhist1 = []
flowmatch1 = {}
loadhist1 = []
winhost1 = []
cheat1 = []
diff1= []
roundhost = np.random.randint(0,high=poolsize)
print("first random host: "+str(roundhost))
roundhost0 = roundhost
roundhost1 = roundhost

collectload = []
target = 0.30 # 0.30
percent = 0.01
freq1 = (target - 1.0/poolsize)/(1 - 1.0/poolsize)  # trivial attack misreport frequency
print("trivial misreport frequency",str(freq1))
freq2 = (target - 1.0/poolsize)/(pow(1 - percent, poolsize - 1) - 1.0/poolsize) # stealthy attack misreport frequency
print("stealthy misreport frequency", str(freq2))
winhost.append(roundhost)
cnt = 0 #time epoch counter, collect 600 times before attack

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
                winhost.extend(20)
                loadhist.extend(loadpool)
                flowhist.extend(flowpool)
            if(cnt == learn):
                tmp = loadhist[collectstart*poolsize:learn*poolsize:poolsize]
                loadarr = np.array(tmp)
                loadarr = np.sort(loadarr)
                collectload = loadarr[:math.floor((learn-collectstart)*percent)]
                print(collectload)
            loadpool = zeros(poolsize)
            flowpool = zeros(poolsize)
            flowmatch = {}
            if(cnt>=learn): 
                loadhist0.extend(loadpool0)
                flowhist0.extend(flowpool0)
                loadhist1.extend(loadpool1)
                flowhist1.extend(flowpool1)
                loadpool0 = zeros(poolsize)
                flowpool0 = zeros(poolsize)
                flowmatch0 = {}
                loadpool1 = zeros(poolsize)
                flowpool1 = zeros(poolsize)
                flowmatch1 = {}
        #update the min load host
        candidates = [i for i,x in enumerate(loadpool) if x==min(loadpool)]
        if(cnt == learn):
            tmp = loadhist[collectstart*poolsize:learn*poolsize:poolsize]
            loadarr = np.array(tmp)
            loadarr = np.sort(loadarr)
            collectload = loadarr[:math.floor((learn-collectstart)*percent)]
            print(collectload)
        if(cnt >= learn):
            if(cnt == learn):
                loadpool0 = loadpool
                loadpool1 = loadpool
            candidate0 = [i for i,x in enumerate(loadpool0) if x==min(loadpool0)]
            candidate1 = [i for i,x in enumerate(loadpool1) if x==min(loadpool1)]
            diff0.append(0)
            cheat0.append(0)
            diff1.append(0)
            cheat1.append(0)
            localtemp0 = loadpool0[0]
            localtemp1 = loadpool1[0]
            if(random.uniform(0.0, 1.0) < freq1):
                loadpool0[0] = 0
                cheat0[-1] = 1
                candidate0_tmp = candidate0
                candidate0 = [i for i,x in enumerate(loadpool0) if x==min(loadpool0)]
                if(candidate0 != candidate0_tmp):
                    diff0[-1] = 1
            if(random.uniform(0.0, 1.0) < freq2):
                loadpool1[0] = random.uniform(collectload[0], collectload[-1])
                loadpool1[0] = min(localtemp1,loadpool1[0])
                cheat1[-1] = 1
                candidate1_tmp = candidate1
                candidate1 = [i for i,x in enumerate(loadpool1) if x==min(loadpool1)]
                if(candidate1 != candidate1_tmp):
                    diff1[-1] = 1
            if(len(candidate0) > 1):
                roundhost0 = candidate0[np.random.randint(0,high = len(candidate0))]
            else:
                roundhost0 = candidate0[0]
            if(len(candidate1) > 1):
                roundhost1 = candidate1[np.random.randint(0,high = len(candidate1))]
            else:
                roundhost1 = candidate1[0]
            winhost0.append(roundhost0)
            winhost1.append(roundhost1)
            loadpool0[0] = localtemp0
            loadhist0.extend(loadpool0)
            flowhist0.extend(flowpool0)
            loadpool0 = zeros(poolsize)
            flowpool0 = zeros(poolsize)
            flowmatch0 = {}
            loadpool1[0] = localtemp1
            loadhist1.extend(loadpool1)
            flowhist1.extend(flowpool1)
            loadpool1 = zeros(poolsize)
            flowpool1 = zeros(poolsize)
            flowmatch1 = {}
        if(len(candidates) > 1):
            roundhost = candidates[np.random.randint(0,high = len(candidates))]
        else:
            roundhost = candidates[0]
        if(cnt > 1):
            winhost.append(roundhost)
            loadhist.extend(loadpool)
            flowhist.extend(flowpool)
        loadpool = zeros(poolsize)
        flowpool = zeros(poolsize)
        flowmatch = {}
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
    if(cnt<=1):
        hostidset[tmp] = 2*poolsize
        lastsee[tmp] = p.time
    else:
        if tmp in hostidset.keys():
            if(p.time - lastsee[tmp])<idle_timeout:
                if(hostidset[tmp]>poolsize):
                    lastsee[tmp] = p.time
                else:
                    lastsee[tmp] = p.time
                    loadpool[hostidset[tmp]] = loadpool[hostidset[tmp]] + p.wirelen
                    if(cnt>=learn):
                        loadpool0[hostidset0[tmp]] = loadpool0[hostidset0[tmp]] + p.wirelen
                        loadpool1[hostidset1[tmp]] = loadpool1[hostidset1[tmp]] + p.wirelen
                        if tmp not in flowmatch0.keys():
                            flowpool0[hostidset0[tmp]] = flowpool0[hostidset0[tmp]] + 1
                            flowmatch0[tmp] = hostidset0[tmp]
                        if tmp not in flowmatch1.keys():
                            flowpool1[hostidset1[tmp]] = flowpool1[hostidset1[tmp]] + 1
                            flowmatch1[tmp] = hostidset1[tmp]
                    if tmp not in flowmatch.keys():
                        flowpool[hostidset[tmp]] = flowpool[hostidset[tmp]] + 1
                        flowmatch[tmp] = hostidset[tmp]
            else:
                hostidset[tmp] = roundhost
                loadpool[roundhost] = loadpool[roundhost] + p.wirelen
                flowpool[roundhost] = flowpool[roundhost] + 1
                flowmatch[tmp] = roundhost
                lastsee[tmp] = p.time
                if(cnt>=learn):
                   hostidset0[tmp] = roundhost0
                   hostidset1[tmp] = roundhost1
                   loadpool0[roundhost0] = loadpool0[roundhost0] + p.wirelen
                   flowpool0[roundhost0] = flowpool0[roundhost0] + 1
                   flowmatch0[tmp] = roundhost0
                   loadpool1[roundhost1] = loadpool1[roundhost1] + p.wirelen
                   flowpool1[roundhost1] = flowpool1[roundhost1] + 1
                   flowmatch1[tmp] = roundhost1
                else:
                   hostidset0[tmp] = roundhost
                   hostidset1[tmp] = roundhost
        else:
            hostidset[tmp] = roundhost
            loadpool[roundhost] = loadpool[roundhost] + p.wirelen
            flowpool[roundhost] = flowpool[roundhost] + 1
            flowmatch[tmp] = roundhost
            lastsee[tmp] = p.time
            if(cnt>=learn):
                hostidset0[tmp] = roundhost0
                hostidset1[tmp] = roundhost1
                loadpool0[roundhost0] = loadpool0[roundhost0] + p.wirelen
                flowpool0[roundhost0] = flowpool0[roundhost0] + 1
                flowmatch0[tmp] = roundhost0
                loadpool1[roundhost1] = loadpool1[roundhost1] + p.wirelen
                flowpool1[roundhost1] = flowpool1[roundhost1] + 1
                flowmatch1[tmp] = roundhost1
            else:
                hostidset0[tmp] = roundhost
                hostidset1[tmp] = roundhost

f = open('misreport_0_'+str(fileid),'wb')
pickle.dump(loadhist, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('flowmisreport_0_'+str(fileid),'wb')
pickle.dump(flowhist, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('flowmisreport_1_'+str(fileid),'wb')
pickle.dump(flowhist0, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('flowmisreport_2_'+str(fileid),'wb')
pickle.dump(flowhist1, f, pickle.HIGHEST_PROTOCOL)
f.close()

f= open('misreport_0win_'+str(fileid),'wb')
pickle.dump(winhost, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_1_'+str(fileid),'wb')
pickle.dump(loadhist0, f ,pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_1win_'+str(fileid),'wb')
pickle.dump(winhost0, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_1cheat_'+str(fileid),'wb')
pickle.dump(cheat0, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_1diff_'+str(fileid),'wb')
pickle.dump(diff0, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_2_'+str(fileid),'wb')
pickle.dump(loadhist1, f , pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_2win_'+str(fileid),'wb')
pickle.dump(winhost1, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_2cheat_'+str(fileid),'wb')
pickle.dump(cheat1, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_2diff_'+str(fileid),'wb')
pickle.dump(diff1, f, pickle.HIGHEST_PROTOCOL)
f.close()

end = time.time()
print('time used: ',(end - start)/60,'min')
print(collectload)
