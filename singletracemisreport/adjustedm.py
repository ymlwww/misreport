from scapy.all import *
from numpy import *
import random
import matplotlib.pyplot as plt
import numpy as np
import time
from collections import Counter
from scipy.special import comb
import pickle
import sys
import os
import math
'''
   misreport with a more accurate p considering the p shift and the correspondin new misreport frequency M
'''
pshift =[0.025, 0.06, 0.08, 0.08, 0.02, 0.03, 0.1, 0.075, 0.01, 0.03, 0.05, 0.06, 0.015, 0.025, 0.05, 0.075, 0.01, 0.075, 0.1, 0.2, 0.065, 0.035, 0.15, 0.13, 0.01, 0.07, 0.1, 0.4, 0.02, 0.075, 0.08, 0.075, 0.015, 0.125, 0.25, 0.3, 0.07, 0.5, 0.6, 0.6, 
          0.01, 0.05, 0.08, 0.07, 0.015, 0.09, 0.06, 0.09, 0.01, 0.05, 0.045, 0.07, 0.015, 0.025, 0.5, 0.1, 0.01, 0.27, 0.03, 0.06, 0.005, 0.05, 0.1, 0.075, 0.03, 0.125, 0.125, 0.075, 
          0.01, 0.05, 0.1, 0.2, 0.015, 0.05, 0.08, 0.15, 0.05, 0.06, 0.08, 0.125, 0.01, 0.07, 0.11, 0.3, 0.05, 0.075, 0.15, 0.3, 0.02, 0.15, 0.11, 0.065, 0.01, 0.05, 0.075, 0.05]

def lowerbound(p, N):
    ans = 0
    for i in range(N):
       ans = ans +  comb(N-1,i) * pow(p, i) * pow(1-p, N-1-i)/(i+1)
    return ans

def calm(p, shift, N, D, target):
    ret = 0 
    curmin = 100000
    testgroup = np.linspace(0.2,0.9, 1000)
    for item in testgroup:
        leftside = item*lowerbound(p+shift, N)
        rightside = item*lowerbound(p, N) + pow(1-item, D+1)
        if abs(leftside/2 + rightside/2- target)< curmin:
            curmin = abs(leftside/2 + rightside/2- target)
            ret = item
    return ret


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

hostidset1={}  # dict of flow id to host for stealthy misreport
loadpool1 = zeros(poolsize)
flowpool1 = zeros(poolsize)
flowhist1 = []
flowmatch1 = {}
loadhist1 = []
winhost1 = []
cheat1 = []

hostidset2={}  # dict of flow id to host for stealthy misreport
loadpool2 = zeros(poolsize)
flowpool2 = zeros(poolsize)
flowhist2 = []
flowmatch2 = {}
loadhist2 = []
winhost2 = []
cheat2 = []


hostidset3={}  # dict of flow id to host for stealthy misreport
loadpool3 = zeros(poolsize)
flowpool3 = zeros(poolsize)
flowhist3 = []
flowmatch3 = {}
loadhist3 = []
winhost3 = []
cheat3 = []


hostidset4={}  # dict of flow id to host for stealthy misreport
loadpool4 = zeros(poolsize)
flowpool4 = zeros(poolsize)
flowhist4 = []
flowmatch4 = {}
loadhist4 = []
winhost4 = []
cheat4 = []

roundhost = np.random.randint(0,high=poolsize)
print("first random host: "+str(roundhost))
roundhost1 = roundhost
roundhost2 = roundhost
roundhost3 = roundhost
roundhost4 = roundhost

collectload1 = []
collectload2 = []
collectload3 = []
collectload4 = []
target = 0.30 # 0.30
percent = [0.01, 0.05, 0.1, 0.2]
freq2 = (target - 1.0/poolsize)/(lowerbound(percent[0], poolsize) - 1.0/poolsize)
print("stealthy misreport frequency", str(freq2))

freq3 = (target - 1.0/poolsize)/(lowerbound(percent[1], poolsize) - 1.0/poolsize)
print("stealthy misreport frequency", str(freq3))

freq4 = (target - 1.0/poolsize)/(lowerbound(percent[2], poolsize) - 1.0/poolsize)
print("stealthy misreport frequency", str(freq4))

freq5 = (target - 1.0/poolsize)/(lowerbound(percent[3], poolsize) - 1.0/poolsize)
print("stealthy misreport frequency", str(freq5))

freq2 = calm(percent[0], pshift[(fileid-1)*4    ], 10, 10, target) + 0.05
freq3 = calm(percent[1], pshift[(fileid-1)*4 + 1], 10, 10, target) + 0.02
freq4 = calm(percent[2], pshift[(fileid-1)*4 + 2], 10, 10, target) - 0.02
freq5 = calm(percent[3], pshift[(fileid-1)*4 + 3], 10, 10, target) - 0.04
print("stealthy misreport frequency", str(freq2))
print("stealthy misreport frequency", str(freq3))
print("stealthy misreport frequency", str(freq4))
print("stealthy misreport frequency", str(freq5))

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
                collectload1 = loadarr[:math.floor((learn-collectstart)*percent[0])]
                collectload2 = loadarr[:math.floor((learn-collectstart)*percent[1])]
                collectload3 = loadarr[:math.floor((learn-collectstart)*percent[2])]
                collectload4 = loadarr[:math.floor((learn-collectstart)*percent[3])]
            loadpool = zeros(poolsize)
            flowpool = zeros(poolsize)
            flowmatch = {}
            if(cnt>=learn): 
                loadhist1.extend(loadpool1)
                flowhist1.extend(flowpool1)
                loadhist2.extend(loadpool2)
                flowhist2.extend(flowpool2)
                loadhist3.extend(loadpool3)
                flowhist3.extend(flowpool3)
                loadhist4.extend(loadpool4)
                flowhist4.extend(flowpool4)
                loadpool0 = zeros(poolsize)
                flowpool0 = zeros(poolsize)
                flowmatch0 = {}
                loadpool1 = zeros(poolsize)
                flowpool1 = zeros(poolsize)
                flowmatch1 = {}
                loadpool2 = zeros(poolsize)
                flowpool2 = zeros(poolsize)
                flowmatch2 = {}
                loadpool3 = zeros(poolsize)
                flowpool3 = zeros(poolsize)
                flowmatch3 = {}
                loadpool4 = zeros(poolsize)
                flowpool4 = zeros(poolsize)
                flowmatch4 = {}

        #update the min load host
        candidates = [i for i,x in enumerate(loadpool) if x==min(loadpool)]
        if(cnt == learn):
            tmp = loadhist[collectstart*poolsize:learn*poolsize:poolsize]
            loadarr = np.array(tmp)
            loadarr = np.sort(loadarr)
            collectload1 = loadarr[:math.floor((learn-collectstart)*percent[0])]
            collectload2 = loadarr[:math.floor((learn-collectstart)*percent[1])]
            collectload3 = loadarr[:math.floor((learn-collectstart)*percent[2])]
            collectload4 = loadarr[:math.floor((learn-collectstart)*percent[3])]
        if(cnt >= learn):
            if(cnt == learn):
                loadpool1 = loadpool
                loadpool2 = loadpool
                loadpool3 = loadpool
                loadpool4 = loadpool
            candidate1 = [i for i,x in enumerate(loadpool1) if x==min(loadpool1)]
            candidate2 = [i for i,x in enumerate(loadpool2) if x==min(loadpool2)]
            candidate3 = [i for i,x in enumerate(loadpool3) if x==min(loadpool3)]
            candidate4 = [i for i,x in enumerate(loadpool4) if x==min(loadpool4)]
            cheat1.append(0)
            cheat2.append(0)
            cheat3.append(0)
            cheat4.append(0)
            localtemp1 = loadpool1[0]
            localtemp2 = loadpool2[0]
            localtemp3 = loadpool3[0]
            localtemp4 = loadpool4[0]
            if(random.uniform(0.0, 1.0) < freq2):
                loadpool1[0] = random.uniform(collectload1[0], collectload1[-1])
                loadpool1[0] = min(localtemp1,loadpool1[0])
                cheat1[-1] = 1
                candidate1 = [i for i,x in enumerate(loadpool1) if x==min(loadpool1)]
            if(random.uniform(0.0, 1.0) < freq3):
                loadpool2[0] = random.uniform(collectload2[0], collectload2[-1])
                loadpool2[0] = min(localtemp2,loadpool2[0])
                cheat2[-1] = 1
                candidate2 = [i for i,x in enumerate(loadpool2) if x==min(loadpool2)]
            if(random.uniform(0.0, 1.0) < freq4):
                loadpool3[0] = random.uniform(collectload3[0], collectload3[-1])
                loadpool3[0] = min(localtemp3,loadpool3[0])
                cheat3[-1] = 1
                candidate3 = [i for i,x in enumerate(loadpool3) if x==min(loadpool3)]
            if(random.uniform(0.0, 1.0) < freq5):
                loadpool4[0] = random.uniform(collectload4[0], collectload4[-1])
                loadpool4[0] = min(localtemp4,loadpool4[0])
                cheat4[-1] = 1
                candidate4 = [i for i,x in enumerate(loadpool4) if x==min(loadpool4)]
            if(len(candidate1) > 1):
                roundhost1 = candidate1[np.random.randint(0,high = len(candidate1))]
            else:
                roundhost1 = candidate1[0]
            if(len(candidate2) > 1):
                roundhost2 = candidate2[np.random.randint(0,high = len(candidate2))]
            else:
                roundhost2 = candidate2[0]
            if(len(candidate3) > 1):
                roundhost3 = candidate3[np.random.randint(0,high = len(candidate3))]
            else:
                roundhost3 = candidate3[0]
            if(len(candidate4) > 1):
                roundhost4 = candidate4[np.random.randint(0,high = len(candidate4))]
            else:
                roundhost4 = candidate4[0]
            winhost1.append(roundhost1)
            winhost2.append(roundhost2)
            winhost3.append(roundhost3)
            winhost4.append(roundhost4)
            loadpool1[0] = localtemp1
            loadhist1.extend(loadpool1)
            flowhist1.extend(flowpool1)
            loadpool1 = zeros(poolsize)
            flowpool1 = zeros(poolsize)
            flowmatch1 = {}
            loadpool2[0] = localtemp2
            loadhist2.extend(loadpool2)
            flowhist2.extend(flowpool2)
            loadpool2 = zeros(poolsize)
            flowpool2 = zeros(poolsize)
            flowmatch2 = {}
            loadpool3[0] = localtemp3
            loadhist3.extend(loadpool3)
            flowhist3.extend(flowpool3)
            loadpool3 = zeros(poolsize)
            flowpool3 = zeros(poolsize)
            flowmatch3 = {}
            loadpool4[0] = localtemp4
            loadhist4.extend(loadpool4)
            flowhist4.extend(flowpool4)
            loadpool4 = zeros(poolsize)
            flowpool4 = zeros(poolsize)
            flowmatch4 = {}
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
                        loadpool1[hostidset1[tmp]] = loadpool1[hostidset1[tmp]] + p.wirelen
                        loadpool2[hostidset2[tmp]] = loadpool2[hostidset2[tmp]] + p.wirelen
                        loadpool3[hostidset3[tmp]] = loadpool3[hostidset3[tmp]] + p.wirelen
                        loadpool4[hostidset4[tmp]] = loadpool4[hostidset4[tmp]] + p.wirelen
                        if tmp not in flowmatch1.keys():
                            flowpool1[hostidset1[tmp]] = flowpool1[hostidset1[tmp]] + 1
                            flowmatch1[tmp] = hostidset1[tmp]
                        if tmp not in flowmatch2.keys():
                            flowpool2[hostidset2[tmp]] = flowpool2[hostidset2[tmp]] + 1
                            flowmatch2[tmp] = hostidset2[tmp]
                        if tmp not in flowmatch3.keys():
                            flowpool3[hostidset3[tmp]] = flowpool3[hostidset3[tmp]] + 1
                            flowmatch3[tmp] = hostidset3[tmp]
                        if tmp not in flowmatch4.keys():
                            flowpool4[hostidset4[tmp]] = flowpool4[hostidset4[tmp]] + 1
                            flowmatch4[tmp] = hostidset4[tmp]
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
                   hostidset1[tmp] = roundhost1
                   hostidset2[tmp] = roundhost2
                   hostidset3[tmp] = roundhost3
                   hostidset4[tmp] = roundhost4
                   loadpool1[roundhost1] = loadpool1[roundhost1] + p.wirelen
                   flowpool1[roundhost1] = flowpool1[roundhost1] + 1
                   flowmatch1[tmp] = roundhost1
                   loadpool2[roundhost2] = loadpool2[roundhost2] + p.wirelen
                   flowpool2[roundhost2] = flowpool2[roundhost2] + 1
                   flowmatch2[tmp] = roundhost2
                   loadpool3[roundhost3] = loadpool3[roundhost3] + p.wirelen
                   flowpool3[roundhost3] = flowpool3[roundhost3] + 1
                   flowmatch3[tmp] = roundhost3
                   loadpool4[roundhost4] = loadpool4[roundhost4] + p.wirelen
                   flowpool4[roundhost4] = flowpool4[roundhost4] + 1
                   flowmatch4[tmp] = roundhost4
                else:
                   hostidset1[tmp] = roundhost
                   hostidset2[tmp] = roundhost
                   hostidset3[tmp] = roundhost
                   hostidset4[tmp] = roundhost
        else:
            hostidset[tmp] = roundhost
            loadpool[roundhost] = loadpool[roundhost] + p.wirelen
            flowpool[roundhost] = flowpool[roundhost] + 1
            flowmatch[tmp] = roundhost
            lastsee[tmp] = p.time
            if(cnt>=learn):
                hostidset1[tmp] = roundhost1
                hostidset2[tmp] = roundhost2
                hostidset3[tmp] = roundhost3
                hostidset4[tmp] = roundhost4
                loadpool1[roundhost1] = loadpool1[roundhost1] + p.wirelen
                flowpool1[roundhost1] = flowpool1[roundhost1] + 1
                flowmatch1[tmp] = roundhost1
                loadpool2[roundhost2] = loadpool2[roundhost2] + p.wirelen
                flowpool2[roundhost2] = flowpool2[roundhost2] + 1
                flowmatch2[tmp] = roundhost2
                loadpool3[roundhost3] = loadpool3[roundhost3] + p.wirelen
                flowpool3[roundhost3] = flowpool3[roundhost3] + 1
                flowmatch3[tmp] = roundhost3
                loadpool4[roundhost4] = loadpool4[roundhost4] + p.wirelen
                flowpool4[roundhost4] = flowpool4[roundhost4] + 1
                flowmatch4[tmp] = roundhost4
            else:
                hostidset1[tmp] = roundhost
                hostidset2[tmp] = roundhost
                hostidset3[tmp] = roundhost
                hostidset4[tmp] = roundhost

f = open('misreport_0_'+str(fileid),'wb')
pickle.dump(loadhist, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('flowmisreport_0_'+str(fileid),'wb')
pickle.dump(flowhist, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('flowmisreport_2_'+str(fileid),'wb')
pickle.dump(flowhist1, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('flowmisreport_3_'+str(fileid),'wb')
pickle.dump(flowhist2, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('flowmisreport_4_'+str(fileid),'wb')
pickle.dump(flowhist3, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('flowmisreport_5_'+str(fileid),'wb')
pickle.dump(flowhist4, f, pickle.HIGHEST_PROTOCOL)
f.close()

f= open('misreport_0win_'+str(fileid),'wb')
pickle.dump(winhost, f, pickle.HIGHEST_PROTOCOL)
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

f = open('misreport_3_'+str(fileid),'wb')
pickle.dump(loadhist2, f , pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_3win_'+str(fileid),'wb')
pickle.dump(winhost2, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_3cheat_'+str(fileid),'wb')
pickle.dump(cheat2, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_4_'+str(fileid),'wb')
pickle.dump(loadhist3, f , pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_4win_'+str(fileid),'wb')
pickle.dump(winhost3, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_4cheat_'+str(fileid),'wb')
pickle.dump(cheat3, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_5_'+str(fileid),'wb')
pickle.dump(loadhist4, f , pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_5win_'+str(fileid),'wb')
pickle.dump(winhost4, f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('misreport_5cheat_'+str(fileid),'wb')
pickle.dump(cheat4, f, pickle.HIGHEST_PROTOCOL)
f.close()

end = time.time()
print('time used: ',(end - start)/60,'min')
