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
attack specific ip flows
'''

start = time.time() #start timer

fileid = int(sys.argv[1]) + 1
trackid = int(sys.argv[2])
prepareid = int(sys.argv[3])
#get the pcap file list
fileList = os.listdir(os.getcwd())
fileList = sorted([x for x in fileList if "pcap" in x])
print("read file: "+fileList[fileid])

#set params
tracklist = ["203.116.111.195", "203.116.121.169", "203.116.121.138"]
iptrack = tracklist[trackid]
poolsize = 10
idle_timeout = 10 # soft time-out is 10s
time0 = 0.0
lastsee={} # dict of the last time that the flow is seen

#honest case
hostidset={}  # dict of flow id to host
loadpool = zeros(poolsize) #load of each epoch

#misreport 25% of the time continuously
hostidset1={}  # dict of flow id to host for stealthy misreport
loadpool1 = zeros(poolsize)

#misreport 25% of the time every 4th time
hostidset2={}  # dict of flow id to host for stealthy misreport
loadpool2 = zeros(poolsize)

roundhost = np.random.randint(0,high=poolsize)
print("first random host: "+str(roundhost))
roundhost1 = roundhost
roundhost2 = roundhost

#get load report history from most recent trace
f = open('res/loadhist'+str(prepareid), 'rb')
loadhist = pickle.load(f)
f.close()

loadarr = np.array(loadhist[poolsize*100::poolsize])
loadarr = np.sort(loadarr)
collectload = loadarr[:math.floor(len(loadarr)*0.01)]

cnt = 0 #time epoch counter, collect 600 times before attack
track = np.zeros(6) #track array: total load, new attack load, old attack old, total flow number, new attack flow no, old attack flow no
counter = 0 #reset pkt counter
pkts = PcapReader(fileList[fileid])
misreportcnt = 0
special = 0
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
            loadpool1 = zeros(poolsize)
            loadpool2 = zeros(poolsize)
        #update the min load host
        candidate  = [i for i,x in enumerate(loadpool) if x==min(loadpool)]
        candidate1 = [i for i,x in enumerate(loadpool1) if x==min(loadpool1)]
        candidate2 = [i for i,x in enumerate(loadpool2) if x==min(loadpool2)]
        if(cnt>= 50 and cnt%4  == 0):
            tmp1 = 0.1*random.uniform(collectload[0], collectload[-1])
            loadpool2[0] = min(tmp1,loadpool2[0])
            candidate2 = [i for i,x in enumerate(loadpool2) if x==min(loadpool2)]
        if(special == 0):
            if(cnt>= 50 and cnt%4  == 0):
                misreportcnt = misreportcnt + 1
                tmp0 = 0.1*random.uniform(collectload[0], collectload[-1])
                loadpool1[0] = min(tmp0,loadpool1[0])
                candidate1 = [i for i,x in enumerate(loadpool1) if x==min(loadpool1)]
        else:
            if(misreportcnt<=225):
                misreportcnt = misreportcnt + 1
                tmp0 = 0.1*random.uniform(collectload[0], collectload[-1])
                loadpool1[0] = min(tmp0,loadpool1[0])
                candidate1 = [i for i,x in enumerate(loadpool1) if x==min(loadpool1)]
        if(len(candidate) > 1):
            roundhost = candidate[np.random.randint(0,high = len(candidate))]
        else:
            roundhost = candidate[0]
        if(len(candidate1) > 1):
            roundhost1 = candidate1[np.random.randint(0,high = len(candidate1))]
        else:
            roundhost1 = candidate1[0]
        if(len(candidate2) > 1):
            roundhost2 = candidate2[np.random.randint(0,high = len(candidate2))]
        else:
            roundhost2 = candidate2[0]
        loadpool = zeros(poolsize)
        loadpool1 = zeros(poolsize)
        loadpool2 = zeros(poolsize)
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
    tmp = ",".join(item)   #note that this method would classify tcp and its syn to two flows
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
                    loadpool1[hostidset1[tmp]] = loadpool1[hostidset1[tmp]] + p.wirelen
                    loadpool2[hostidset2[tmp]] = loadpool2[hostidset2[tmp]] + p.wirelen
            else:
                hostidset[tmp] = roundhost
                loadpool[roundhost] = loadpool[roundhost] + p.wirelen
                lastsee[tmp] = p.time
                hostidset1[tmp] = roundhost1
                loadpool1[roundhost1] = loadpool1[roundhost1] + p.wirelen
                hostidset2[tmp] = roundhost2
                loadpool2[roundhost2] = loadpool2[roundhost2] + p.wirelen
                if(len(tmp.split(',')) >=2):
                    src = tmp.split(',')[0]
                    dst = tmp.split(',')[1]
                    rsrc = src.split("_")[1]
                    if((rsrc == iptrack) or (dst == iptrack)):
                        if(cnt>=50):
                            special = 1
                        track[3] = track[3] + 1
                        if hostidset1[tmp] == 0:
                            track[4]= track[4] + 1
                        if hostidset2[tmp] == 0:
                            track[5]= track[5] + 1
        else:
            hostidset[tmp] = roundhost
            loadpool[roundhost] = loadpool[roundhost] + p.wirelen
            lastsee[tmp] = p.time
            hostidset1[tmp] = roundhost1
            loadpool1[roundhost1] = loadpool1[roundhost1] + p.wirelen
            hostidset2[tmp] = roundhost2
            loadpool2[roundhost2] = loadpool2[roundhost2] + p.wirelen
            if(len(tmp.split(',')) >=2):
                src = tmp.split(',')[0]
                dst = tmp.split(',')[1]
                rsrc = src.split("_")[1]
                if((rsrc == iptrack) or (dst == iptrack)):
                    if(cnt >= 50):
                        special = 1
                    track[3] = track[3] + 1
                    if hostidset1[tmp] == 0:
                        track[4]= track[4] + 1
                    if hostidset2[tmp] == 0:
                        track[5]= track[5] + 1
        if(len(tmp.split(',')) >=2):
            #print("yes")
            if counter%100000==0:
                print(track,special,cnt,roundhost)
            src = tmp.split(',')[0]
            dst = tmp.split(',')[1]
            rsrc = src.split("_")[1]
            if((rsrc == iptrack) or (dst == iptrack)):
                if(cnt >= 50):
                    special = 1
                if(hostidset[tmp] < poolsize):
                    track[0] = track[0] + p.wirelen
                if(tmp in hostidset1 and hostidset1[tmp] == 0):
                    track[1]= track[1] + p.wirelen
                if(tmp in hostidset2 and hostidset2[tmp] == 0):
                    track[2]= track[2] + p.wirelen


pkts.close()
print(fileid)
print(trackid)
print(track)
f = open('iptrack_'+str(fileid)+"_"+str(trackid),'wb')
pickle.dump(track, f, pickle.HIGHEST_PROTOCOL)
f.close()

end = time.time()
print('time used: ',(end - start)/60,'min')
