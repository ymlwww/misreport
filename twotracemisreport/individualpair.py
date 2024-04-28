'''
   simulate and get the individual IP that the switch can observe with different parameters
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
percent = float(sys.argv[2]) #0.01
#get the pcap file list
fileList = os.listdir(os.getcwd())
fileList = sorted([x for x in fileList if "pcap" in x])
print("read file: "+fileList[fileid+1])

#constants
poolsize = 10
idle = 10 #idle time out

#individual IP pair codes for different misreport frequency and p

f = open('res/loadpool'+str(fileid), 'rb')
loadpool = pickle.load(f)
f.close()

f = open('res/lastsee'+str(fileid), 'rb')
lastsee = pickle.load(f)
f.close()

f = open('res/hostidset'+str(fileid), 'rb')
hostidset = pickle.load(f)
f.close()

f = open('res/loadhist'+str(fileid), 'rb')
loadhist = pickle.load(f)
f.close()

f = open('res/time0'+str(fileid), 'rb')
time0 = pickle.load(f)
f.close()

f = open('res/roundhost'+str(fileid), 'rb')
roundhost = pickle.load(f)
f.close()

hostidset2=hostidset  # dict of flow to host case 2
hostidset3=hostidset  # dict of flow to host case 3
hostidset4=hostidset  # dict of flow to host case 4
hostidset5=hostidset  # dict of flow to host case 5 
hostidset6=hostidset  # dict of flow to host case 6

loadpool2 = loadpool  #load of each epoch case 2
loadpool3 = loadpool  #load of each epoch case 3
loadpool4 = loadpool  #load of each epoch case 4
loadpool5 = loadpool  #load of each epoch case 5
loadpool6 = loadpool  #load of each epoch case 6

counter = 0 #reset pkt counter

pairdict={} # map IP src dst IP pair to a vector of 6 cases and the total

collectload = loadhist[poolsize*100::poolsize]
loadarr = np.array(collectload)
loadarr = np.sort(loadarr)
collectload = loadarr[:math.floor(len(loadarr)*percent)]
print(len(collectload))
roundhost2 = roundhost
roundhost3 = roundhost
roundhost4 = roundhost
roundhost5 = roundhost
roundhost6 = roundhost

cnt = 0 #time epoch counter
pkts = PcapReader(fileList[fileid+1])
for p in pkts:
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
            loadpool2 = zeros(poolsize)
            loadpool3 = zeros(poolsize)
            loadpool4 = zeros(poolsize)
            loadpool5 = zeros(poolsize)
            loadpool6 = zeros(poolsize)
        #update the min load host
        candidate1 = [i for i,x in enumerate(loadpool) if x==min(loadpool)]
        tmp = random.uniform(collectload[0], collectload[-1])
        candidate2 = [i for i,x in enumerate(loadpool2) if x==min(loadpool2)]
        if(cnt%20 == 0):
            loadpool2[0] = min(tmp,loadpool2[0])
            candidate2 = [i for i,x in enumerate(loadpool2) if x==min(loadpool2)]
        candidate3 = [i for i,x in enumerate(loadpool3) if x==min(loadpool3)]
        if(cnt%10 == 0):
            loadpool3[0] = min(tmp,loadpool3[0])
            candidate3 = [i for i,x in enumerate(loadpool3) if x==min(loadpool3)]
        candidate4 = [i for i,x in enumerate(loadpool4) if x==min(loadpool4)]
        if(cnt%6 == 0):
            loadpool4[0] = min(tmp,loadpool4[0])
            candidate4 = [i for i,x in enumerate(loadpool4) if x==min(loadpool4)]
        candidate5 = [i for i,x in enumerate(loadpool5) if x==min(loadpool5)]
        if(cnt%5 == 0):
            loadpool5[0] = min(tmp,loadpool5[0])
            candidate5 = [i for i,x in enumerate(loadpool5) if x==min(loadpool5)]
        candidate6 = [i for i,x in enumerate(loadpool6) if x==min(loadpool6)]
        if(cnt%4 == 0):
            loadpool6[0] = min(tmp,loadpool6[0])
            candidate6 = [i for i,x in enumerate(loadpool6) if x==min(loadpool6)]
        if(len(candidate1) > 1):
            roundhost = candidate1[np.random.randint(0,high = len(candidate1))]
        else:
            roundhost = candidate1[0]
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
        if(len(candidate5) > 1):
            roundhost5 = candidate5[np.random.randint(0,high = len(candidate5))]
        else:
            roundhost5 = candidate5[0]
        if(len(candidate6) > 1):
            roundhost6 = candidate6[np.random.randint(0,high = len(candidate6))]
        else:
            roundhost6 = candidate6[0]
        loadpool = zeros(poolsize)
        loadpool2 = zeros(poolsize)
        loadpool3 = zeros(poolsize)
        loadpool4 = zeros(poolsize)
        loadpool5 = zeros(poolsize)
        loadpool6 = zeros(poolsize)
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
    src = tmp.split(',')[0]
    dst = tmp.split(',')[1]
    if tmp in hostidset.keys():
        if(p.time - lastsee[tmp])<idle:
            lastsee[tmp] = p.time
            if(hostidset[tmp]<poolsize):
                loadpool[hostidset[tmp]] = loadpool[hostidset[tmp]] + p.wirelen
            if(hostidset2[tmp]<poolsize):
                loadpool2[hostidset2[tmp]] = loadpool2[hostidset2[tmp]] + p.wirelen
            if(hostidset3[tmp]<poolsize):
                loadpool3[hostidset3[tmp]] = loadpool3[hostidset3[tmp]] + p.wirelen
            if(hostidset4[tmp]<poolsize):
                loadpool4[hostidset4[tmp]] = loadpool4[hostidset4[tmp]] + p.wirelen
            if(hostidset5[tmp]<poolsize):
                loadpool5[hostidset5[tmp]] = loadpool5[hostidset5[tmp]] + p.wirelen
            if(hostidset6[tmp]<poolsize):
                loadpool6[hostidset6[tmp]] = loadpool6[hostidset6[tmp]] + p.wirelen
        else:
            lastsee[tmp] = p.time
            hostidset[tmp] = roundhost
            hostidset2[tmp] = roundhost2
            hostidset3[tmp] = roundhost3
            hostidset4[tmp] = roundhost4
            hostidset5[tmp] = roundhost5
            hostidset6[tmp] = roundhost6
            loadpool[roundhost] = loadpool[roundhost] + p.wirelen
            loadpool2[roundhost2] = loadpool2[roundhost2] + p.wirelen
            loadpool3[roundhost3] = loadpool3[roundhost3] + p.wirelen
            loadpool4[roundhost4] = loadpool4[roundhost4] + p.wirelen
            loadpool5[roundhost5] = loadpool5[roundhost5] + p.wirelen
            loadpool6[roundhost6] = loadpool6[roundhost6] + p.wirelen
            pair = src+dst
            if pair not in pairdict.keys():
                pairdict[pair] = zeros(7)
                pairdict[pair][6] = 1
                if roundhost == 0:
                    pairdict[pair][0] = 1
                if roundhost2 == 0:
                    pairdict[pair][1] = 1
                if roundhost3 == 0:
                    pairdict[pair][2] = 1
                if roundhost4 == 0:
                    pairdict[pair][3] = 1
                if roundhost5 == 0:
                    pairdict[pair][4] = 1
                if roundhost6 == 0:
                    pairdict[pair][5] = 1
            else:
                pairdict[pair][6] = pairdict[pair][6] + 1 
                if roundhost == 0:
                    pairdict[pair][0] = pairdict[pair][0] + 1
                if roundhost2 == 0:
                    pairdict[pair][1] = pairdict[pair][1] + 1
                if roundhost3 == 0:
                    pairdict[pair][2] = pairdict[pair][2] + 1
                if roundhost4 == 0:
                    pairdict[pair][3] = pairdict[pair][3] + 1
                if roundhost5 == 0:
                    pairdict[pair][4] = pairdict[pair][4] + 1
                if roundhost6 == 0:
                    pairdict[pair][5] = pairdict[pair][5] + 1
    else:
        lastsee[tmp] = p.time
        hostidset[tmp] = roundhost
        hostidset2[tmp] = roundhost2
        hostidset3[tmp] = roundhost3
        hostidset4[tmp] = roundhost4
        hostidset5[tmp] = roundhost5
        hostidset6[tmp] = roundhost6
        loadpool[roundhost] = loadpool[roundhost] + p.wirelen
        loadpool2[roundhost2] = loadpool2[roundhost2] + p.wirelen
        loadpool3[roundhost3] = loadpool3[roundhost3] + p.wirelen
        loadpool4[roundhost4] = loadpool4[roundhost4] + p.wirelen
        loadpool5[roundhost5] = loadpool5[roundhost5] + p.wirelen
        loadpool6[roundhost6] = loadpool6[roundhost6] + p.wirelen
        pair = src+dst
        if pair not in pairdict.keys():
            pairdict[pair] = zeros(7)
            pairdict[pair][6] = 1
            if roundhost == 0:
                pairdict[pair][0] = 1
            if roundhost2 == 0:
                pairdict[pair][1] = 1
            if roundhost3 == 0:
                pairdict[pair][2] = 1
            if roundhost4 == 0:
                pairdict[pair][3] = 1
            if roundhost5 == 0:
                pairdict[pair][4] = 1
            if roundhost6 == 0:
                pairdict[pair][5] = 1
        else:
            pairdict[pair][6] = pairdict[pair][6] + 1
            if roundhost == 0:
                pairdict[pair][0] = pairdict[pair][0] + 1
            if roundhost2 == 0:
                pairdict[pair][1] = pairdict[pair][1] + 1
            if roundhost3 == 0:
                pairdict[pair][2] = pairdict[pair][2] + 1
            if roundhost4 == 0:
                pairdict[pair][3] = pairdict[pair][3] + 1
            if roundhost5 == 0:
                pairdict[pair][4] = pairdict[pair][4] + 1
            if roundhost6 == 0:
                pairdict[pair][5] = pairdict[pair][5] + 1
pkts.close()
avg = 0 # average IP pair appearance
for item in pairdict.keys():
   avg = avg + pairdict[item][6]
avg = avg/len(pairdict.keys())
print(avg)
elephants = {}
for item in pairdict.keys():
    if(pairdict[item][6] > avg):
        elephants[item] = pairdict[item]
f = open('res/individualpairdict'+str(fileid)+'_p_'+str(percent),'wb')
pickle.dump(elephants, f, pickle.HIGHEST_PROTOCOL)
f.close()

ans = np.zeros(7)
ans[6] = len(pairdict.keys())
for item in pairdict.keys():
    if pairdict[item][0]>0:
        ans[0] = ans[0] + 1
    if pairdict[item][1]>0:
        ans[1] = ans[1] + 1
    if pairdict[item][2]>0:
        ans[2] = ans[2] + 1
    if pairdict[item][3]>0:
        ans[3] = ans[3] + 1
    if pairdict[item][4]>0:
        ans[4] = ans[4] + 1
    if pairdict[item][5]>0:
        ans[5] = ans[5] + 1 
f = open('res/individualpaircnt'+str(fileid)+'_p_'+str(percent),'wb')
pickle.dump(ans, f, pickle.HIGHEST_PROTOCOL)
f.close()

end = time.time()
print('time used: ',(end - start)/60,'min')
