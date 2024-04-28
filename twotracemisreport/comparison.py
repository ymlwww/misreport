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

#find the 10 most frequest IP pairs and IP address
f = open('res/pairdict'+str(fileid)+'_p_0.01', 'rb')
pairset = pickle.load(f)
f.close()
#find the 10 most frequest IP pairs
brr = list(pairset.items())
arr = sorted(brr, key=lambda x: x[1][5], reverse=True)
tracklist = []
for i in range(0,10):
    tracklist.append(arr[i*2][0])
    print(arr[i*2][1])
print(tracklist)

#find the 10 most frequest IP address
IPcount = {}
for IPpair in pairset.keys():
    #get IPs from the pair
    IPpair = IPpair.split("_")[1]
    srcip =""
    dstip =""
    ipseg = IPpair.split(".")
    if(len(ipseg) !=7):
        continue
    #print(ipseg)
    match len(ipseg[3]):
        case 6:
            #print("len 6")
            #print(ipseg[3][0:2])
            #print(ipseg[3])
            srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:3]
            dstip = ipseg[3][3:6]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
            #print(srcip+"******"+dstip)
        case 5:
            if(int(ipseg[3][2:5]) < 256):
                #print("len 5")
                #print(ipseg[3][0:1])
                #print(ipseg[3])
                srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:2]
                dstip = ipseg[3][2:5]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
                #print(srcip+"******"+dstip)
            else:
                #print("len 5")
                #print(ipseg[3][0:2])
                #print(ipseg[3])
                srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:3]
                dstip = ipseg[3][3:5]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
                #print(srcip+"******"+dstip)
        case 4:
            #print("len 4")
            #print(ipseg[3][0:1])
            #print(ipseg[3])
            if(ipseg[3][0]=="0"):
                srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0]
                dstip = ipseg[3][1:4]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
            else:
                if(ipseg[3][2] == "0"):
                    if(int(ipseg[3][0:3])<256):
                        srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:3]
                        dstip = ipseg[3][3]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
                    else:
                        srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0]
                        dstip = ipseg[3][1:4]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
                else:
                    srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:2]
                    dstip = ipseg[3][2:4]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
            #print(srcip+"******"+dstip)
        case 3:
            #print("len 3")
            #print(ipseg[3][0:1])
            #print(ipseg[3])
            srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:2]
            dstip = ipseg[3][2]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
            #print(srcip+"******"+dstip)
        case 2:
            #print("len 2")
            #print(ipseg[3][0])
            #print(ipseg[3])
            srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0]
            dstip = ipseg[3][1]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
            #print(srcip+"******"+dstip)
        case _:
            print("len < 2 error")
    if srcip in IPcount.keys():
        IPcount[srcip] = IPcount[srcip] + 1
    else:
        IPcount[srcip] = 1
    if dstip in IPcount.keys():
        IPcount[dstip] = IPcount[dstip] + 1
    else:
        IPcount[dstip] = 1
brr = list(IPcount.items())
arr = sorted(brr, key=lambda x: x[1], reverse=True)
iptracklist = []
for i in range(0,20):
    iptracklist.append(arr[i][0])
    print(arr[i][1])
print(iptracklist)

#get the pcap file list
fileList = os.listdir(os.getcwd())
fileList = sorted([x for x in fileList if "pcap" in x])
print("read file: "+fileList[fileid+1])

#constants
idle = 10 #idle time out
poolsize = 10

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

#four cases: p = 0.01, honest, M = 10\%, M = 20\%, M = 25\%

loadarr = np.array(loadhist[poolsize*100::poolsize])
loadarr = np.sort(loadarr)
collectload = loadarr[:math.floor(len(loadarr)*0.01)]

hostidset2=hostidset  # dict of flow to host case 2
hostidset3=hostidset  # dict of flow to host case 3
hostidset4=hostidset

loadpool2 = loadpool  #load of each epoch case 2
loadpool3 = loadpool  #load of each epoch case 3
loadpool4 = loadpool

track = []
for i in range(5):
    track.append(dict())

counter = 0 #reset pkt counter

roundhost2 = roundhost
roundhost3 = roundhost
roundhost4 = roundhost
cnt = 0
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
        #update the min load host
        candidate1 = [i for i,x in enumerate(loadpool) if x==min(loadpool)]
        candidate2 = [i for i,x in enumerate(loadpool2) if x==min(loadpool2)]
        candidate3 = [i for i,x in enumerate(loadpool3) if x==min(loadpool3)]
        candidate4 = [i for i,x in enumerate(loadpool4) if x==min(loadpool4)]
        if(cnt%10 == 0):
            tmp0 = random.uniform(collectload[0], collectload[-1])
            loadpool2[0] = min(tmp0,loadpool2[0])
            candidate2 = [i for i,x in enumerate(loadpool2) if x==min(loadpool2)]
        if(cnt%5  == 0):
            tmp1 = random.uniform(collectload[0], collectload[-1])
            loadpool3[0] = min(tmp1,loadpool3[0])
            candidate3 = [i for i,x in enumerate(loadpool3) if x==min(loadpool3)]
        if(cnt%4  == 0):
            tmp0 = random.uniform(collectload[0], collectload[-1])
            loadpool4[0] = min(tmp0,loadpool4[0])
            candidate4 = [i for i,x in enumerate(loadpool4) if x==min(loadpool4)]
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
        loadpool = zeros(poolsize)
        loadpool2 = zeros(poolsize)
        loadpool3 = zeros(poolsize)
        loadpool4 = zeros(poolsize)
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
            pair = src+dst
            rsrc = src.split("_")[1]
            if((pair in tracklist) or (rsrc in iptracklist) or (dst in iptracklist)):
                if tmp in track[0].keys():
                    track[0][tmp][0] = track[0][tmp][0] + p.wirelen
                    track[0][tmp][2] = p.time
                if tmp in track[1].keys():
                    track[1][tmp][0] = track[1][tmp][0] + p.wirelen
                    track[1][tmp][2] = p.time
                if tmp in track[2].keys():
                    track[2][tmp][0] = track[2][tmp][0] + p.wirelen
                    track[2][tmp][2] = p.time
                if tmp in track[3].keys():
                    track[3][tmp][0] = track[3][tmp][0] + p.wirelen
                    track[3][tmp][2] = p.time
                if tmp in track[4].keys():
                    track[4][tmp][0] = track[4][tmp][0] + p.wirelen
                    track[4][tmp][2] = p.time
        else:
            lastsee[tmp] = p.time
            hostidset[tmp] = roundhost
            hostidset2[tmp] = roundhost2
            hostidset3[tmp] = roundhost3
            hostidset4[tmp] = roundhost4
            loadpool[roundhost] = loadpool[roundhost] + p.wirelen
            loadpool2[roundhost2] = loadpool2[roundhost2] + p.wirelen
            loadpool3[roundhost3] = loadpool3[roundhost3] + p.wirelen
            loadpool4[roundhost4] = loadpool4[roundhost4] + p.wirelen
            pair = src+dst
            rsrc = src.split("_")[1]
            if((pair in tracklist) or (rsrc in iptracklist) or (dst in iptracklist)):
                if tmp in track[0].keys():
                    track[0][tmp][0] = track[0][tmp][0] + p.wirelen
                    track[0][tmp][2] = p.time
                else:
                    track[0][tmp]=[p.wirelen, p.time, p.time]
                if roundhost == 0:
                    if tmp in track[1].keys():
                        track[1][tmp][0] = track[1][tmp][0] + p.wirelen
                        track[1][tmp][2] = p.time
                    else:
                        track[1][tmp]=[p.wirelen, p.time, p.time]
                if roundhost2 == 0:
                    if tmp in track[2].keys():
                        track[2][tmp][0] = track[2][tmp][0] + p.wirelen
                        track[2][tmp][2] = p.time
                    else:
                        track[2][tmp]=[p.wirelen, p.time, p.time]
                if roundhost3 == 0:
                    if tmp in track[3].keys():
                        track[3][tmp][0] = track[3][tmp][0] + p.wirelen
                        track[3][tmp][2] = p.time
                    else:
                        track[3][tmp]=[p.wirelen, p.time, p.time]
                if roundhost4 == 0:
                    if tmp in track[4].keys():
                        track[4][tmp][0] = track[4][tmp][0] + p.wirelen
                        track[4][tmp][2] = p.time
                    else:
                        track[4][tmp]=[p.wirelen, p.time, p.time]
    else:
        lastsee[tmp] = p.time
        hostidset[tmp] = roundhost
        hostidset2[tmp] = roundhost2
        hostidset3[tmp] = roundhost3
        hostidset4[tmp] = roundhost4
        loadpool[roundhost] = loadpool[roundhost] + p.wirelen
        loadpool2[roundhost2] = loadpool2[roundhost2] + p.wirelen
        loadpool3[roundhost3] = loadpool3[roundhost3] + p.wirelen
        loadpool4[roundhost4] = loadpool4[roundhost4] + p.wirelen
        pair = src+dst
        rsrc = src.split("_")[1]
        if((pair in tracklist) or (rsrc in iptracklist) or (dst in iptracklist)):
            if tmp in track[0].keys():
                track[0][tmp][0] = track[0][tmp][0] + p.wirelen
                track[0][tmp][2] = p.time
            else:
                track[0][tmp]=[p.wirelen, p.time, p.time]
                #ind = [i for i,x in enumerate(tracklist) if x==pair]
            if roundhost == 0:
                if tmp in track[1].keys():
                    track[1][tmp][0] = track[1][tmp][0] + p.wirelen
                    track[1][tmp][2] = p.time
                else:
                    track[1][tmp]=[p.wirelen, p.time, p.time]
            if roundhost2 == 0:
                if tmp in track[2].keys():
                    track[2][tmp][0] = track[2][tmp][0] + p.wirelen
                    track[2][tmp][2] = p.time
                else:
                    track[2][tmp]=[p.wirelen, p.time, p.time]
            if roundhost3 == 0:
                if tmp in track[3].keys():
                    track[3][tmp][0] = track[3][tmp][0] + p.wirelen
                    track[3][tmp][2] = p.time
                else:
                    track[3][tmp]=[p.wirelen, p.time, p.time]
            if roundhost4 == 0:
                if tmp in track[4].keys():
                    track[4][tmp][0] = track[4][tmp][0] + p.wirelen
                    track[4][tmp][2] = p.time
                else:
                    track[4][tmp]=[p.wirelen, p.time, p.time]
pkts.close()
f = open('track0_'+str(fileid),'wb')
pickle.dump(track[0], f, pickle.HIGHEST_PROTOCOL)
f.close()

f = open('track1_'+str(fileid),'wb')
pickle.dump(track[1], f, pickle.HIGHEST_PROTOCOL)
f.close()
f = open('track2_'+str(fileid),'wb')
pickle.dump(track[2], f, pickle.HIGHEST_PROTOCOL)
f.close()
f = open('track3_'+str(fileid),'wb')
pickle.dump(track[3], f, pickle.HIGHEST_PROTOCOL)
f.close()
f = open('track4_'+str(fileid),'wb')
pickle.dump(track[4], f, pickle.HIGHEST_PROTOCOL)
f.close()

end = time.time()
print('time used: ',(end - start)/60,'min')
