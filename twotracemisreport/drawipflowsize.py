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
res = np.zeros(5) #flow duration error percent
cnt = 0 #IP pair count
fileids = [36, 48, 60, 72] 

for fileid in fileids:
    #find the 10 most frequest IP address
    f = open('res/pairdict'+str(fileid)+'_p_0.01', 'rb')
    pairset = pickle.load(f)
    f.close()

    IPcount = {}
    for IPpair in pairset.keys():
        #get IPs from the pair
        IPpair = IPpair.split("_")[1]
        srcip =""
        dstip =""
        ipseg = IPpair.split(".")
        if(len(ipseg) !=7):
            continue
        match len(ipseg[3]):
            case 6:
                srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:3]
                dstip = ipseg[3][3:6]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
            case 5:
                if(int(ipseg[3][2:5]) < 256):
                    srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:2]
                    dstip = ipseg[3][2:5]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
                else:
                    srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:3]
                    dstip = ipseg[3][3:5]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
            case 4:
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
            case 3:
                srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0:2]
                dstip = ipseg[3][2]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
            case 2:
                srcip = ipseg[0]+"."+ipseg[1]+"."+ipseg[2]+"."+ipseg[3][0]
                dstip = ipseg[3][1]+"."+ipseg[4]+"."+ipseg[5]+"."+ipseg[6]
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
    print(iptracklist)

    track = []
    for i in range(5):
        track.append(dict())
        f = open('track'+str(i)+'_'+str(fileid), 'rb')
        track[i] = pickle.load(f)
        f.close()

    f = open('res/time0'+str(fileid), 'rb')
    time0 = pickle.load(f)
    f.close()


    #track flows of IP pairs
    for pair in iptracklist:
        size = []
        print("scan pair "+str(pair))
        mark = 0
        for i in range(5):
            size.append(list())
            for flowtmp in track[i].keys():
                dstip = flowtmp.split(',')[1]
                srcip = flowtmp.split(',')[0]
                srcip = srcip.split('_')[1]
                #print(srcip,dstip)
                if(len(srcip.split('.')) == 4 and len(dstip.split('.')) == 4 and (srcip == pair or dstip == pair)):
                    if((track[i][flowtmp][0] >= 40) and (float(track[i][flowtmp][2]) - float(track[i][flowtmp][1]) >=1)):
                        size[i].append(track[i][flowtmp][0])
            if(len(size[i])):
                mark = mark + 1
        avgtmp = 0
        if(len(size[0])):
            avgtmp = np.average(size[0])
        if(mark == 5):
            for i in range(5):
                print(np.average(size[i]))
                res[i] = res[i] + 100*abs(np.average(size[i]) - avgtmp)/avgtmp
                cnt = cnt + 1
    print("****************")
res = res/cnt
print(res)
end = time.time()
print('time used: ',(end - start)/60,'min')
