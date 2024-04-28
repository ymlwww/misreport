'''
    read average flow duration
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
res = np.zeros(5) #flow duration error percent
cnt = 0 #IP pair count
fileids = [36, 48, 60, 72] #int(sys.argv[1]) - 1

for fileid in fileids:
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
    print(tracklist)

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
    for pair in tracklist:
        flowdur = []
        mark = 0
        print("scan pair "+str(pair))
        for i in range(5):
            flowdur.append(list())
            for flowtmp in track[i].keys():
                ipseg = flowtmp.split(',')[0]+flowtmp.split(',')[1]
                if(ipseg == pair):
                    if((track[i][flowtmp][0] >= 40) and (float(track[i][flowtmp][2]) - float(track[i][flowtmp][1]) >=1)):
                        flowdur[i].append(float(track[i][flowtmp][2]) - float(track[i][flowtmp][1]))
            if(len(flowdur[i])):
                mark = mark + 1
        avgtmp = 0
        if(len(flowdur[0])):
            avgtmp = np.average(flowdur[0])
        if(mark == 5):
            for i in range(5):
                print(np.average(flowdur[i]))
                res[i] = res[i] + 100*abs(np.average(flowdur[i]) - avgtmp)/avgtmp
                cnt = cnt + 1
    print("****************")
res = res/cnt
print(res)
end = time.time()
print('time used: ',(end - start)/60,'min')
