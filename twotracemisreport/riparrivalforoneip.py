'''
   get the arrival pattern for four IP
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
trackid = int(sys.argv[2])
#find the 10 most frequest IP address
f = open('res/pairdict'+str(fileid)+'_p_0.01', 'rb')
pairset = pickle.load(f)
f.close()

iptracklist = ["203.116.121.138", "203.116.121.169", "203.116.111.195", "133.192.114.66"]

track = []
for i in range(5):
    track.append(dict())
    f = open('track'+str(i)+'_'+str(fileid), 'rb')
    track[i] = pickle.load(f)
    f.close()

f = open('res/time0'+str(fileid), 'rb')
time0 = pickle.load(f)
f.close()

size = []
iptrack = iptracklist[trackid]
labels = ["ground truth","honest","M=10%","M=20%","M=25%"]
for i in range(5):
    size.append(list())
    for flowtmp in track[i].keys():
        dstip = flowtmp.split(',')[1]
        srcip = flowtmp.split(',')[0]
        srcip = srcip.split('_')[1]
        if(len(srcip.split('.')) == 4 and len(dstip.split('.')) == 4 and (srcip == iptrack or dstip == iptrack)):
            if((track[i][flowtmp][0] >= 40) and (float(track[i][flowtmp][2]) - float(track[i][flowtmp][1]) >=1)):
                size[i].append(math.floor(float(track[i][flowtmp][1]) - time0))
    tmphist = np.array(list(Counter(size[i]).items()))
    tmphist = sorted(tmphist, key = lambda x: x[0])
    cum = [x[1] for x in tmphist]
    plt.plot([x[0] for x in tmphist], cum, label=labels[i])
plt.legend(prop={'size':10})
plt.grid(linestyle=":")
plt.xlabel("time/s", fontsize = 15)
plt.ylabel("number of flows", fontsize = 14)
plt.savefig("ipflowarrival_"+str(fileid)+"_"+str(trackid)+".eps")
plt.clf()
plt.close()

end = time.time()
print('time used: ',(end - start)/60,'min')
