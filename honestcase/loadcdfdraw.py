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
'''
plot load cdf figures from the saved pickle data
'''

fileid = 8 #int(sys.argv[1])

f = open('res1/pool50loadcdfhis'+str(fileid), 'rb')
loadhist = pickle.load(f)
f.close()
poolsize = 50
# plot and save the figurei
for hostid in range(poolsize):
    if(hostid == 41):
        continue
    arr = np.array(loadhist[hostid + poolsize*100::poolsize])
    tmphist = np.array(list(Counter(arr).items()))
    tmphist = sorted(tmphist, key = lambda x: x[0])
    cum = [x[1] for x in tmphist]
    cumcdf = np.cumsum(cum)/np.sum(cum)
    plt.xscale("log")
    plt.plot([x[0]/1000.0 for x in tmphist], cumcdf, label="member"+str(hostid))
    #plt.legend(ncol = 2, prop={'size':10})
plt.grid(linestyle=":")
#plt.title("Load report distribution", fontsize = 12)
plt.xlabel("load per second(KB/s)", fontsize = 15)
plt.ylabel("CDF", fontsize = 14)
plt.savefig("pool50loadreport"+str(fileid)+".eps")
plt.clf()
plt.close()
