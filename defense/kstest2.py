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
from scipy import stats
'''
   KS test method2
'''

fileid = int(sys.argv[1])

f = open('res/loadcdfhis'+str(fileid), 'rb')
loadhist = pickle.load(f)
poolsize = 10
# plot and save the figure
for hostid in range(poolsize):
    print('test host id %d' % hostid)
    arr = np.array(loadhist[hostid + poolsize*300::poolsize])
    for shostid in range(hostid+1, poolsize):
        brr = np.array(loadhist[shostid + poolsize*300::poolsize]) 
        print(stats.ks_2samp(arr,brr,method='asymp'))
    #tmphist = np.array(list(Counter(loadhist[hostid::poolsize]).items()))
    #tmphist = sorted(tmphist, key = lambda x: x[0])
    #cum = [x[1] for x in tmphist ]
    #cumcdf = np.cumsum(cum)/np.sum(cum)
    #plt.plot([x[0]/1000.0 for x in tmphist], cumcdf, label="member"+str(hostid))
#plt.legend(ncol = 2, prop={'size':14})
#plt.grid(linestyle=":")
#plt.title("Load report distribution", fontsize = 12)
#plt.xlabel("Load(Kb)", fontsize = 15)
#plt.ylabel("Cumulative Probability", fontsize = 14)
#plt.savefig("loadreport"+str(fileid)+".eps")
