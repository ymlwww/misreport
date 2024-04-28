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
plot load cdf figures in a batch  from the saved pickle data
'''
poolsize = 50
for fileid in range(1, 25):
    f = open('res1/pool'+str(poolsize)+'loadcdfhis'+str(fileid), 'rb') # modify the filename for different pool size
    loadhist = pickle.load(f)
    f.close()
    # plot and save the figure
    for hostid in range(poolsize):
        arr = np.array(loadhist[hostid + poolsize*50::poolsize]) #modify the start period
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
    plt.savefig("pool"+str(poolsize)+"loadreport"+str(fileid)+".jpg")
    plt.clf()
    plt.close()
