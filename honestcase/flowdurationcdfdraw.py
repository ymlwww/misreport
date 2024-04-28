from scapy.all import *
from numpy import *
import math
import random
import matplotlib.pyplot as plt
import numpy as np
import time
from collections import Counter
import pickle
import sys
import os
'''
plot figures from the saved pickle data
'''
a = []
for fileid in range(1,25):
    f = open('res/flowduration'+str(fileid), 'rb')
    flowduration = pickle.load(f)
    f.close()
    stamps = list(flowduration.values())
    duration = [float(x[1]) - float(x[0]) for x in stamps]
    dur = np.array(duration)
    filter_arr = dur > 0
    newdur = dur[filter_arr]

    #average calculate
    avgdur = np.average(newdur)
    print("average duration: "+str(avgdur) + "s")
    a.append(avgdur)

    tmphist = np.array(list(Counter(newdur).items()))
    tmphist = sorted(tmphist, key = lambda x: x[0])
    cum = [x[1] for x in tmphist]
    cumcdf = np.cumsum(cum)/np.sum(cum)
    plt.xscale("log")
    plt.plot([x[0] for x in tmphist], cumcdf)

#plt.legend(ncol = 2, prop={'size':10})
plt.grid(linestyle=":")
plt.axvline(x = 1)
plt.axvline(x = 2)
plt.axvline(x = 3)
plt.axvline(x = 4)
plt.axvline(x = 5)
plt.axvline(x = 6)
#plt.title("Load report distribution", fontsize = 12)
plt.xlabel("flow duration/s", fontsize = 15)
plt.ylabel("CDF", fontsize = 14)
plt.savefig("fig/durationcdf.jpg")
print(np.average(np.array(a)))
