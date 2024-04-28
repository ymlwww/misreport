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
plot the size of new flows per second figure
'''
a = []
for fileid in range(3,4):
    f = open('res/epochload'+str(fileid), 'rb')
    epochload = pickle.load(f)
    f.close()
    # plot and save the figure
    flowtimedict = list(epochload.items())
    flowtimedict.sort(key=lambda x: x[0])
    times = [x[0] for x in flowtimedict]
    byte = [x[1] for x in flowtimedict]
    byte = np.array(byte)
    byte = byte/1000
    avgbyte = np.average(byte[2:-2])
    times = np.array(times)
    times = times - times[0]
    print(len(times))
    arr = np.array(byte[0:10])
    arr = arr/avgbyte
    np.set_printoptions(precision=2)
    print(arr)
    a.append(byte[1]/avgbyte)
    
    plt.plot(times[:-2], byte[:-2])
    plt.axhline(y = avgbyte, color = 'r', linestyle = '-', label = "avg load")
    plt.legend(prop={'size':10})
    plt.grid(linestyle=":")
    plt.yscale("log")
    plt.xlabel("time/s", fontsize = 15)
    plt.ylabel("size of new flows/KB", fontsize = 14)
    plt.savefig("perarrivalload"+str(fileid)+".eps")
    plt.close()

print(np.average(np.array(a)))
print(a)
