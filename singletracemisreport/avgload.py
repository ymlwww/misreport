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
import os.path
'''
plot figures from the saved pickle data

plot for the average load gain from msireport attack
'''

#batchid = int(sys.argv[1])

h = []
t = []
s = []
poolsize = 10
for fileid in range(13,14):
    '''
    if(os.path.exists('res'+str(batchid)+'/misreport_0_'+str(fileid))):
        print("---------")
    else:
        continue
    '''
    #tmp load value for three cases
    htmp = 0.0
    ttmp = 0.0
    stmp = 0.0

    for batchid in range(11,12):
        #honest case
        f = open('res'+str(batchid)+'/misreport_0_'+str(fileid), 'rb')
        loadhist = pickle.load(f)
        f.close()

        base = np.average(np.array(loadhist[600*poolsize:]))
        #print(round(base/1000.0,1))
        arr = np.array(loadhist[600*poolsize::poolsize])
        #print("normal load: ",str(int(np.average(arr)/1000.0)),"KB/s rate: ",str(round(100*np.average(arr)/base,1)),"%")
        htmp = htmp + 10*np.average(arr)/base
        
        #trivial case
        f = open('res'+str(batchid)+'/misreport_1_'+str(fileid), 'rb')
        loadhist0 = pickle.load(f)
        loadhist0 = loadhist0[poolsize:]
        f.close()
        brr = np.array(loadhist0[::poolsize])
        #print("trivial attack load: ",str(int(np.average(brr)/1000.0)),"KB/s ", str(round(np.average(brr)*100.0/base,1)),"%")
        ttmp = ttmp  + 10*np.average(brr)/base
    
        #stealthy case
        f = open('res'+str(batchid)+'/misreport_2_'+str(fileid), 'rb')
        loadhist1 = pickle.load(f)
        loadhist1 = loadhist1[poolsize:]
        f.close()
        crr = np.array(loadhist1[::poolsize])
        #print("stealthy attack load: ",str(int(np.average(crr)/1000.0)),"KB/s", str(round(np.average(crr)*100.0/base,1)),"%")
        stmp = stmp + 10*np.average(crr)/base

    h.append(htmp)
    t.append(ttmp)
    s.append(stmp)

s = np.array(s)
print(h)
print(t)
print(s)
#s = s - 1.4
'''    
arr = []
for i in range(10):
    arr.append((round(10*np.average(np.array(loadhist[600*poolsize+i::poolsize]))/base,1)))
arr.sort()
print(arr)
'''

plt.plot(arange(len(h)), h, marker = "1",  label="honest")
plt.axhline(y = np.average(h), linestyle = "--", label ="honestavg")
print("honest flow no:")
print(np.average(h))

plt.plot(arange(len(h)), t, marker = "2", label="trivial")
plt.axhline(y = np.average(t), linestyle = "--", color = "darkorange",  label ="trivialavg")
print("trivial flow no:")
print(np.average(t))

plt.plot(arange(len(h)), s, marker = "3", label="stealthy")
plt.axhline(y = np.average(s), linestyle = "--",color ="green", label ="stealthyavg")
print("stealthy flow no:")
print(np.average(s))

plt.axhline(y = 30, linestyle = "--", color = "crimson" ,label ="target")
plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.1), ncol=4, prop={'size':10})
plt.grid(linestyle=':')
plt.ylabel("load/%", fontsize = 14)
plt.xlabel("trace id", fontsize = 15)
plt.savefig("avgload.eps")
