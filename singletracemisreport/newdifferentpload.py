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
from scipy.special import comb
'''
   plot the performance figure with different p with the new method
'''
def lowerbound(p, N):
    ans = 0
    for i in range(N):
       ans = ans +  comb(N-1,i) * pow(p, i) * pow(1-p, N-1-i)/(i+1)
    return ans

def avgret(arr, ind):
    cnt = 0
    res = 0
    for k in range(25):
        if arr[k][ind]:
            res = res + arr[k][ind]
            cnt = cnt + 1
    return res/cnt

batchid = int(sys.argv[1])
#batchid = 10
h = []
s1 = []
s2 = []
s3 = []
s4 = []
loads = np.zeros((25,6))
cheats = np.zeros((25,5))
wins = np.zeros((25,6))
poolsize = 10
for fileid in range(1,25):
    if(os.path.exists('res'+str(batchid)+'/misreport_0_'+str(fileid))):
        print("---------")
    else:
        continue
    
    for i in range(6):
        if i == 0: #honest case
            f = open('res'+str(batchid)+'/misreport_'+str(i)+'_'+str(fileid), 'rb')
            loadhist = pickle.load(f)
            f.close()
            base = np.average(np.array(loadhist[600*poolsize:]))
            arr = np.array(loadhist[600*poolsize::poolsize])
            loads[fileid][i] = 10*np.average(arr)/base
            f = open('res'+str(batchid)+'/misreport_'+str(i)+'win_'+str(fileid),'rb')
            winhost = pickle.load(f)
            winhost = winhost[:-1]
            f.close()
            count0 = 0
            period = len(winhost)
            for k in range(period):
                if(winhost[k] == 0):
                    count0 = count0 + 1
            wins[fileid][i] = count0/period*100
        else:#trivial case
            if i == 1:
                continue
            f = open('res'+str(batchid)+'/misreport_'+str(i)+'_'+str(fileid), 'rb')
            loadhist = pickle.load(f)
            loadhist = loadhist[poolsize:]
            f.close()
            arr = np.array(loadhist[::poolsize])
            loads[fileid][i] = 10*np.average(arr)/base
            f = open('res'+str(batchid)+'/misreport_'+str(i)+'win_'+str(fileid),'rb')
            winhost = pickle.load(f)
            winhost = winhost[:-1]
            f.close()
            f = open('res'+str(batchid)+'/misreport_'+str(i)+'cheat_'+str(fileid),'rb')
            cheat = pickle.load(f)
            cheat = cheat[:-1]
            f.close()
            count0 = 0
            count1 = 0
            period = len(winhost)
            for k in range(period):
                if(winhost[k] == 0):
                    count0 = count0 + 1
                if(cheat[k] == 1):
                    count1 = count1 + 1
            cheats[fileid][i-1] = count1/period*100
            wins[fileid][i] = count0/period*100


finalwin = []
finalcheat = []
for i in range(2,6):
    finalwin.append(avgret(wins, i))
for i in range(1,5):
    finalcheat.append(avgret(cheats, i))
x = [0.01, 0.05, 0.1, 0.2]
y = []
z = []
for i in range(2,6):
    z.append(avgret(loads, i))
for i in range(len(finalcheat)):
    mk = finalcheat[i]
    y.append(mk*lowerbound(x[i],10) + 10*(1-0.01*mk))
print(finalcheat)
print(finalwin)
print(z)
plt.plot(x, finalcheat, marker = "2", label="cheat rate")
plt.plot(x, finalwin, marker = "2", label="win rate")
plt.plot(x, z, marker = "1", label="win load")
#plt.plot(x, y, marker = "1", label="low bound predicted")
plt.axhline(y = avgret(loads,0), linestyle = "--", label ="honest")
print(avgret(loads,0))
plt.axhline(y = 30, linestyle = "--", color = "crimson" ,label ="target")
plt.legend(prop={'size':10})
plt.grid(linestyle=':')
plt.ylabel("percentage/%", fontsize = 14)
plt.xlabel("p", fontsize = 15)
plt.savefig("newdifferentp"+str(batchid)+".eps")
