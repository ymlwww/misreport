from numpy import *
import random
import matplotlib.pyplot as plt
import numpy as np
from scipy.special import comb
import time
import sys
import os
import pickle
'''
   draw the trivial and stealthy attack winrate vs winload fig Fig.5 in the paper"
'''
def lowerbound(p, N):
    ans = 0
    for i in range(N):
       ans = ans +  comb(N-1,i) * pow(p, i) * pow(1-p, N-1-i)/(i+1)
    return ans

#honest = sorted(honest, key = lambda x:x[0])
batchid = int(sys.argv[1])
poolsize = 10
N = poolsize
honestwinrate = []
trivialwinrate = []
trivialwinload = []
trivialbound = []
stealthywinrate = []
stealthywinload = []
stealthybound = []
trivialoldpredict = []
stealthyoldpredict = []
trivialload = []
stealthyload = []
for fileid in range(1,25):
    testpath ='res'+str(batchid)+'/misreport_0_'+str(fileid)
    if(os.path.isfile(testpath) == False):
        continue
    f = open('res'+str(batchid)+'/misreport_0_'+str(fileid), 'rb')
    loadhist = pickle.load(f)
    loadhist = loadhist[600*poolsize:]
    f.close()

    f = open('res'+str(batchid)+'/misreport_1_'+str(fileid), 'rb')
    loadhist0 = pickle.load(f)
    loadhist0 = loadhist0[poolsize:]
    f.close()

    f = open('res'+str(batchid)+'/misreport_2_'+str(fileid), 'rb')
    loadhist1 = pickle.load(f)
    loadhist1 = loadhist1[poolsize:]
    f.close()

    f = open('res'+str(batchid)+'/misreport_0win_'+str(fileid),'rb')
    winhost = pickle.load(f)
    winhost = winhost[:-1]
    f.close()

    f = open('res'+str(batchid)+'/misreport_1win_'+str(fileid),'rb')
    winhost0 = pickle.load(f)
    winhost0 = winhost0[:-1]
    f.close()

    f = open('res'+str(batchid)+'/misreport_2win_'+str(fileid),'rb')
    winhost1 = pickle.load(f)
    winhost1 = winhost1[:-1]
    f.close()

    f = open('res'+str(batchid)+'/misreport_1cheat_'+str(fileid),'rb')
    cheat0 = pickle.load(f)
    cheat0 = cheat0[:-1]
    f.close()

    f = open('res'+str(batchid)+'/misreport_2cheat_'+str(fileid),'rb')
    cheat1 = pickle.load(f)
    cheat1 = cheat1[:-1]
    f.close()

    f = open('res'+str(batchid)+'/misreport_1diff_'+str(fileid),'rb')
    diff0 = pickle.load(f)
    diff0 = diff0[:-1]
    f.close()

    f = open('res'+str(batchid)+'/misreport_2diff_'+str(fileid),'rb')
    diff1 = pickle.load(f)
    diff1 = diff1[:-1]
    f.close()

    p = 0.01
    #part = pow(1-p, poolsize - 3)
    #allpart = part*(1-p)*(1-p) + 0.5*(p - p*p)*part + part*p*p/3.0
    period = len(winhost[600:])
    
    #honest report win rate
    count = 0
    for i in range(0,period):
        if(winhost[600+i] == 0):
            count = count + 1
    honestwinrate.append(count/period*100)
    #print("honest report win rate: "+str(round(count/period*100.0,1))+"%")
    
    
    #trivial win rate, win load and win bound
    count0 = 0
    count1 = 0
    periodt = len(winhost0)
    for i in range(0, periodt):
        if(winhost0[i] == 0):
            count0 = count0 + 1
        if(cheat0[i] == 1):
            count1 = count1 + 1
    cheatrate = count1/periodt*100
    trivialwinrate.append(count0/periodt*100)
    trivialbound.append([cheatrate, cheatrate + 10*(1 - count1/periodt)])
    trivialoldpredict.append(10*(1 - count1/periodt) + cheatrate)
    trivialload.append(10*np.average(loadhist0[::poolsize])/np.average(loadhist))
    #print("cheat rate: "+str(round(count1/period*100.0,1))+"%, trivial win rate: "+str(round(count0/period*100.0,1))+"%, bound: "+str(count1*100.0/period)+"% ~ "+str((1-count1/period)*100.0/poolsize + count1*100.0/period))

    #stealthy win rate, win load and win bound
    count0 = 0
    count1 = 0
    periods = len(winhost1)
    for i in range(1, periods):
        if(winhost1[i] == 0):
            count0 = count0 + 1
        if(cheat1[i] == 1):
            count1 = count1 + 1
    cheatrate = count1/periods*100 #
    stealthywinrate.append(count0/periods*100) #
    stealthybound.append([cheatrate*lowerbound(p, 10), cheatrate + 10*(1 - count1/periods)])
    stealthyoldpredict.append(10*(1 - count1/periods) + cheatrate*pow(1-p,N-1))
    stealthyload.append(10*np.average(loadhist1[::poolsize])/np.average(loadhist))    
    #print("cheat rate: "+str(round(count1/period*100.0,1))+"%, stealthy win rate: "+str(round(count0/period*100.0,1))+"%, bound: "+str(count1*allpart*100.0/period)+"% ~ "+str((1-count1/period)*100.0/poolsize + count1*100.0/period))


baseaxis = np.arange(len(honestwinrate))
plt.plot(baseaxis, honestwinrate,         marker = "1", color = "dodgerblue", label="honest")
plt.axhline(y = np.average(honestwinrate), linestyle = "--", color = "dodgerblue", label = "avg honest")
print("honest avg win rate: "+str(np.average(honestwinrate)))
plt.plot(baseaxis, trivialoldpredict,     marker = "2", color='orange', label="prediction[15]")
plt.plot(baseaxis, trivialwinrate,        marker = "3", color='red', label="trivial")
plt.axhline(y = np.average(trivialwinrate), linestyle = "--", color = 'red', label = 'avg trivial')
#plt.plot(baseaxis, trivialload,           marker = "*", label="trivial win load")
print("trivial avg win rate: "+str(np.average(trivialwinrate)))
print("trivial avg win load: "+str(np.average(trivialload)))
print(len(honestwinrate))
print(len(trivialbound))
boundavg = []
for i in range(len(honestwinrate)):
    plt.plot((i,i), (trivialbound[i][0] , trivialbound[i][1]), linestyle = "--", color = "limegreen")
    boundavg.append((trivialbound[i][0] + trivialbound[i][1])/2)
plt.axhline(y = np.average(np.array(boundavg)), linestyle = "--", color = 'limegreen', label = 'avg bound')
plt.plot((1,1), (trivialbound[1][0], trivialbound[1][1]), linestyle = "--", color = "limegreen", label = "win rate bound")
plt.legend(ncol=3, prop={'size':10})
plt.grid(linestyle=':')
plt.ylabel("win rate/%", fontsize = 14)
plt.xlabel("trace id", fontsize = 15)
plt.savefig("workingfig/trivialwinrate"+str(batchid)+".eps")
plt.clf()
plt.close()

plt.plot(baseaxis, honestwinrate,         marker = "1", color = "dodgerblue", label="honest")
plt.axhline(y = np.average(honestwinrate), linestyle = "--", color = "dodgerblue", label = "avg honest")
print("honest avg win rate: "+str(np.average(honestwinrate)))
plt.plot(baseaxis, stealthyoldpredict,     marker = "2", color='orange', label="prediction[15]")
plt.plot(baseaxis, stealthywinrate,        marker = "3", color='red', label="stealthy")
plt.axhline(y = np.average(stealthywinrate), linestyle = "--", color = 'red', label = 'avg stealthy')
#plt.plot(baseaxis, trivialload,           marker = "*", label="trivial win load")
print("stealthy avg win rate: "+str(np.average(stealthywinrate)))
print("stealthy avg win load: "+str(np.average(stealthyload)))

boundavg = []
for i in range(len(honestwinrate)):
    plt.plot((i,i), (stealthybound[i][0] , stealthybound[i][1]), linestyle = "--", color = "limegreen")
    boundavg.append((stealthybound[i][0] + stealthybound[i][1])/2)
plt.axhline(y = np.average(np.array(boundavg)), linestyle = "--", color = 'limegreen', label = 'avg bound')
plt.plot((1,1), (stealthybound[1][0], stealthybound[1][1]), linestyle = "--", color = "limegreen", label = "win rate bound")
plt.legend(ncol=3, prop={'size':10})
plt.grid(linestyle=':')
plt.ylabel("win rate/%", fontsize = 14)
plt.xlabel("trace id", fontsize = 15)
plt.savefig("workingfig/stealthywinrate"+str(batchid)+".eps")
plt.clf()
plt.close()
