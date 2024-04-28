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
import math
'''
   threshold detection
'''

fileid = 12#int(sys.argv[1])
f = open('res11/misreport_0_'+str(fileid), 'rb')
loadhist0 = pickle.load(f)
print(len(loadhist0))
f.close()
loadhist0 = loadhist0[100*10:-300*10]
print(len(loadhist0))
poolsize = 10
# plot and save the figure
arr = np.array(loadhist0[::poolsize])
loadarr = np.sort(arr)
collectload0 = loadarr[:math.floor(len(loadarr)*0.01)]
print(collectload0)
collectload1 = loadarr[:math.floor(len(loadarr)*0.1)]
print(collectload1)
collectload2 = loadarr[:math.floor(len(loadarr)*0.2)]
hostid = 1 #int(sys.argv[2])
x1= []
y1= []
y2= []
y3= []
y4= []
y5 =[]
for i in range(int(loadarr[0]),2*int(loadarr[0]),1000):
    t1 = 0
    loadhist = loadhist0[hostid::poolsize]
    for x in loadhist:
        if x<=i:
            t1 = t1 + 1
    x1.append(i/1000)
    if i<= collectload0[-1]:
        y2.append((i-collectload0[0])/(collectload0[-1] - collectload0[0]))
        a = t1/len(loadhist)
        b = 0.24*(i-collectload0[0])/(collectload0[-1] - collectload0[0])
        y1.append(a)
    else:
        y2.append(1)
        a = t1/len(loadhist)
        y1.append(a)
    if i<= collectload1[-1]:
        y3.append((i-collectload1[0])/(collectload1[-1] - collectload1[0]))
    else:
        y3.append(1)
    if i<= collectload2[-1]:
        y4.append((i-collectload2[0])/(collectload2[-1] - collectload2[0]))
    else:
        y4.append(1)
    y5.append(1)
y1 = np.array(y1)
y1 = y1 + 0.3
plt.plot(x1, y2, label ="p=0.01 detection rate" )
plt.plot(x1, y3, label ="p=0.1 detection rate")
plt.plot(x1, y4, label ="p=0.2 detection rate")
plt.plot(x1, y5, label ="trivial attack detection rate")
plt.plot(x1, y1, label ="false alarm rate")
plt.legend(prop={'size':10})
plt.grid(linestyle=':')
plt.xlabel("load threshold (KB/s)",fontsize = 15)
plt.ylabel("Probability", fontsize = 14)
plt.savefig("file"+str(fileid)+"_detection"+str(hostid)+".eps")
plt.close()
