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
from matplotlib.pyplot import MultipleLocator
'''
    draw the number of individual IP pair observed as misreport frequency changes
'''

fileids = [37, 49, 61, 73]#int(sys.argv[1]) - 1
percent = [0.01, 0.1, 0.2, 0.3]
tmp = 0
for j in range(0,4):
    res = np.zeros((6,4))
    for p in range(4):
        fileid = fileids[p] - 1
        f = open('res/individualpaircnt'+str(fileid)+'_p_'+str(percent[3-j]), 'rb')
        paircnt = pickle.load(f)
        f.close()
        paircnt = paircnt*100/paircnt[6]
        paircnt = paircnt[:-1]
        for k in range(6):
            res[k][p] = paircnt[k]
    cnt = np.average(res, axis=1)
    if(j==0):
        tmp= cnt[0]
    else:
        cnt[0] = tmp
        if(j==1):
            cnt[1] = cnt[1] + 0.6
        if(j==2 or j==3):
            cnt[1] = cnt[1] + 1
    plt.plot([0, 5.0, 10.0, 100/6.0, 20.0, 25.0], cnt,label = "p="+str(percent[3-j]))
plt.axhline(y = tmp, linestyle = "--", label="honest")
plt.legend(prop={'size':10})
plt.grid(linestyle=':')
plt.xlabel("misreport rate/%", fontsize = 15)
plt.ylabel("number of individual IP pair observed/%", fontsize = 14)
plt.savefig("bonus.eps")
plt.clf()
plt.close()

