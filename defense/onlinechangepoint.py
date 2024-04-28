'''
   conduct online change point detection 
'''
import datetime as dt
import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import os
import math
import changefinder
import matplotlib.pyplot as plt
from matplotlib import pyplot
import pickle
import sys
import os




def changefinderTS(data, r, order, smooth):
    cf = changefinder.ChangeFinder(r=r, order=order, smooth=smooth)

    ret = []
    for i in data:
        score = cf.update(i)
        ret.append(score)
    return ret

def plotTSScore(data, ret, hostid):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.plot(ret, label='anomaly score', color = 'red', alpha=0.9)
    ax2 = ax.twinx()
    ax2.plot(data, label='load(MB/s)', color = 'blue', alpha=0.9)
    #plt.title('Anomaly Score time series')
    plt.ylabel('anomaly score',fontsize = 14)
    ax.set_xlabel('time',fontsize = 15)
    plt.axvline(x=600, ymin = 0, ymax = 1, color = 'fuchsia', linestyle="--")
    plt.text(0.745, 0.85, 'attack begin',
        horizontalalignment='right',
        verticalalignment='top',
        transform=ax.transAxes, color='red', fontsize=11)
    plt.legend(prop={'size':11})
    plt.rcParams.update({'axes.labelsize': '11'})
    #plt.rcParams.update({'font.size': 14})
    plt.grid(linestyle=':')
    plt.savefig(str(hostid)+".eps")

fileid = int(sys.argv[1])

f = open('res11/misreport_2_'+str(fileid), 'rb')
loadhist = pickle.load(f)
print(len(loadhist))
f = open('res11/misreport_0_'+str(fileid), 'rb')
loadhist0 = pickle.load(f)
print(len(loadhist0))
loadhist0 = loadhist0[:-300*10]
lh = np.concatenate((loadhist0, loadhist))
poolsize = 10
# plot and save the figure
arr = np.array(lh[::poolsize])/1000000
ret = changefinderTS(arr, r=0.03, order=1, smooth=5)
plotTSScore(arr, ret, fileid)
