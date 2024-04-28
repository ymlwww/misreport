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
from mpl_toolkits.axes_grid1.inset_locator import zoomed_inset_axes, mark_inset
from mpl_toolkits.axes_grid1.anchored_artists import AnchoredSizeBar
from matplotlib.patches import ConnectionPatch
batchid = int(sys.argv[1])
'''
plot figures to show the predicted p shift and the actual p shift
'''
poolsize = 10
for fileid in range(1,25):
    f = open('res'+str(batchid)+'/misreport_0_'+str(fileid), 'rb')
    loadhist = pickle.load(f)
    f.close()

    f = open('res'+str(batchid)+'/misreport_1_'+str(fileid), 'rb')
    loadhist0 = pickle.load(f)
    loadhist0 = loadhist0[poolsize:]
    f.close()

    f = open('res'+str(batchid)+'/misreport_2_'+str(fileid), 'rb')
    loadhist1 = pickle.load(f)
    loadhist1 = loadhist1[poolsize:]
    f.close()

    poolsize = 10
    # plot and save the figure
    arr = np.array(loadhist[poolsize*50:poolsize*600:poolsize])
    tmphist = np.array(list(Counter(arr).items()))
    tmphist = sorted(tmphist, key = lambda x: x[0])
    cum = [x[1] for x in tmphist]
    cumcdf = np.cumsum(cum)/np.sum(cum)
    plt.plot([x[0]/1000.0 for x in tmphist], cumcdf, label="pre-attack")

    arr = np.array(loadhist[poolsize*50:poolsize*600:poolsize]) * 0.7
    tmphist = np.array(list(Counter(arr).items()))
    tmphist = sorted(tmphist, key = lambda x: x[0])
    cum = [x[1] for x in tmphist]
    cumcdf = np.cumsum(cum)/np.sum(cum)
    plt.plot([x[0]/1000.0 for x in tmphist], cumcdf, label="honest switch predicted")

    for k in range(1,10):
        '''
        arr = np.array(loadhist0[k::poolsize])
        tmphist = np.array(list(Counter(arr).items()))
        tmphist = sorted(tmphist, key = lambda x: x[0])
        cum = [x[1] for x in tmphist]
        cumcdf = np.cumsum(cum)/np.sum(cum)
        plt.plot([x[0]/1000.0 for x in tmphist], cumcdf)
        '''
        arr = np.array(loadhist1[k::poolsize])
        tmphist = np.array(list(Counter(arr).items()))
        tmphist = sorted(tmphist, key = lambda x: x[0])
        cum = [x[1] for x in tmphist]
        cumcdf = np.cumsum(cum)/np.sum(cum)
        plt.plot([x[0]/1000.0 for x in tmphist], cumcdf)

    plt.xscale("log")
    plt.grid(linestyle=":")
    plt.legend(prop={'size':12})
    plt.xlabel("load per second(KB/s)", fontsize = 15)
    plt.ylabel("CDF", fontsize = 14)
    plt.savefig("explainpshift"+str(batchid)+"file"+str(fileid)+".jpg")
    plt.close()
