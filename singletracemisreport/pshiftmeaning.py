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
'''
   plot p shift meaning figure
'''
f = open('res1/pool10loadcdfhis5', 'rb')
loadhist = pickle.load(f)
poolsize = 10
# plot and save the figure
arr = np.array(loadhist[5 + poolsize*100::poolsize])
tmphist = np.array(list(Counter(arr).items()))
tmphist = sorted(tmphist, key = lambda x: x[0])
cum = [x[1] for x in tmphist]
cumcdf = np.cumsum(cum)/np.sum(cum)
plt.xscale("log")
plt.plot([x[0]/1000.0 for x in tmphist], cumcdf, label="original")

arr = np.array(loadhist[5 + poolsize*100::poolsize]) * 0.7
tmphist = np.array(list(Counter(arr).items()))
tmphist = sorted(tmphist, key = lambda x: x[0])
cum = [x[1] for x in tmphist]
cumcdf = np.cumsum(cum)/np.sum(cum)
plt.xscale("log")
plt.plot([x[0]/1000.0 for x in tmphist], cumcdf, label="honest switch")

arr = np.array(loadhist[5 + poolsize*100::poolsize]) * 1.3 
tmphist = np.array(list(Counter(arr).items()))
tmphist = sorted(tmphist, key = lambda x: x[0])
cum = [x[1] for x in tmphist]
cumcdf = np.cumsum(cum)/np.sum(cum)
plt.xscale("log")
plt.plot([x[0]/1000.0 for x in tmphist], cumcdf, label="malicious switch")

plt.axhline(y = 0.6, xmin = 0, xmax = 0.54, linestyle="--")
plt.axhline(y = 0.7, xmin = 0, xmax = 0.54, linestyle="--")
plt.axvline(x = 2600, ymin=0, ymax=0.68, linestyle="--")
plt.plot([2600],[0.6],marker="1", markersize=10, markeredgecolor="red", markerfacecolor="red", label = "p=0.6, $L_p$=2600")
plt.plot([2600],[0.7],marker="1", markersize=10, markeredgecolor="lime", markerfacecolor="lime", label = "realp=0.7, $L_p$=2600")
plt.grid(linestyle=":")
plt.legend(prop={'size':12})
plt.xlabel("load per second(KB/s)", fontsize = 15)
plt.ylabel("CDF", fontsize = 14)
plt.savefig("explainpshift.eps")
