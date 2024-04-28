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
plot figures from the saved pickle data

plot for the average load gain from msireport attack with adjusted m
'''
finalcheat  = [36.916339489118315, 43.991452991453, 53.968154718627304, 74.34462701759487]
finalwin = [34.44937230381465, 36.14353400222965, 37.57040376133004, 37.817459163394886]
z = [30.33491131341446, 29.54107188610463, 31.27659039052253, 31.010576640060376]
x = [0.01, 0.05 ,0.1, 0.2]
plt.plot(x, finalcheat, marker = "2", label="cheat rate")
plt.plot(x, finalwin, marker = "2", label="win rate")
plt.plot(x, z, marker = "1", label="win load")
plt.axhline(y = 10.242412424271356, linestyle = "--", label ="honest")
plt.axhline(y = 30, linestyle = "--", color = "crimson" ,label ="target")
plt.legend(prop={'size':10})
plt.grid(linestyle=':')
plt.ylabel("percentage/%", fontsize = 14)
plt.xlabel("p", fontsize = 15)
plt.savefig("newdifferentp.eps")
