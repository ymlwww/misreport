'''
   draw the figure for the relationship between average win rate and win load
'''
from numpy import *
import random
import matplotlib.pyplot as plt
import numpy as np
from scipy.special import comb
import time
import sys
import os
import pickle
x = [10.312969967004108, 15.973220921590485, 16.02258011067945, 21.83151445431615, 24.214170692431566, 22.91143813,       23.847759,          30.48102564,       44.52338907,        43.35076923,      23.64503902, 24.24526198, 31.40156076, 43.82983278,45.11170569]
y = [10.31438961716496, 16.02258011067945, 15.728292729980339, 19.752500530482035, 21.83151445431615,  19.27605166859182, 20.084944616286446, 27.22262632144184, 35.194722207063826, 36.07555241259567, 19.27605166859182, 20.084944616286446, 27.22262632144184, 35.194722207063826, 36.07555241259567]
plt.scatter(x,y, marker='^',color = 'red', label="data point")
x = np.linspace(8, 45, 500)
y = x
z = x*0.5 + 12.5
plt.plot(x, y-3, label="load = rate - 3")
plt.plot(x, y, label="load = rate")
plt.plot(x, z, label="load = rate*0.5 + 12.5")
plt.legend(prop={'size':10})
plt.grid(linestyle=':')
plt.ylabel("average win load/%", fontsize = 14)
plt.xlabel("average win rate/%", fontsize = 15)
plt.savefig("winrateload.eps")
plt.clf()
plt.close()
