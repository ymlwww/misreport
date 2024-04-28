'''
   draw the results with different misreport timing
'''


from numpy import *
import random
import matplotlib.pyplot as plt
import numpy as np
import time
import sys
import os
import pickle


fileid = int(sys.argv[1]) - 1

f = open('res/pairdict'+str(fileid)+'_p_0.01', 'rb')
pairset = pickle.load(f)
f.close()
poolsize = 10
print(len(pairset.keys()))
freqs= list(pairset.values())
arr = sorted(freqs, key=lambda x: x[5], reverse=True)
honest = []
for i in range(0,10):
    tmp1 = arr[i*2]
    tmp2 = [x*100/tmp1[5] for x in tmp1]
    honest.append(tmp2)

'''
f = open('res/paircnt'+str(fileid)+'_p_0.01', 'rb')
ans = pickle.load(f)
f.close()
print(ans/ans[6])
print(ans[6])
'''

#print(100*np.around(arr[i*2]/arr[i*2][6],decimals=3))


#honest = [[12.4, 100.0, 97.8, 30.9, 31.3, 12.6], [12.7, 100.0, 98.0, 30.9, 31.4, 12.9], [15.4, 100.0, 98.2, 32.8, 33.3, 15.4], [15.1, 100.0, 98.2, 32.5, 33.0, 15.1], [5.1, 100.0, 98.4, 26.8, 27.0, 5.3], [16.4, 100.0, 98.3, 35.3, 33.2, 16.4], [16.5, 100.0, 98.4, 35.1, 33.3, 16.4], [16.5, 100.0, 98.4, 35.2, 33.3, 16.5], [16.2, 100.0, 98.2, 35.0, 33.0, 16.2], [16.2, 100.0, 98.2, 35.1, 32.9, 16.2]]
honest = sorted(honest, key = lambda x:x[0])
h =  [x[0] for x in honest] #honest win flow
ta = [x[1] for x in honest] # trivial all
sa = [x[2] for x in honest] # stealthy all
s2 = [x[3] for x in honest] # s25
s3 = [x[4] for x in honest] #s25 different timing
plt.plot(arange(len(honest)), h, marker = "d", label="honest")
plt.plot(arange(len(honest)), ta, marker = "2", label="trivial attack all the time")
plt.plot(arange(len(honest)), sa, marker = "3", label="stealthy attack all the time")
plt.plot(arange(len(honest)), s2, marker = "*", label="stealthy attack 25% of the time")
plt.plot(arange(len(honest)), s3, marker = "+", label="stealthy attack 25% of the time(different epoch)")
#plt.plot(arange(len(honest)), s1, marker = "x", label="stealthy attack once")
#plt.axvline(x = 0, ymin = (honest[0][3]+4)/75.0, ymax = (honest[0][4]+4)/75.0, linestyle = "--", color = "dodgerblue", label = "win rate bound")
plt.legend(loc = "upper left", bbox_to_anchor=(0.1, 0.85),prop={'size':11})
plt.grid(linestyle=':')
plt.ylabel("flow number observed per IP pair/%", fontsize = 14)
plt.xlabel("IP pair id", fontsize = 15)
plt.savefig("timing"+str(fileid)+".eps")
