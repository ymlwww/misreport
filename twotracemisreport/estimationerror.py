'''
    draw the estimation error figure
'''
import numpy as np
import matplotlib.pyplot as plt

size = 2
x = np.arange(2)
a = [10.52967424, 32.22135022] 
b = [3.17461166, 9.83019104]
c = [2.56812762, 9.73093222]
d = [1.98361778, 6.6804126]

total_width, n = 0.8, 4
width = total_width / n
x = x - (total_width - width) / 2

fig, ax = plt.subplots()
rects1 = ax.bar(x, a, width, label="honest")
rects2 = ax.bar(x + width, b, width=width, label='M=10%')
rects3 = ax.bar(x + 2 * width, c, width=width, label='M=20%')
rects4 = ax.bar(x + 3 * width, d, width=width, label='M=25%')
ax.set_ylabel('error/%', fontsize = 14)
ax.set_xticks(x + width )
ax.set_xticklabels(('flow duration error', 'flow size error'))
ax.tick_params(axis='x', labelsize=15)
plt.legend(prop={'size':11})

def autolabel(rects):
    """
    Attach a text label above each bar displaying its height
    """
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()/2., 1.05*height,
                '%.2f' % float(height),
                ha='center', va='bottom')

autolabel(rects1)
autolabel(rects2)
autolabel(rects3)
autolabel(rects4)
plt.savefig("error.eps")
