import statistics
import math
import os
import pandas as pd
from matplotlib import pyplot as plt

filenames = [
                'Vno_Lno_S0_D60.txt', 
                'Vno_Llow_S0_D60.txt', 
                'Vno_Lhigh_S0_D60.txt', 
                'Vno_Lhigh_S2_D60.txt', 
                'Vno_Lhigh_S10_D60.txt', 
                'Vno_Lhigh_S20_D60.txt', 
                'Vyes_Lno_S0_D60.txt', 
                'Vyes_Llow_S0_D60.txt', 
                'Vyes_Lhigh_S0_D60.txt'
]

description = [
                'Vno_Lno_S0_D60.txt', 
                'Vno_Llow_S0_D60.txt', 
                'Vno_Lhigh_S0_D60.txt', 
                'Vno_Lhigh_S2_D60.txt', 
                'Vno_Lhigh_S10_D60.txt', 
                'Vno_Lhigh_S20_D60.txt', 
                'Vyes_Lno_S0_D60.txt', 
                'Vyes_Llow_S0_D60.txt', 
                'Vyes_Lhigh_S0_D60.txt'
]

data_dict = {}
data_dict['experiment'] = [f.replace('.txt', '').replace('_D60', 'D60').replace('_', '\n').replace('V', 'vCPU pinned: ').replace('L', 'Host load: ').replace('S', 'Serial: ').replace('D60', '%') for f in filenames]
data_dict['lower'] = []
data_dict['mean'] = []
data_dict['upper'] = []

n = 30
Z = 1.960   # for 95% confidence interval
for filename in filenames:
    print(filename)
    if '.txt' not in filename:
        continue
    # s=filename.replace('.txt', '').split('_')
    # for t in s:
    #     print(''.join(ch for ch in t if not ch.isupper()))
    # exit(0)    
    with open(os.path.join(os.getcwd(), "results", filename), 'r') as f: # open in readonly mode
        values = [float(i) for i in f.readline().split(',')]

        mean = statistics.mean(values)
        stdev = statistics.stdev(values) * 0.5
        ci = stdev / math.sqrt(n) * Z

        # data_dict['category'].append(filename)
        data_dict['lower'].append(mean - ci)
        data_dict['mean'].append(mean)
        data_dict['upper'].append(mean + ci)
print(str(len(data_dict['upper'])))


dataset = pd.DataFrame(data_dict)


i=0
color = 'black'
for lower,mean, upper,y in zip(dataset['lower'],data_dict['mean'],dataset['upper'],range(len(dataset))):
    if i == 6:
        color = 'gray'
    # plt.plot((y,y,y),(lower,mean, upper),'ro-',color='orange')

    plt.plot((y, y), (lower, mean), '_-', color=color)
    plt.plot((y, y), (mean, upper), '_-', color=color)
    plt.plot((y), (mean), 'ro-', color=color)
    i +=1

plt.xticks(range(len(dataset)),list(dataset['experiment']))
plt.title('Throughput evaluation under different load conditions')
plt.xlabel('Experiments')
plt.ylabel('Throughput [Mpps]')

plt.grid(alpha=0.7)
plt.show()