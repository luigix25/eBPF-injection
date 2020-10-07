import statistics
import math
import os
import sys
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



with open(os.path.join(os.getcwd(), filenames[int(sys.argv[1])]), 'r') as f: # open in readonly mode
    values = [float(i) for i in f.readline().split(',')]

    mean = statistics.mean(values)
    print(mean)
