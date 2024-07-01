import os
import re
import csv
import sys
import time
import mmap
import numpy as np
import pandas as pd
import pickle
import gzip
import matplotlib.pyplot as plt
from joblib import dump
from sklearn import metrics
from sklearn import preprocessing
from sklearn.decomposition import PCA
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MinMaxScaler
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report,confusion_matrix
from sklearn.model_selection import train_test_split, cross_val_score

#################################
#  Select the amount of file   #
#################################
amount = int(input("Select amounts of input data: "))
file_amount = int((amount - 1) * 5)  # Network type has 5 type
oid_amount = 38  # One file has 38 OID

#######################################
#  Make dictionary for OID and label  #
#######################################
oid = ['.3.6.1.2.1.2.2.1.10.2', '.3.6.1.2.1.2.2.1.10.24', '.3.6.1.2.1.2.2.1.11.2', '.3.6.1.2.1.2.2.1.11.24',
       '.3.6.1.2.1.2.2.1.16.2', '.3.6.1.2.1.2.2.1.16.24', '.3.6.1.2.1.2.2.1.17.2', '.3.6.1.2.1.2.2.1.17.24',
       '.3.6.1.2.1.4.3.0', '.3.6.1.2.1.4.9.0', '.3.6.1.2.1.4.10.0', '.3.6.1.2.1.4.11.0', '.3.6.1.2.1.4.31.1.1.3.1',
       '.3.6.1.2.1.4.31.1.1.5.1', '.3.6.1.2.1.4.31.1.1.18.1', '.3.6.1.2.1.4.31.1.1.20.1', '.3.6.1.2.1.4.31.1.1.25.1',
       '.3.6.1.2.1.4.31.1.1.30.1', '.3.6.1.2.1.4.31.1.1.32.1', '.3.6.1.2.1.5.1.0', '.3.6.1.2.1.5.3.0',
       '.3.6.1.2.1.5.8.0',
       '.3.6.1.2.1.5.14.0', '.3.6.1.2.1.5.15.0', '.3.6.1.2.1.5.16.0', '.3.6.1.2.1.5.22.0', '.3.6.1.2.1.5.29.1.2.1',
       '.3.6.1.2.1.5.29.1.4.1', '.3.6.1.2.1.5.29.1.5.1', '.3.6.1.2.1.5.30.1.3.1.3', '.3.6.1.2.1.5.30.1.3.1.8',
       '.3.6.1.2.1.5.30.1.4.1.0',
       '.3.6.1.2.1.5.30.1.4.1.3', '.3.6.1.2.1.6.10.0', '.3.6.1.2.1.6.11.0', '.3.6.1.2.1.6.12.0', '.3.6.1.2.1.6.15.0',
       '.3.6.1.2.1.7.2.0']
OID_dict = dict()
count = 0
for i in oid:
    OID_dict[count] = i
    count += 1

label_dict = {0: 'normal', 1: 'tcp', 2: 'arp', 3: 'udp', 4: 'icmp'}

########################################
#  Filte OID octet and put it in list  #
########################################
data_type = ['normal', 'tcp', 'arp', 'udp', 'icmp']

for n in range(len(data_type)):
    for i in range(1, 1 + amount):

        # Load the OID file #
        file = open( data_type[n] + str(i))
        iter_file = iter(file)

        # Create a global variable(list) #
        globals()[data_type[n] + str(i)] = []
        # Use 'name' to replace compound string #
        name = globals()[data_type[n] + str(i)]

        # Capture "Counter32" volume #
        # OID EX."iso.3.6.1.2.1.2.2.1.10.14 = Counter32: 64"
        for line in iter_file:
            iso = line.find('iso')
            if iso < 0:
                print("MIB ERROR : 'iso' not found")
                break

            Equal = line.find('=')
            if iso < 0:
                print("MIB ERROR : '=' not found")
                break

            Counter = line.find('Counter32: ')
            if Counter < 0:
                print("MIB ERROR : 'Counter32' not found")
                break

            Packet = line[Counter + 11:]
            OID = line[iso + 3: Equal - 1]

            dict_append = True
            for i in range(len(OID_dict)):
                # Detect OID whether exist in dictionary #
                if OID == OID_dict[i]:
                    # Append the dict index and packet value to list #
                    name.append([i, Packet])
                    dict_append = False
                    break
                    # Add new OID to OID_dict #
            if dict_append is True:
                OID_dict[len(OID_dict)] = OID
                # The (lenth - 1) also is new OID index #
                name.append([len(OID_dict) - 1, Packet])

        file.close()
print("##### OID filte END #####")

#######################################################
#  Counting feature and create the training dataset.  #
#######################################################


# Create feature and label dataset #
x_data = np.empty((file_amount, oid_amount, 2))
y_data = np.empty(file_amount)

# y and z variable for loop #
y = 0
z = 0

for n in range(len(data_type)):
    for i in range(1, amount):

        # Use two file to counting value's delta as feature #
        f1 = globals()[data_type[n] + str(i)]
        f2 = globals()[data_type[n] + str(i + 1)]

        for j in range(len(f1)):
            for k in range(len(f2)):
                # Before count, compare the OID #
                if str(f1[j][0]) == str(f2[k][0]):
                    delta = (int(f2[k][1]) - int(f1[j][1])) / 20  # 20s
                    x_data[y][z][0] = f1[j][0]
                    x_data[y][z][1] = delta
                    z += 1
                    continue
        z = 0  # Reset z for next loop

        y_data[y] = n  # Variable 'n' equal the label_dict index
        y += 1

print("##### Feature Counting END #####")

# Original dataset is 3d, reshape to 2d #
x, y, z = np.shape(x_data)
x_data = x_data.reshape(x, y*z)

'''# set MinMaxScaler object #
minmax = preprocessing.MinMaxScaler()
# data standardization #
x_data = minmax.fit_transform(x_data)
print(x_data[0])
'''

##############################
#  Start the model training  #
##############################

# cut train set and test set
dx_train, dx_test, dy_train, dy_test = train_test_split(x_data, y_data, test_size=0.2, random_state=0)

# cross validation
cv_scores = []

# test result
test_scores = []

# x-axis of plot
x = np.arange(15) + 1

knn = KNeighborsClassifier(n_neighbors=1).fit(dx_train, dy_train)

dump(knn, 'knn.joblib') 

'''
# knn train loop with cross validation
for k in x:
  knn = KNeighborsClassifier(n_neighbors=k).fit(dx_train, dy_train)
  cv_scores.append(cross_val_score(knn, dx_train, dy_train, cv=10).mean())
  test_scores.append(knn.score(dx_test, dy_test))

# plot present
plt.figure(figsize=(12,8))
plt.title('KNN Hyperparameter')
plt.plot(x, cv_scores, label = 'CV Score')
plt.plot(x, test_scores, label = 'Test Score')
plt.xlabel('k Neighbors')
plt.ylabel('Accuracy (%)')
plt.legend()
plt.grid(True)
plt.show()
'''
