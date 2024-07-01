import os
import re
import csv
import sys
import time
import numpy as np
from joblib import load
from sklearn import preprocessing
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MinMaxScaler
from sklearn.neighbors import KNeighborsClassifier
###############################################################################

amount = 2                       # Capture 2 MIB data in once predict
file_amount = int((amount-1))    # Network type has 5 type
oid_amount = 38                  # One file has 38 OID
timeout = False
Host = "192.168.1.100 "          # Server
Switch = "192.168.1.253 "
LastType = 'normal'              # Default network didn't occur attack
ModelPath = 'KNN_Model.pgz'
FilePath = "/home/lab/SNMP/Detection_MiB/" # "~/SNMP/MIB/"
KNN = load('knn.joblib')         # Load the KNN model

##############################
#  OID list for capture MiB  #
##############################
switch_oid = ['1.3.6.1.2.1.2.2.1.10.2', '1.3.6.1.2.1.2.2.1.10.24', '1.3.6.1.2.1.2.2.1.11.2', '1.3.6.1.2.1.2.2.1.11.24',
              '1.3.6.1.2.1.2.2.1.16.2', '1.3.6.1.2.1.2.2.1.16.24', '1.3.6.1.2.1.2.2.1.17.2', '1.3.6.1.2.1.2.2.1.17.24']

host_oid = ['1.3.6.1.2.1.4.3.0', '1.3.6.1.2.1.4.9.0', '1.3.6.1.2.1.4.10.0', '1.3.6.1.2.1.4.11.0',
            '1.3.6.1.2.1.4.31.1.1.3.1', '1.3.6.1.2.1.4.31.1.1.5.1', '1.3.6.1.2.1.4.31.1.1.18.1',
            '1.3.6.1.2.1.4.31.1.1.20.1', '1.3.6.1.2.1.4.31.1.1.25.1', '1.3.6.1.2.1.4.31.1.1.30.1',
            '1.3.6.1.2.1.4.31.1.1.32.1', '1.3.6.1.2.1.5.1.0', '1.3.6.1.2.1.5.3.0', '1.3.6.1.2.1.5.9.0',
            '1.3.6.1.2.1.5.14.0', '1.3.6.1.2.1.5.15.0', '1.3.6.1.2.1.5.16.0', '1.3.6.1.2.1.5.22.0',
            '1.3.6.1.2.1.5.29.1.2.1', '1.3.6.1.2.1.5.29.1.4.1', '1.3.6.1.2.1.5.29.1.5.1', '1.3.6.1.2.1.5.30.1.3.1.3',
            '1.3.6.1.2.1.5.30.1.3.1.8', '1.3.6.1.2.1.5.30.1.4.1.0', '1.3.6.1.2.1.5.30.1.4.1.3', '1.3.6.1.2.1.6.10.0',
            '1.3.6.1.2.1.6.11.0', '1.3.6.1.2.1.6.12.0', '1.3.6.1.2.1.6.15.0', '1.3.6.1.2.1.7.2.0']

########################################
# Make a "OID" and "label" Dictionary  #
########################################
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
# Use list to make a "OID" Dictionary
for i in oid:
    OID_dict[count] = i
    count += 1

# Label dictionary
label_dict = {0: 'Normal', 1: 'TCP Attack', 2: 'ARP Attack', 3: 'UDP Attack', 4: 'ICMP Attack'}

###############################################
#  The predict loop execute every 5 minutes  #
###############################################
while 1 == 1:
    DateString = time.strftime("%Y-%m-%d ", time.localtime()) 
    TimeString = time.strftime("%H:%M:%S", time.localtime())
    print("========================================")
    print("   Date: " + DateString + "   Time: " + TimeString )
    print("========================================")
    
    #######################
    #  Start capture MiB  #
    #######################
    Datemd = time.strftime("%m-%d", time.localtime()) 
    TimeHM = time.strftime("%H:%M", time.localtime())
    filename = ("MIB_" + Datemd + "_" + TimeHM)
    
    sleep = 1  #  Sleep funtion counter
    for n in range(1, amount + 1):
        print("Start to capture MiB (" + str(n) + "/" + str(2) + ")...")

        # Capture OID from Switch(192.168.1.253)
        for j in switch_oid:
            os.system("snmpwalk -v 2c -c public " + Switch + j + " >>" + FilePath + filename + "\(" + str(n) + "\)" +
			                                         " 2>> " +  FilePath + filename + "\(" + str(n) + "\)")

        # Capture OID from attacked host
        for k in host_oid:
            os.system("snmpwalk -v 2c -c public " + Host + k + " >>" + FilePath + filename + "\(" + str(n) + "\)"
			                                      " 2>> " +  FilePath + filename + "\(" + str(n) + "\)")

        if sleep != 0:
          time.sleep(20)  # MiB file interval 20 sec.
          sleep -= 1

    print("Capture MiB END\n")

    #############################
    #  Preprocess the MiB file  #
    #############################
    print("Start to Preprocess... ")

    # Filtration OID octet and put it in list #
    for i in range(1, amount + 1):

        # Load the OID file
        file = open(FilePath + filename + "(" + str(i) + ")")
        iter_file = iter(file)

        # Create a global variable(list) ###
        globals()["File" + str(i)] = []
        # Use 'name' to replace compound string
        name = globals()["File" + str(i)]

        #  Capture "Counter32" volume
        for line in iter_file:
            iso = line.find('iso')
            if iso < 0:
                if line.find('Timeout') >= 0:
                    timeout = True
                    continue
                elif line.find('Timeout'):
                    print("MIB CAPTURE OCCUR ERROR!")
                    break

            Equal = line.find('=')

            state = -1
            Counter = line.find('Counter32: ')  
            if Counter < 0:
		#if OID output this messages
            	if line.find('No Such Instance currently exists at this OID\\') < 0:
            		Packet = 0  # If OID not exists, set 0.
            		state = 1
            	else:
            		print("MIB ERROR : 'Counter32' not found")
            		break
            if state < 0:
            	Packet = line[Counter + 11:]
            OID = line[iso + 3: Equal - 1]

            dict_append = True
            for i in range(len(OID_dict)):
                # Detect OID whether exist in dictionary
                if OID == OID_dict[i]:
                    # Append the dict index and packet value to list
                    name.append([i, Packet])
                    dict_append = False
                    break
                    # Add new OID to OID_dict
            if dict_append is True:
                OID_dict[len(OID_dict)] = OID
                # The (lenth - 1) also is new OID index
                name.append([len(OID_dict) - 1, Packet])

        file.close()

    #  Set a array to store feature
    Feature = np.zeros((file_amount, oid_amount, 2))
    # Use two file to count value's delta as feature
    f1 = File1
    f2 = File2
    z = 0
    for j in range(len(f1)):
        for k in range(len(f2)):
            # Before count, compare the OID
            if str(f1[j][0]) == str(f2[k][0]):
                delta = (int(f2[k][1]) - int(f1[j][1])) / 20  # 20sec
                Feature[0][z][0] = f1[j][0]
                if delta == 'nan':
                    Feature[0][z][1] = 0
                else:
                    Feature[0][z][1] = delta
                z += 1
                continue

    # Original dataset is 3d, reshape to 2d
    x, y, z = np.shape(Feature)
    Feature = Feature.reshape(x, y * z)

    print("Preprocess END\n")

    ################################
    #  Start the model predicting  #
    ################################
    print("Start Predict...")
        
    prediction = KNN.predict(Feature)
    network_type = label_dict[int(prediction)]

    if timeout is True:  # Host timeout
        if network_type == 'Normal':
            print("### Network Type : \"" + str(network_type) + "\" ###")
            print("WARNNING! The Host occur the unknown situation, Please check the host or switch.\n ")
        else:  # the type is attack
            print("### Network Type : \"" + str(network_type) + "\" ###")
            print("WARNNING! The Host disconnected due to attack, Please check the host or switch.\n ")
    elif timeout is False:
        LastType = network_type
        print("### Network Type : \"" + str(network_type) + "\" ###\n\n")

    time.sleep(39)  # Detect every five minutes (300sec)
