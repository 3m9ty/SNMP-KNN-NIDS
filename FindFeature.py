import os
import re
import csv
import mmap
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import pickle as pickle
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.decomposition import PCA
from sklearn.preprocessing import MinMaxScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report,confusion_matrix
from sklearn import metrics
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

##############################################################################
##############################################################################
######   diff_3.0 VERSION USE "LIST" INSTEAD OF "CSV"    ########
##############################################################################
##############################################################################

x = int(input("Select amounts of input data: "))

##############################################################################
############ Classification OID to "INTEGER","Counter32" ################
##############################################################################

for data_type in ['normal','tcp','arp','udp','icmp']:  
  for i in range(1,1+x): 

    ##### Load the OID file, two file are open because #####
      ###  need to distinguish integer or counter  ###
    file = open(data_type + str(i))
    file1 = open(data_type + str(i))
    iterf_integer = iter(file) 
    iterf_counter = iter(file1)  

    ##### Create new files to save transform data #####
    File_Integer = open(data_type + "_oid_integer" + str(i) + ".txt",'w',
		        encoding='utf-8',newline='')
    File_Counter = open(data_type + "_oid_counter" + str(i) + ".txt",'w',
		        encoding='utf-8',newline='')

    ##### Skip unimportant OIDs in the first few lines of file #####
    for j in range(11):
      next(iterf_integer)
    for j in range(11):
      next(iterf_counter)   

    ##### Capture "INTEGER" volume #####
    for line in iterf_integer:
      iso = line.find('iso')
      if iso < 0:
        print("MIB data ERROR\n")
        exit()

      equal = line.find('=')

      if line.find('INTEGER: ') > 0:
        integer = line.find('INTEGER: ')
        volume = int(line[integer+9: ])

        OID = line[iso+3 : equal-1]

        if volume >= 0:
          string = (OID + "," + str(volume)+ ",")
          File_Integer.write(string)


    ##### Capture "Counter32" volume #####
    for line in iterf_counter:
      iso = line.find('iso')
      if iso < 0:
        print("MIB data ERROR\n")
        exit()
      
      equal = line.find('=')

      if line.find('Counter32: ') > 0:
       counter = line.find('Counter32: ')
       packet = int(line[counter+11: ])

       OID = line[iso+3: equal-1]

       if packet >= 0:       
         string = (OID + "," + str(packet)+ ",")
         File_Counter.write(string)

    ##### Change the new file's permission #####
    os.system("sudo chmod 777 "+ data_type +"_oid_integer" + str(i) +".txt")
    os.system("sudo chmod 777 "+ data_type +"_oid_counter" + str(i) +".txt")
    file.close()
    File_Integer.close()
    File_Counter.close()
print("##### OID filte END #####")

############################################################
### Load 5 data types OID into list (90 files) ###
############################################################
data_type = ['normal','tcp','arp','udp','icmp']
filename = ["_oid_integer","_oid_counter"]

for n in range(len(data_type)):
  for m in range(len(filename)):
    for i in range(1,1+x):

      f = open( data_type[n] + filename[m] + str(i) + '.txt',encoding='utf-8',newline='')
      OID_File = f.read().split(',') #EX: [.3.6.1.2.1.2.2.1,20] -> [.3.6.1.2.1.2.2.1],[20]    

      ### Create a global variable(list) ###    
      globals()[data_type[n] + filename[m] + str(i)] = [] 
      ### Use 'name' to replace compound string ###
      name = globals()[data_type[n] + filename[m] + str(i)]

      ### Inorder to append two value in one time， ###
      ### using buf and count to control "append()". ####       
      count = 0    
      for line in OID_File:
        if count == 0:
          buf = line
          count = 1
        elif count == 1:
          name.append([buf,line])
          count = 0
      f.close()

#print(icmp_oid_counter9)
#print(icmp_oid_counter9[0][0])

##############################################################################
################# compare OID before counting delta ####################
### 1.OID(normal)<->OID(attack_type) 2.delta = normal - attack_type ###
##############################################################################
data_type = ['tcp','arp','udp','icmp']
filename = ["_oid_integer","_oid_counter"]

for n in range(len(data_type)):
  for m in range(len(filename)):
    for i in range(1,1+x):
      f = open( data_type[n] + filename[m] +'_diff' + str(i) + '.txt','w')
      csv_write = csv.writer(f)
      csv_write.writerow(['OID',' Normal',' Attack ',' delta'])

      ### Use 'attack','normal' to replace compound string ###
      attack = globals()[data_type[n] + filename[m] + str(i)]
      normal = globals()['normal' + filename[m] + str(i)]
      
      k = 0
      att_lenth = len(attack)-1
      for j in range(len(normal)-1):
        for k in range(att_lenth):

          if str(normal[j][0]) == str(attack[k][0]):           
            delta = int(attack[k][1]) - int(normal[j][1])
            
            if (delta != 0):              
              ### Write Format : [OID, normal volume, attack volume, delta] ###
              csv_write.writerow([attack[k][0], normal[j][1], attack[k][1], str(delta)])
              del attack[k]
              att_lenth -= 1
              continue
            else:
              del attack[k]
              att_lenth -= 1
              continue

      f1 = open(data_type[n] +filename[m] +'_lost' + '.txt','w')
      csv_lost = csv.writer(f1)
      for j in range(len(attack)):
        csv_lost.writerow([attack[j][0],attack[j][1]])

      f1.close()   
      f.close()
print("##### COUNTING END #####")    
