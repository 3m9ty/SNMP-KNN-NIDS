import sys
import os
import time

print("===================================")
x = int(input("Please select the data type number: \n"+" (0)NORMAL (1)ARP (2)ICMP (3)TCP (4)UDP \n"+"Data type: "))
y = int(input("\nSelect the numbers of file: "))
z = int(input("\nSelect the amount of file : "))

switch_oid = ['1.3.6.1.2.1.2.2.1.10.2','1.3.6.1.2.1.2.2.1.10.24','1.3.6.1.2.1.2.2.1.11.2','1.3.6.1.2.1.2.2.1.11.24',
              '1.3.6.1.2.1.2.2.1.16.2','1.3.6.1.2.1.2.2.1.16.24','1.3.6.1.2.1.2.2.1.17.2','1.3.6.1.2.1.2.2.1.17.24']


if x == 0:
	x = 'normal'
elif x == 1:
	x = 'arp'
elif x == 2:
	x = 'icmp'
elif x == 3:
	x = 'tcp'
elif x == 4:
	x = 'udp'  
else:
	print("The data type number is wrong!")
	os.exit()
 
for i in range(y,z+1):
  print("Start to Poll MiB (" + str(i) + "/" + str(z) + ")\n")
	
  #Capture OID from Switch(192.168.1.253)
  for j in switch_oid:			 
	  os.system("snmpwalk -v 2c -c public 192.168.1.253 " + j + " >>" + " ~/SNMP/MIB/" + x + str(i))
    
  time.sleep(10)	  	  

print("Finished\n")
