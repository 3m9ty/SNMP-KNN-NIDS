oid_str = '3.6.1.2.1.5.8.0'
new_str = '3.6.1.2.1.5.9.0'

for i in range(1,602):
  file_data = ""
  file = open("normal"+str(i),'r')
  for line in file:
    if oid_str in line:
      line = line.replace(oid_str,new_str)
    file_data += line
  file.close()
  with open("normal"+str(i),'w',encoding="utf-8")as f:
    f.write(file_data)