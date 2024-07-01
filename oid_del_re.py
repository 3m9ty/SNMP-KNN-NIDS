start = 251
end = 801
filename = 'udp'

for i in range(start,end+1):
  file_data = ""

  f = open(filename + str(i))
  f_iter = iter(f)

  for j in range(38):
    next(f_iter)

  for line in f_iter:
    file_data += line

  with open(filename + str(i),'w') as f:
    f.write(file_data)
