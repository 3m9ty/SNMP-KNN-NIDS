# Best parameter find #

best_parameter_tmp = [0,0,0,0,0,0,0] #[test_size, cv, k, test_score, cv_score, score_sum, best_parameter_group]
anime = ["[□□□□□□□]","[■□□□□□□]","[■■□□□□□]", "[■■■□□□□]", "[■■■■□□□]", "[■■■■■□□]", "[■■■■■■□]", "[■■■■■■■]"]
ts = [0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5]
z = 0
u = 0
v = 0
parameter = []
parameter_num = []

#cross validation
cv_scores = []

#test result
test_scores = []

cv = [2, 5, 10]
while u < 3:
  while z < 8:

    #cut train set and test set
    dx_train,dx_test,dy_train,dy_test = train_test_split(x_data,y_data,test_size=ts[z],random_state=0)
    #print(y_data)

    #x-axis of plot
    x = np.arange(4) + 1

    #knn train loop with cross validation
    for k in x:
      knn = KNeighborsClassifier(n_neighbors = k).fit(dx_train, dy_train)
      cv_scores.append(cross_val_score(knn, dx_train, dy_train, cv = cv[u]).mean())
      test_scores.append(knn.score(dx_test, dy_test)) 
      parameter.append((cv[u],ts[z],k))
      parameter_num.append(v)
      print("k = " + str(k))
      print("cv = " + str(cv[u]))
      print("test_size = " + str(ts[z])) 
      #print("CV_score = " + str(cv_scores[k-1]))
      print("CV_score = " + str(cv_scores[v]))
      #print("test_score = " + str(test_scores[k-1]))
      print("test_score = " + str(test_scores[v]))
      #print("score_sum  = " + str())

      if((cv_scores[v] + test_scores[v]) > best_parameter_tmp[5]):
        best_parameter_tmp[0] = ts[z]
        best_parameter_tmp[1] = cv[u]
        best_parameter_tmp[2] = k
        best_parameter_tmp[3] = test_scores[v]
        best_parameter_tmp[4] = cv_scores[v]
        best_parameter_tmp[5] = cv_scores[v] + test_scores[v]
        best_parameter_tmp[6] = v

      v += 1

    sys.stdout.write("/rAnalyzing" + anime[z])
    sys.stdout.flush()

    z += 1
  u += 1
  z = 0

print("\n\nBest test_size  = " + str(best_parameter_tmp[0]))
print("Best cv      = " + str(best_parameter_tmp[1]))
print("Best k      = " + str(best_parameter_tmp[2]))
print("Best test_score = " + str(best_parameter_tmp[3]))
print("Best cv_score  = " + str(best_parameter_tmp[4]))
print("Best score_sum  = " + str(best_parameter_tmp[5]))
print("\n")


