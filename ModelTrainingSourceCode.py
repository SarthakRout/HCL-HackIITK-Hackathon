import os
import json
import pandas as pd
import numpy as np
import pickle
import joblib

data={}
# Directory(Set to test this)
default='/content/HCLCR1/' 
static='Static_Analysis_Data/'  
benign='Benign/'
malware='Malware/'
dyn1='Dynamic_Analysis_Data_Part1/'
dyn2='Dynamic_Analysis_Data_Part2/'
#Types of Malware
dirs=['Backdoor','Trojan','TrojanDownloader','TrojanDropper','Virus','Worm']
drive='/content/gdrive/My Drive/HCLCR1' #Google Drive directory for Colab
data={}#This is the dict data

def hexa(stringobj):
	if(stringobj[:2] != '0x'):
		return 1
	return int(stringobj[2:], 16)
def readStringAndStructure(a,y,threshold):#Reading static data
  os.chdir(a) 
  stringobj = {}
  for foldername in os.listdir():
    if not foldername in data:
      data[foldername]={}
    os.chdir(foldername)
    print('in '+foldername)
    print('Opening String.txt ')
    fs=open('String.txt','r')
    for line in fs.readlines():
      line = line.replace('\n', '')
      if(line.isalnum()==True) and (len(line) > 4):#check this once
        if line in stringobj:
          stringobj[line] = stringobj[line] + 1
        else:
          stringobj[line] = 1
    fs.close()
    print('Opening Structure_Info.txt ')
    names = ['.text', '.data', '.rsrc', '.rdata', 'reloc']
    header_name = ''
    section_name = ''
    file= open('Structure_Info.txt', 'r', encoding='utf-8', errors='ignore')
    for line in file.readlines():
      line = line.replace("\n", "")
      if line[:6] == '[IMAGE':
        header_name = line
        continue
      if line[:2] == '0x':
        parts = line.split()
        if ((len(parts) == 4) or (parts[2] == 'TimeDateStamp')):
          if (parts[2] == 'Name'):
            section_name = parts[2]
            continue
          if header_name == '[IMAGE_SECTION_HEADER]':
            data[foldername][section_name + '_' + parts[2]] = hexa(parts[3])
          else:
            data[foldername][header_name + '_' + parts[2]] = hexa(parts[3])
      elif ((line[:2] == 'Dl') or (line[:2] == 'Fl')) :
        parts = line.split()
        for part in parts[1:]:
          if part.endswith(','):
             part=part[:-1]
          print('Flag'+part)
          data[foldername][part] = 1
    file.close()          
    data[foldername]['y']= y 
    os.chdir('..')
    print(len(data))
  os.chdir(a)
  for foldername in os.listdir():
    if not foldername in data:
      data[foldername]={}
    os.chdir(foldername)
    print('in '+foldername)
    print('Opening String.txt ')
    fs=open('String.txt','r')
    for line in fs.readlines():
      line = line.replace('\n', '')
      if line in stringobj:
        if stringobj[line]>threshold:
            data[foldername][line]=1
    os.chdir('..')
    print(len(data))      
  stringobj={}                  
def dynamicjson(a,y,gram,threshold): # reading dynamic observations
  os.chdir(a)
  stringobj={}
  for fname in os.listdir():
    print('Opening '+fname)
    if fname.endswith(".json"):
      with open(fname,encoding='utf-8') as p:
        js=json.load(p)
      fname=fname[:-5]#VerifyOnce
      if not fname in data:
        data[fname]={}
      data[fname]['y']=y  
      behav=js['behavior']['processes']
      for obj in behav:
        calls=obj['calls']
        for i in range (0,len(calls)-gram):
          col=''
          for j in range(i,i+gram):
            col=col+calls[j]['api']#Check Again maybe not present
          if col in stringobj:
             stringobj[col]=stringobj[col]+1
          else:
             stringobj[col]=1
  for fname in os.listdir():
    print('Opening '+fname)
    if fname.endswith(".json"):
      with open(fname,encoding='utf-8') as p:
        js=json.load(p)
      fname=fname[:-5]#VerifyOnce
      if not fname in data:
        data[fname]={}
      behav=js['behavior']['processes']
      for obj in behav:
        calls=obj['calls']
        for i in range (0,len(calls)-gram):
          col=''
          for j in range(i,i+gram):
            col=col+calls[j]['api']#Check Again maybe not present
          if col in stringobj:
            if stringobj[col]>threshold:
              data[fname][col]=1
  stringobj={} 

readStringAndStructure(default+static+benign,0,300)
print('done1')
os.chdir(default+static+malware)
for dir in dirs:
  if dir in os.listdir():
    print(dir)
    readStringAndStructure(default+static+malware+dir,1,100)
    os.chdir(default+static+malware)
print('done2')
os.chdir(default+dyn1+benign)
dynamicjson(default+dyn1+benign,0,4,300)
print('done3')
os.chdir(default+dyn1+malware)
for dir in dirs:
  if dir in os.listdir():
    print(dir)
    dynamicjson(default+dyn1+malware+dir,1,4,100)
    os.chdir(default+dyn1+malware)
print('done4')
os.chdir(default+dyn2+benign)
dynamicjson(default+dyn2+benign,0,4,300)
print('done5')
os.chdir(default+dyn2+malware)
for dir in dirs:
  if dir in os.listdir():
    print(dir)
    dynamicjson(default+dyn2+malware+dir,1,4,100) 
    os.chdir(default+dyn2+malware)
print('done6')    

mixed=pd.DataFrame.from_dict(data,'index')  
mixed=mixed.fillna(0)   
mixed.to_csv('fulldataset.csv')

cols=mixed.columns
pickle.dump(cols,open('Features.dat','wb'))

X=mixed[[i for i in list(mixed.columns) if i != 'y']].values #Feature vector extraction
y=mixed[['y']].values #Target values

#Training and testing part begins
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2
from sklearn.pipeline import Pipeline
from sklearn.externals import joblib
from sklearn.linear_model import LogisticRegression
from sklearn import svm
from sklearn import tree
import random 
# Load and split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=random.randint(1,10000))

# Construct some pipelines
feature_selection = SelectKBest(chi2,k=3000)
pipe_lr = Pipeline([('mml', MinMaxScaler()),
			('feature_selection', feature_selection),
			('clf', LogisticRegression(max_iter=5000, random_state=46, solver='lbfgs', multi_class='ovr'))])

pipe_svm = Pipeline([('mml', MinMaxScaler()),
			('feature_selection', feature_selection),
			('clf', svm.SVC(random_state=42))])
			
pipe_dt = Pipeline([('mml', MinMaxScaler()),
			('feature_selection', feature_selection),
			('clf', tree.DecisionTreeClassifier(random_state=42))])

# List of pipelines for ease of iteration
pipelines = [pipe_lr, pipe_svm, pipe_dt]
			
# Dictionary of pipelines and classifier types for ease of reference
pipe_dict = {0: 'Logistic Regression', 1: 'Support Vector Machine', 2: 'Decision Tree'}

# Fit the pipelines
i=0
for pi in pipelines:
 print(i)
 pi.fit( X_train ,  y_train.ravel() )

# Compare accuracies
for idx, val in enumerate(pipelines):
	print('%s pipeline test accuracy: %.3f' % (pipe_dict[idx], val.score(X_test, y_test)))

# Identify the most accurate model on test data
best_acc = 0.0
best_clf = 0
best_pipe = ''
for idx, val in enumerate(pipelines):
	if val.score(X_test, y_test) > best_acc:
		best_acc = val.score(X_test, y_test)
		best_pipe = val
		best_clf = idx
print('Classifier with best accuracy: %s' % pipe_dict[best_clf])

#Logistic Regression pipeline test accuracy: 0.998
#Support Vector Machine pipeline test accuracy: 0.993
#Decision Tree pipeline test accuracy: 0.996
#Classifier with best accuracy: Logistic Regression

y_pred=best_pipe.predict(X_test)
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
print(cm)

#[[1274    4]
# [   0 1222]]  

joblib.dump(best_pipe,open('Model.joblib','wb'))