import numpy as np
import matplotlib.pyplot as plt
from scipy import stats
import math
import shutil


Loc = "C:/Users/SURYA/Dropbox/video codec/"




# # Reading of file & modification part
# f = open(Loc+"wireshark.log",'r')
# out = f.readlines()
# f.close()
# length = len(out)
# temp = []
# #print length

# rn = 163591
# temprn = out[rn].lstrip().split()
# print temprn
#
# tempz = []
# for i in range(0,length-1):
# ## i = 163591
#     if "..!k/!..!k.&..E." in out[i]:
#         temp_1 = out[i].lstrip().split();
#         tempz.append(temp_1[0] + "  " + temp_1[1] + " " + temp_1[2] + " " + temp_1[3] + " " + temp_1[4] + " " + temp_1[5] + " "
#                      + temp_1[6] + " " + temp_1[7] + " " + temp_1[8] + " " + temp_1[9]+ " " + temp_1[10] + " " + temp_1[11] + " "
#                      + temp_1[12] + " " + temp_1[13]+" " + temp_1[14] + " " + temp_1[15]+ " " + temp_1[6] + " " + temp_1[17]+ "\n")
# f_out = open(Loc+"temp1.log",'w')
# for item in tempz:
#     f_out.write("%s" % item)
# f_out.close()


# Reading of file ans saving Time Stamp and FrameNubmer
Loc = "C:/Users/SURYA/Dropbox/video codec/"
f = open(Loc+"wireshark_server.log",'r')
out = f.readlines()
f.close()
length = len(out)
#print length
tempz = []
for i in range(0, length-1):
## i = 163591
    tempLine = out[i].lstrip().split()
    #print "number:", len(tempLine)
    if "Epoch" in out[i]:
        tempEp = tempLine
        tempEp[2] = str(int(float(tempEp[2])*1000000))
    elif "Frame Number:" in out[i]:
        tempFN = tempLine
    elif "0060" in out[i]:
        tempCw = tempLine
        if tempCw[0] == "0060":
            lenCwLine = len(tempCw)
            #print "number:", i, "Length", len(tempCw)
            if lenCwLine > 12:
                #print "number:", i, "Length", len(tempCw)
                CodeW = tempCw[1]+tempCw[2]+tempCw[3]+tempCw[4]+tempCw[5]+tempCw[6]
                tempz.append(tempEp[2] + "\t" + tempFN[2] + "\t" + tempCw[1] + "\t" + tempCw[2] + "\t" + tempCw[3] + "\t" + tempCw[4] + "\t" + tempCw[5] + "\t" + tempCw[6] )
                # i = int(str(CodeW),16)   ###For Hexa to Decimal
                # if int(CodeW,16) != 0:
                #     tempz.append("\t"+str(i))
                tempz.append("\n")

# for item in tempz:
#     temp1 = item.lstrip().split();
#     print temp1[1]

f_out = open(Loc+"pyGen_wireshark_server_TSnFNnCW.log",'w')
for item in tempz:
    f_out.write("%s" % item)
f_out.close()


##### PART - 1a: abstraction of epoch time and pts from wireshark packet log ############
# note*** : Program can be changed according to the data field captured by wireshark #####

# Reading of file & modification part
f = open(Loc+"wireshark_server.log",'r')
out = f.readlines()
f.close()
length = len(out)
temp = []
#print length
hc1 = "01"
hc2 = "54"
hc3 = "95"


for k in range(0,length-1):
    lentemp = len(temp)
    # if lentemp > 4:
    #     break
    if "Epoch" in out[k]:
        temp1 = out[k].lstrip().split();
        temp1[2]=str(int(float(temp1[2])*1000000))
        #temp.append(temp1[2]+"\t");
    elif "Frame Number:" in out[k]:
        tempFN = out[k].lstrip().split();
    elif "01" in out[k]:        #############   here In wireshark it will look for 01 4f (pts in hex) it may be differ then change
        temp2 = out[k].lstrip().split();
        temp4 = out[k+1].lstrip().split();
        if len(temp2)>17:
            for t, j in enumerate(temp2):
                if j == hc1:
                    if t < 12 and temp2[t+1]==hc2 and temp2[t+2]==hc3:                           # change temp[t+2] according wireshark packet
                        temp3 = temp2[t]+temp2[t+1]+temp2[t+2]+temp2[t+3]+temp2[t+4]+temp2[t+5]
                        #print(temp3)
                        i = int(str(temp3),16)
                        if int(temp3,16) != 0:
                            temp.append(temp1[2]+"\t"+str(i)+"\t" +tempFN[2]+ "\n")
                            #print "Cond1", k
                    elif t==12 and temp2[t+1]==hc2 and temp2[t+2]==hc3:
                        temp3 = temp2[t]+temp2[t+1]+temp2[t+2]+temp2[t+3]+temp2[t+4]+temp4[1]
                        i = int(str(temp3),16)
                        if int(temp3,16) != 0:
                            temp.append(temp1[2]+"\t"+str(i)+ "\t" +tempFN[2]+ "\n")
                            #print "Cond2", k
                    elif t==13 and temp2[t+1]==hc2 and temp2[t+2]==hc3:
                        #print(temp1[2])
                        temp3 = temp2[t]+temp2[t+1]+temp2[t+2]+temp2[t+3]+temp4[1]+temp4[2]
                        i = int(str(temp3),16)
                        if int(temp3,16) != 0:
                            temp.append(temp1[2]+"\t"+str(i)+ "\t" + tempFN[2]+ "\n")
                            #print "Cond3", k
                    elif t==14 and temp2[t+1]==hc2 and temp2[t+2]==hc3:
                        temp3 = temp2[t]+temp2[t+1]+temp2[t+2]+temp4[1]+temp4[2]+temp4[3]
                        i = int(str(temp3),16)
                        if int(temp3,16) != 0:
                            temp.append(temp1[2]+"\t"+str(i)+"\t" + tempFN[2]+ "\n")
                            # print "Cond4", k
                            # print "Cond4", temp2
                            # print "Cond4", temp4
                            # print "Cond4", tempFN[2]
                    elif t==15 and temp2[t+1]==hc2 and temp4[1]==hc3:
                        temp3 = temp2[t]+temp2[t+1]+temp4[1]+temp4[2]+temp4[3]+temp4[4]
                        i = int(str(temp3),16)
                        if int(temp3,16) != 0:
                            temp.append(temp1[2]+"\t"+str(i)+"\t" + tempFN[2]+ "\n")
                            #print "Cond5", k
                    elif t==16 and temp4[1]==hc2 and temp4[2]==hc3:
                        temp3 = temp2[t]+temp4[1]+temp4[2]+temp4[3]+temp4[4]+temp4[5]
                        i = int(str(temp3),16)
                        if int(temp3,16) != 0:
                            temp.append(temp1[2]+"\t"+str(i)+"\t" + tempFN[2]+ "\n")
                            # print "Cond6", k
                            # print "Cond6", temp2
                            # print "Cond6", temp4
                            # print "Cond6", tempFN[2]
#writing modified data to anotherfile
f_out = open(Loc+"python_generated_wireshark_serverLogs.log",'w')
for item in temp:
    f_out.write("%s" % item)
f_out.close()
#shutil.copy2(Loc+"python_generated_wireshark_server.log", Loc+"python_generated_wireshark_server_p1a.log")


## 1.Extracting frame numbers from python_generated_wiresharkLogsfile
Loc = "C:/Users/SURYA/Dropbox/video codec/"
f = open(Loc+"python_generated_wireshark_serverLogs.log",'r')
out = f.readlines()
f.close()
length = len(out)
tempPGFN = []

for i in range(0,length-1):
    temp1 = out[i].lstrip().split()
    tempPGFN.append(temp1[2])
#print tempPGFN



## Finding the frames and TS between sender and reciever frame TS ***Need to correct the text
##print "Index for 132 : ", tempDRFN.index('132\n')

## tempDRFN  is python generated Frame numbers in Wiresharklog file based on 01 54 85 Code, tempwFN is Frame all frame numbers in log file

f_wFN = open(Loc+"pyGen_wireshark_server_TSnFN.log",'r')
out_wFN = f_wFN.readlines()
f_wFN.close()
length_wFN = len(out_wFN)
tempwFN = []
for i in range(0,length_wFN-1):
    # i = 1
    temp1 = out_wFN[i].lstrip().split()
    #print temp1[1]
    tempwFN.append(temp1[1])

## creating sepate list for recived frames and its previous frames needs to clean.
length_wTSLogPGFN = len(tempPGFN)
#print length_wTSLogPGFN
sIndx = 0
tmpL = []

f_outFNG = open(Loc+"py_Gen_WiresharkServer_FNG.log",'w')

for j in range(0, length_wTSLogPGFN-1):
    # j =1
    iD = tempPGFN[j]
    eIndx = tempwFN.index(iD)
    sET = []
    sET.append(iD)
    tempN = tempwFN[sIndx:eIndx]
    sET = sET + tempN
    print sET
    sIndx = eIndx + 1
    f_outFNG.write("%s" % sET)

f_outFNG.close()



##### PART - 1b: abstraction of epoch time and pts  from ffserver log  ###########

# Reading of file & modification part
f = open(Loc+"server.log",'r')
out = f.readlines()
f.close()
length = len(out)
temp = []
prev_val = "0 0 0"
for i in range(0,length-1):
    if "TEST FFMDEC2 ->" in out[i]:
        temp2 = out[i].lstrip().split();
    if "Starting new cluster" in out[i]:
        temp1 = out[i].lstrip().split();
    if "Bytes sent at time" in out[i]:
        temp3 = out[i].lstrip().split();
        if len(temp1)>18:
            temp.append(prev_val+"\t"+temp3[11]+"\n");
            prev_val = temp2[8]+"\t"+temp1[19]+"\t"+temp2[11];

#writing modified data to anotherfile
f_out = open(Loc+"python_generated_ffserver_server.log",'w')
for item in temp:
    f_out.write("%s" % item)
#print(temp)
f_out.close()
shutil.copy2(Loc+"python_generated_ffserver_server.log", Loc+"python_generated_ffserver_server_p1b.log")

##### PART - 1c: Epoch Time Difference file between Wireshark frame & FFserver frame  ###########

f_1 = open(Loc+"python_generated_wireshark_server.log",'r')
out_1 = f_1.readlines()
f_1.close()
length = len(out_1)
f_2 = open(Loc+"python_generated_ffserver_server.log",'r')
out_2 = f_2.readlines()
length_1 = len(out_2)
f_2.close()
k= 0
a=0
b= length_1
x_1 = []
z = []
temp = []
for i in range(0,length-1):
        temp_1 = out_1[i].lstrip().split();
        j = k
        #print temp_1
        for l in range(j,length_1-1):
            temp_2 = out_2[l].lstrip().split();
            #print l
            if temp_1[1]==temp_2[1]:
                temp.append(temp_2[0]+"\t"+temp_2[2]+"\t"+temp_2[3]+"\t"+temp_1[0]+"\n")
                k+=1
                break

print("\n")

f_out = open(Loc+"python_generated_wirehark+ffserver_timestamp.log",'w')
for item in temp:
    f_out.write("%s" % item)
#print(temp)
f_out.close()
shutil.copy2(Loc+"python_generated_wirehark+ffserver_timestamp.log", Loc+"python_generated_wirehark+ffserver_timestamp__p1c.log")

##### PART - 2: abstraction of BMPdecoder and FFMENC epoch time from ffmpeg log  ###########

# Reading of file & modification part
f = open(Loc+"ffmpeg.log",'r')
out = f.readlines()
f.close()
length = len(out)
temp = []
temp1 = []
for i in range(0,length):
    if "raw_decode() called" in out[i]:
        temp1 = out[i].lstrip().split();
        #print temp1[1]
        temp1_1 = temp1[0].split("[")
        temp1_2 = temp1_1[1].split("]")
        #print(temp1_2[0])
    elif "FFMENC --> Start_time" in out[i]:
        temp2 = out[i].lstrip().split();
        temp2_1 = temp2[0].split("[")
        temp2_2 = temp2_1[1].split("]")
        #print(temp1[7])
    elif "UTILS: the size in append_packet_chunked" in out[i]:
        temp3 = out[i].lstrip().split();
        #print temp1[1]
        temp3_1 = temp3[0].split("[")
        temp3_2 = temp3_1[1].split("]")
        #print(temp1_2[0])
    elif "UTILS:read_frame_internal() no parsing needed:" in out[i]:
        temp4 = out[i].lstrip().split();
        temp4_1 = temp4[0].split("[")
        temp4_2 = temp4_1[1].split("]")
        if len(temp1)!=0:
            temp.append(temp1[6]+"\t"+temp1_2[0]+"\t"+temp2_2[0]+"\t"+temp3_2[0]+"\t"+temp4_2[0]+"\n")


#writing modified data to anotherfile
f_out = open(Loc+"python_generated_bmp_ffmenc_render_timestamp.log",'w')
for item in temp:
    f_out.write("%s" % item)
f_out.close()
#print(temp)
shutil.copy2(Loc+"python_generated_bmp_ffmenc_render_timestamp.log", Loc+"python_generated_bmp_ffmenc_render_timestamp_p2.log")

##### PART - 3: abstraction of epoch time from render log for particular frame from ffmpeg log ###########

# Reading of file & modification part
f_render = open(Loc+"render1.log",'r')
out_render = f_render.readlines()
length_render = len(out_render)
f_render.close()

# epoch time of render frame from render log will be added to below opened file
f_bmp = open(Loc+"python_generated_bmp_ffmenc_render_timestamp.log",'r')
out_bmp = f_bmp.readlines()
length_bmp = len(out_bmp)
f_bmp.close()

#print(length_bmp)
k= 0
z = []
for i in range(0,length_bmp-1):
        temp_1 = out_bmp[i].lstrip().split();
        j = k
        for l in range(j,length_render-1):
            temp_2 = out_render[l].lstrip().split();
            if int(temp_1[0])==int(temp_2[3]):
                temp_1.append(temp_2[0])
                #print(temp_1)
                z.append(temp_1[0]+"\t"+temp_1[5]+"\t"+temp_1[1]+"\t"+temp_1[2]+"\t"+temp_1[3]+"\t"+temp_1[4]+"\n")
                k+=1
                break

#writing modified data
f_out = open(Loc+"python_generated_bmp_ffmenc_render_timestamp.log",'w')
for item in z:
    f_out.write("%s" % item)
f_out.close()
#print(temp)

shutil.copy2(Loc+"python_generated_bmp_ffmenc_render_timestamp.log", Loc+"python_generated_bmp_ffmenc_render_timestamp_p3.log")
##### PART - 4: abstraction of epoch time from server log  for particular wireshark captured frame ###########


# Reading of file & modification part
f_server = open(Loc+"python_generated_wirehark+ffserver_timestamp.log",'r')
out_server = f_server.readlines()
length_server = len(out_server)
f_server.close()
# epoch time of ffmdec frame from server log will be added to below opened file
f = open(Loc+"python_generated_bmp_ffmenc_render_timestamp.log",'r')
out = f.readlines()
length = len(out)
f.close()

k= 0
x = []
z = []
for i in range(0,length_server-1):
    temp_1 = out_server[i].lstrip().split();
    j = k
    #print(temp_1)
    for l in range(j,length-1):
        temp_2 = out[l].lstrip().split();
        if int(temp_1[0])==int(temp_2[0]):
            #print(temp_1)
            z.append(temp_2[0]+"\t"+temp_2[1]+"\t"+temp_2[2]+"\t"+temp_2[3]+"\t"+temp_2[4]+"\t"+temp_2[5]+"\t"+temp_1[1]+"\t"+temp_1[2]+"\t"+temp_1[3]+"\n")
            k+=1
            break

#writing modified data
f_out = open(Loc+"python_generated_bmp_ffmenc_render_timestamp.log",'w')
for item in z:
    f_out.write("%s" % item)
f_out.close()
#print(temp)
shutil.copy2(Loc+"python_generated_bmp_ffmenc_render_timestamp.log", Loc+"python_generated_bmp_ffmenc_render_timestamp_p4.log")

##### PART - 4.5: abstraction of epoch time from WireSharkSender log ###########



##### PART - 5: Plot of delay between different point and calculations ###########

f = open(Loc+"python_generated_bmp_ffmenc_render_timestamp.log",'r')
out = f.readlines()
length = len(out)
k= 0
x = []
out_1 = []
out_2 = []
out_3 = []
out_4 = []
out_5 = []
out_6 = []
out_7 = []
res = []
for i in range(0,length-1):
    temp_1 = out[i].lstrip().split();
    x.append(i)
    out_1.append((float(temp_1[2])-float(temp_1[1]))/1000)
    out_2.append((float(temp_1[3])-float(temp_1[2]))/1000)
    out_3.append((float(temp_1[5])-float(temp_1[4]))/1000)
    out_4.append((float(temp_1[6])-float(temp_1[3]))/1000)
    out_5.append((float(temp_1[7])-float(temp_1[6]))/1000)
    out_6.append((float(temp_1[8])-float(temp_1[7]))/1000)
    out_7.append((float(temp_1[8])-float(temp_1[1]))/1000)

    res.append(temp_1[0]+" \t"+str(out_1[i])+"\t"+str(out_2[i])+"\t"
               +str(out_3[i])+"\t"+str(out_4[i])+"\t"+str(out_5[i])+"\t"+str(out_6[i])+ "\t" + str(out_7[i])+"\n")


#writing modified data
f_out = open(Loc+"python_generated_all_delay_data.log",'w')
for item in res:
    f_out.write("%s" % item)
f_out.close()


##  Mean, Standard Deviation and Confidence Interval calculation
print ("__________________________________________________________________________________________________")
print ("                             |Average    Deviation                   ConfidenceInterval")
s = np.array(out_1)
n, min_max, mean, var, skew, kurt = stats.describe(s)
std=math.sqrt(var)
R_1 = stats.norm.interval(0.95,loc=mean,scale=std/math.sqrt(len(s)))
print ("Render-->Raw Dec              |"+str(int(mean))+"\t   "+str(int(std)) +"\t\t"+ str(R_1))
s = np.array(out_2)
n, min_max, mean, var, skew, kurt = stats.describe(s)
std=math.sqrt(var)
R_2= stats.norm.interval(0.95,loc=mean,scale=std/math.sqrt(len(s)))
print ("Raw Dec-->FFMEnc             |"+str(int(mean))+"\t   "+str(int(std))+ "\t\t"+ str(R_2))

s = np.array(out_3)
n, min_max, mean, var, skew, kurt = stats.describe(s)
std=math.sqrt(var)
R_3 = stats.norm.interval(0.95,loc=mean,scale=std/math.sqrt(len(s)))
print ("Buffer                       |"+str(int(mean))+"\t   "+str(int(std)) +"\t\t"+ str(R_3))

s = np.array(out_4)
n, min_max, mean, var, skew, kurt = stats.describe(s)
std=math.sqrt(var)
R_6 = stats.norm.interval(0.95,loc=mean,scale=std/math.sqrt(len(s)))
print ("FFMEnc-->FFMDec              |"+str(int(mean))+"\t   "+str(int(std))+"\t\t"+  str(R_6))

s = np.array(out_5)
n, min_max, mean, var, skew, kurt = stats.describe(s)
std=math.sqrt(var)
R_6 = stats.norm.interval(0.95,loc=mean,scale=std/math.sqrt(len(s)))
print ("FFMDec-->Server Socket       |"+str(int(mean))+"\t   "+str(int(std))+"\t\t"+  str(R_6) )

s = np.array(out_6)
n, min_max, mean, var, skew, kurt = stats.describe(s)
std=math.sqrt(var)
R_4 = stats.norm.interval(0.95,loc=mean,scale=std/math.sqrt(len(s)))
print ("Server Socket--> Client Socket  |"+str(int(mean))+"\t   "+str(int(std)) +"\t\t"+  str(R_4))

s = np.array(out_7)
n, min_max, mean, var, skew, kurt = stats.describe(s)
std=math.sqrt(var)
R_5 = stats.norm.interval(0.95,loc=mean,scale=std/math.sqrt(len(s)))
print ("Render--> Client Socket       |"+str(int(mean))+"\t   "+str(int(std))+"\t\t"+  str(R_5))


print ("_____________________________|______________________________________________________________________")

### PLoting of different delay
fig = plt.figure(1)
#plt.figure(1)
plt.xlabel('Frame Number')
plt.ylabel('Latency in msec')
#plt.ylim((0,500))
#plt.xlim((0,900))
plt.plot(x,out_1,label="Render-->Raw Dec")
plt.plot(x,out_2,label="Raw Dec-->FFMEnc")
plt.plot(x,out_3,label="Buffer")
plt.plot(x,out_4,label="FFMEnc-->FFMDec")
plt.plot(x,out_5,label="FFMDec-->Server Socket")
plt.plot(x,out_6,label="Server Socket-->Client Socket")
plt.plot(x,out_7,label="Render-->Client Socket")

plt.legend( loc='upper left', numpoints = 1,prop={'size':6.5} )
fig.savefig('delay_with_PL_0.01.png')
plt.show()

