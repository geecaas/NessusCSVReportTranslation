#!/usr/bin/python
# -*- coding:utf-8 -*- 

import sys
from lxml import etree
import sqlite3
import unicodecsv as ucsv
import csv
from baidu_traslate import translate
import time

host=''
result_list=[]
list_host=[]
def getRisk(r):
    risk=""
    if r=="Critical":
        risk="Critical"
    elif r=="High":
        risk="High"
    elif r=="Medium":
        risk="Medium"
    elif r=="Low":
        risk="低危"
    elif r=="None":
        risk='信息'
    else:
        risk='Parsing error,Check that the versions are consistent.'
    return risk
    
def select(id, ip, protocol,port,CVE):
    f=open("./NessusChineseVulnerable.csv")
    db_reader = csv.reader(f)
    for row in db_reader:
        type(row[0])
        type(id)
        if row[0]==id:
            f.close()
            return [id,ip, protocol,port, row[1], CVE,row[2], row[3], row[4], row[5]]
    f.close()


def insert(plugin_id,name,risk,description,solution):
    f=open("./NessusChineseVulnerable.csv","ab")
    w = ucsv.writer(f, encoding='gbk')
    item = [plugin_id, name, risk, description, solution,u'yes']
    w.writerow(item)
    f.close()
    print("插入成功", plugin_id)

if __name__ == '__main__':
    file_name = sys.argv[1]
    csv_reader = csv.reader(open(file_name)) 
    i=0
    for row in csv_reader:
        if i==0:
            print(row)
        elif(i>= 1):
            print("初始化中......."+str(row))
            risk=getRisk(row[3])
            if risk=="信息" or risk=="低危":
                continue 
            list_host.append(row[0]+"-*-"+row[1]+"-*-"+row[2]+"-*-"+risk+"-*-"+row[4]+"-*-"+row[5]+"-*-"+row[6]+"-*-"+row[7]+"-*-"+row[8]+"-*-"+row[9]+"-*-"+row[10])
        else:
            print("初始化结束，即将开始翻译....")
            break
        i=i+1

    with open(file_name[:-4]+'_Out.csv', 'wb') as f:
        w = ucsv.writer(f, encoding='gbk')
        title = [u'扫描插件ID',u'IP',u'协议',u'端口',u'漏洞名称',u'CVE编号',u'风险等级', u'漏洞描述', u'整改建议',u'百度翻译']
        w.writerow(title)
        for i in list_host:
            info = i.split('-*-')
            result = select(info[0],info[4],info[5],info[6],info[1])
            if result is not None:
                data = result
                print("本地数据库命中："+str(data))
            else:
                abc = info[7]+"$*#^#*$"+info[9]+"$*#^#*$"+info[10] 
                abc = translate(abc)
                time.sleep(1)
                abc = abc.split('$*#^#*$')

                insert(info[0],abc[0],info[3],abc[1],abc[2])
                data = info[0],info[4],info[5],info[6],abc[0],info[1],info[3],abc[1],abc[2],'yes'               
                print("未命中，进行翻译："+str(data))
            w.writerow(data)
