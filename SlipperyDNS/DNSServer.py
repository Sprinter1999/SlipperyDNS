#TODO:导入本程序外部的包
import socket
from ParseCommand import ParseCommand
import datetime
import os
import random

#TODO:展示DNS协议的报文格式：
'''
                            Header
        0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                      ID                       |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |QR|  opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    QDCOUNT                    |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    ANCOUNT                    |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    NSCOUNT                    |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    ARCOUNT                    |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                        Question 查询字段
		0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                     ...                       |
	  |                    QNAME                      |
	  |                     ...                       |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    QTYPE                      |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    QCLASS                     |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
               Resource Answer/Authority/Additional
	   0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |					   ... 						  |
	  |                    NAME                       |
	  |                    ...                        |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    TYPE                       |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    CLASS                      |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    TTL                        |
      |                                               |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    RDLENGTH                   |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    ...                        |
	  |                    RDATA                      |
	  |                    ...                        | 
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


解析均按顺序书写：
**********************Header字段*************************************
1.会话标识（2字节）：
是DNS报文的ID标识，对于请求报文和其对应的应答报文，
这个字段是相同的，通过它可以区分DNS应答报文是哪个请求的响应
2.标志（2字节）：
QR（1bit）	    查询/响应标志，0为查询，1为响应
Opcode（4bit）	0表示标准查询，1表示反向查询，2表示服务器状态请求
AA（1bit）	    表示授权回答
TC（1bit）	    表示可截断的
RD（1bit）	    表示期望递归
RA（1bit）	    表示可用递归
rcode（4bit）	表示返回码，
                0表示没有差错，3表示名字差错，2表示服务器错误
3.数量字段（总共8字节）：
Questions、Answer RRs、Authority RRs、Additional RRs
各自表示后面的四个区域的数目。
Questions表示查询问题区域节的数量，
Answers表示回答区域的数量，
Authoritative namesversers表示授权区域的数量，
Additional recoreds表示附加区域的数量

**********************正文字段************************************
1.Queries字段，长度不固定：
1.1 查询名:
长度不固定，且不使用填充字节，一般该字段表示的就是需要查询的域名
（如果是反向查询，则为IP，反向查询即由IP地址反查域名）
1.2 查询类型:
占两个字节，理论上256个类型，但是一般只用12种类型
1.3 查询类：
通常为1，表明是Internet数据

2.资源记录(RR)字段，长度不固定：
（该区域有三个，但格式都是一样的。这三个区域分别是：回答区域，授权区域和附加区域）
2.1. 域名（2字节或不定长）：
它的格式和Queries区域的查询名字字段是一样的。有一点不同就是，
当报文中域名重复出现的时候，该字段使用2个字节的偏移指针来表示。
比如，在资源记录中，域名通常是查询问题部分的域名的重复，因此用2字节的指针来表示，
具体格式是最前面的两个高位是 11，用于识别指针。其余的14位从DNS报文的开始处计数（从0开始），
指出该报文中的相应字节数。一个典型的例子，C00C(1100000000001100，12正好是头部的长度，
其正好指向Queries区域的查询名字字段)。
2.2 查询类型：
表明资源纪录的类型，见1.2节的查询类型表格所示 
2.3 查询类：
对于Internet信息，总是IN
2.4 生存时间（TTL）：
以秒为单位，表示的是资源记录的生命周期，一般用于当地址解析程序取出资源记录后
决定保存及使用缓存数据的时间，它同时也可以表明该资源记录的稳定程度，
极为稳定的信息会被分配一个很大的值（比如86400，这是一天的秒数）。

2.5. 资源数据：
该字段是一个可变长字段，表示按照查询段的要求返回的相关资源记录的数据。
可以是Address（表明查询报文想要的回应是一个IP地址）或者CNAME
（表明查询报文想要的回应是一个规范主机名）等。
'''

#TODO:一下是全局变量
shield_ip="0.0.0.0"
default_TTL=176800                  #稳定资源记录生存时间为2天，暂时不懂有什么用
buf_size=512                        #传输缓冲区大小，每次接收or发送都以它为单位
local_table="dnsrelay.txt"          #默认本地对照表
trans_form={}                       #ID转换表
domain_ip={}                        #创建字典domain_ip,用于存储映射表
port=53                             #53号port专用于DNS服务器，用于域名解析
serverIp = '10.3.9.5'              #学校局域网固有的dns server的ip，通过ipconfig查看
dns_ip_port=(serverIp,port)         #外部dns服务器的端口
local_ip_port=("",port)             #本地ip端口号
debug_level = 0                     #默认调试等级为0
Order = 1                           #调试等级debug_level为2时序列号
queryDict={}
id_map={}

#TODO:定义DNS报文包
class DNSPackage:
    #查询报解析：
    def QueryAnalysis(self, arr):
        # ID
        self.ID = (arr[0] << 8) + arr[1]
        # FLAGS
        self.QR = arr[2] >> 7
        self.Opcode = (arr[2] % 128) >> 3
        self.AA = (arr[2] % 8) >> 2
        self.TC = (arr[2] % 4) >> 1
        self.RD = arr[2] % 2
        self.RA = arr[3] >> 7
        self.Z = (arr[3] % 128) >> 4
        self.RCODE = arr[3] % 16
        # 资源记录数量
        self.QDCOUNT = (arr[4] << 8) + arr[5]
        self.ANCOUNT = (arr[6] << 8) + arr[7]
        self.NSCOUNT = (arr[8] << 8) + arr[9]
        self.ARCOUNT = (arr[10] << 8) + arr[11]
        # 查询部分内容
        name_length = 0
        self.name = ""
        flag = 12
        while arr[flag] != 0x0:
            for i in range(flag + 1, flag + arr[flag] + 1):
                self.name = self.name + chr(arr[i])
            name_length = name_length + arr[flag] + 1
            flag = flag + arr[flag] + 1
            if arr[flag] != 0x0:
                self.name = self.name + "."
        name_length = name_length + 1
        self.name.casefold()
        flag = flag + 1
        self.qtype = (arr[flag] << 8) + arr[flag + 1]
        self.qclass = (arr[flag + 2] << 8) + arr[flag + 3]
        #返回值为查询域名长度，用于确定响应包字节数组长度
        return name_length

    def output(self):
        print("ID " + str(hex(self.ID)) + ",", end=' ')
        print("QR " + str(self.QR) + ",", end=' ')
        print("Opcode " + str(self.Opcode) + ",", end=' ')
        print("AA " + str(self.AA) + ",", end=' ')
        print("TC " + str(self.TC) + ",", end=' ')
        print("RD " + str(self.RD) + ",", end=' ')
        print("RA " + str(self.RA) + ",", end=' ')
        print("Z " + str(self.Z) + ",", end=' ')
        print("RCODE " + str(self.RCODE) + ",", end=' ')
        print("QDCOUNT " + str(self.QDCOUNT) + ",", end=' ')
        print("ANCOUNT " + str(self.ANCOUNT) + ",", end=' ')
        print("NSCOUNT " + str(self.NSCOUNT) + ",", end=' ')
        print("ARCOUNT " + str(self.ARCOUNT))

class IDsource:
    def getSrc(self,IP,Port,idsrc):
        self.addr = (IP,Port)
        self.IDsrc = idsrc
        self.rawID=idsrc

class IDrecord:
    def set_record(self, raw_id, new_id, addr):
        self.raw_id = raw_id
        self.unique_id = new_id
        self.respond_address = addr
        self.create_time = datetime.datetime.now()

class DomainResource:
    def init(self):
        self.ipv4_table = []
        self.isShielded = False
        self.TTL = default_TTL
        self.create_time = datetime.datetime.now()
    def append_ipv4(self, ipv4_address):
        self.ipv4_table.append(ipv4_address)
    def set_shield(self):
        self.isShielded = True
    def set_TTL(self, time_to_live):
        self.TTL = time_to_live
    def is_in_ceck(self, ip):
        if ip in self.ipv4_table:
            return True
        else:
            return False
    def print(self):
        print(self.ipv4_table)

#TODO:从dnsrelay.txt种读取本地 域名-ip 映射表
def getTable(fileName, domain_ip):
    f = open(fileName)
    # 按照文法进行解析每一行的映射，将映射表插入
    for each_line in f:
        new_resource = DomainResource()
        new_resource.init()
        flag = each_line.find(" ")
        ip = each_line[:flag]
        domain = each_line[(flag + 1):(len(each_line) - 1)].casefold()
        if ip == shield_ip:
            new_resource.isShielded = True
        else:
            new_resource.append_ipv4(ip)
        domain_ip[domain] = new_resource

#TODO:整体Main函数设计
def main():
    print("░█▀▀░█░░░█░░█▀█░█▀█░█▀▀░█▀█░█░█░█▀▄░█▀█░█▀▀░")
    print("░▀▀█░█░░░█░░█▀▀░█▀▀░█▀▀░█▀▀░░█░░█░█░█░█░▀▀█░")
    print("░▀▀▀░▀▀▀░▀░░▀░░░▀░░░▀▀▀░▀░▀░░▀░░▀▀░░▀░▀░▀▀▀░")
    print("DNS relay server, generating...")
    # 选择服务器之间的通信，采用无连接的UDP传输方式，ipv4报文
    server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    # 绑定到当前地址的53号dns端口，套接字绑定
    server.bind(local_ip_port)
    print("Binding UDP port " + str(local_ip_port) + " ...OK!")
    # TODO:解析命令行指令，并保存到主函数的变量中去
    debug_level,serverIp,local_table=ParseCommand()

    dns_ip_port=(serverIp,port)


    # dns_server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    # dns_server.bind(dns_ip_port)

    # 读取本地dnsrelay.txt
    try:
        getTable(local_table, domain_ip)
        print('Trying to load table ' + local_table + '... OK')
        if debug_level == 2:
            order = 1
            for key in domain_ip:
                #print("          " + str(order) + ":" + domain_ip[key] + "\t" + key)
                order = order + 1
        print(str(domain_ip.__len__()) + " names, occupy " + str(os.path.getsize(local_table)) + " bytes memory")
    except OSError:
        print('Trying to load table "' + local_table + '" ... failed')
        print("0 names, occupy 1 bytes memory")

    startTime=datetime.datetime.now()

    task_number = 0
    #不断收发报文
    while True:
        # Receive DNS package and parse it
        # begin_time=datetime.datetime.now()
        # print("当前时间戳: ",begin_time,' .')
        try:
            data,addr=server.recvfrom(buf_size)
            getMsg=bytearray(data) #使用字节数组，就不用encode()，decode()了
            RecvDp=DNSPackage()
            name_length=RecvDp.QueryAnalysis(getMsg)
            if debug_level>=1:
                task_number += 1
                print("********************************Order[" + str(task_number) + "]**************************************")
        except:
            continue

        #根据接收到的包，进行分情况处理：
        #收到查询报文包：
        if RecvDp.QR==0:
            # and RecvDp.qtype==1
            # 若在本地查询表能找到这个域名
            if domain_ip.get(RecvDp.name)!=None:
                local_resource = domain_ip.get(RecvDp.name)
                now_time = datetime.datetime.now()
                delta_time = (now_time - local_resource.create_time).total_seconds()
                new_live_time = local_resource.TTL - int(delta_time)
                if new_live_time <= 0:
                    del domain_ip[RecvDp.name]
                    print("delete: " + RecvDp.name)

            if (RecvDp.name in domain_ip) and (RecvDp.qtype == 1):
                # 若这个ip并非0.0.0.0,我们正常构造
                if domain_ip.get(RecvDp.name).isShielded == False:  
                    answer_number = len(local_resource.ipv4_table)
                    ip_list = local_resource.ipv4_table
                    time_to_live = new_live_time

                    #前半部分
                    respond = bytearray(16 + name_length + 16 * answer_number)
                    respond[0] = RecvDp.ID >> 8
                    respond[1] = RecvDp.ID % 256
                    respond[2] = 0x81
                    respond[3] = 0x80
                    respond[4] = 0x0
                    respond[5] = 0x1
                    respond[6] = answer_number >> 8    #answer_number
                    respond[7] = answer_number % 256
                    respond[8] = 0x0
                    respond[9] = 0x0
                    respond[10] = 0x0
                    respond[11] = 0x0
                    for i in range(12, 16 + name_length):
                        respond[i] = getMsg[i]
                    flag = name_length + 16

                    #后部answer部分16个字节一组
                    for each_ip in ip_list:
                        respond[flag] = 0xc0
                        respond[flag + 1] = 0x0c
                        respond[flag + 2] = 0x0
                        respond[flag + 3] = 0x1     #ipv4
                        respond[flag + 4] = 0x0
                        respond[flag + 5] = 0x1
                        respond[flag + 6] = time_to_live >> 24
                        respond[flag + 7] = (time_to_live >> 16) % 256
                        respond[flag + 8] = (time_to_live >> 8) % 256
                        respond[flag + 9] = time_to_live % 256
                        respond[flag + 10] = 0x0
                        respond[flag + 11] = 0x4

                        IPtuple = each_ip.split(sep='.')
                        respond[flag + 12] = int(IPtuple[0])
                        respond[flag + 13] = int(IPtuple[1])
                        respond[flag + 14] = int(IPtuple[2])
                        respond[flag + 15] = int(IPtuple[3])
                        flag += 16
                    server.sendto(bytes(respond), addr)
                # 若IP地址为"0.0.0.0"，则按DNS报文规则创建字符数组，返回差错信息并发回客户端
                else:
                    respond = bytearray(16 + name_length)
                    respond[0] = RecvDp.ID >> 8
                    respond[1] = RecvDp.ID % 256
                    respond[2] = 0x81
                    respond[3] = 0x83
                    respond[4] = 0x0
                    respond[5] = 0x1
                    respond[6] = 0x0
                    respond[7] = 0x0
                    respond[8] = 0x0
                    respond[9] = 0x0
                    respond[10] = 0x0
                    respond[11] = 0x0
                    for i in range(12, 16 + name_length):
                        respond[i] = getMsg[i]
                    server.sendto(bytes(respond), addr)
                query_time=datetime.datetime.now()
                if debug_level >= 1:
                    print("收到一次本地查询报文, 当前时间戳: ",query_time)
                if debug_level==1:
                    print("本地不转换ID,当前消息ID:",RecvDp.ID,", 查询的域名为: ",RecvDp.name)
                elif debug_level==2:
                    print("本地不转换ID, 查询的域名为: ",RecvDp.name,", 详细冗长调试信息如下:")
                    RecvDp.output()

            # 若本地查询失败，则转向外部dns服务器获取ip
            else:
                # endTime=datetime.datetime.now()
                # timeGap=(endTime-startTime).seconds
                # idsrc=IDsource()
                # idsrc.getSrc(addr[0],addr[1],RecvDp.ID)
                # # queryDict[idsrc.rawID]=idsrc

                # nowTime=datetime.datetime.now()
                # print((nowTime-startTime).total_seconds(), end=":  ")
                # print("Send a Query to DNS.")

                if RecvDp.ID in id_map:
                    new_id = random.randint(0,2**16 - 1)
                    while new_id in id_map:
                        new_id = random.randint(0,2**16 - 1)
                else:
                    new_id = RecvDp.ID
                id_record = IDrecord()
                id_record.set_record(RecvDp.ID, new_id, addr)
                id_map[new_id] = id_record
                getMsg[0] = new_id >> 8
                getMsg[1] = new_id % 256

                server.sendto(bytes(getMsg),dns_ip_port)
                if debug_level>=1:
                    query_time=datetime.datetime.now()
                    print("收到一次需要访问远程DNS的查询报文, 当前时间戳: ",query_time)
                if debug_level==1:
                    print("进行ID转换,转换信息如下:",hex(RecvDp.ID)," -> ",hex(new_id),", 查询的域名为: ",RecvDp.name)
                elif debug_level==2:
                    print("进行ID转换，转换ID情况为:",hex(RecvDp.ID)," -> ",hex(new_id),"查询的域名为: ",RecvDp.name,"\n, 详细冗长调试信息如下:")
                    RecvDp.output()
            
        # 若收到响应包
        if RecvDp.QR==1:
            
            if(RecvDp.ID in id_map):
            #合法响应包

                if (RecvDp.ARCOUNT == 0) and (RecvDp.NSCOUNT == 0) and (RecvDp.qtype == 1) and (RecvDp.ANCOUNT > 0):
                #维护本地资源表
                    if not (RecvDp.name in domain_ip):
                        new_resource = DomainResource()
                        new_resource.init()    
                    else:
                        new_resource = domain_ip[RecvDp.name]
                    time_to_live = new_resource.TTL
                    answer_number = RecvDp.ANCOUNT
                    if answer_number > 0:
                        flag = 0
                        while True:
                            if (getMsg[flag-14] << 8) + getMsg[flag-13] == 1: #ipv4
                                time_to_live = (getMsg[flag-10] << 24) + (getMsg[flag-9] << 16) + (getMsg[flag-8] << 8) + getMsg[flag-7]
                                ip_write=""
                                ip_write=str(getMsg[flag-4]) + "." + str(getMsg[flag-3]) + "." + str(getMsg[flag-2]) + "." + str(getMsg[flag-1])
                                if not new_resource.is_in_ceck(ip_write):
                                    new_resource.append_ipv4(ip_write)
                                flag -= 16
                            else:
                                break
                        domain_ip[RecvDp.name] = new_resource
                    new_resource.set_TTL(time_to_live)
                
                
                # correspondSRC=queryDict.get(RecvDp.ID)
                unique_id = (getMsg[0] << 8) + getMsg[1]
                raw_id = id_map[unique_id].raw_id 
                getMsg[0] = raw_id >> 8
                getMsg[1] = raw_id % 256
                respond_address = id_map[unique_id].respond_address
                del id_map[unique_id]
                server.sendto(bytes(getMsg), respond_address)
                if debug_level>=1:
                    response_time=datetime.datetime.now()
                    print("收到一次来自DNS服务器的响应报文，当前时间戳: ",response_time)
                if debug_level==1:
                    print("经过消息ID转换，转换如下：",hex(unique_id)," -> ",hex(raw_id)," ,查询的域名如下: ",RecvDp.name)
                elif debug_level==2:
                    print("经过消息ID转换，转换信息如下",hex(unique_id)," -> ",hex(raw_id)," ,查询的域名如下: ",RecvDp.name, "\n详细冗长的调试信息如下: ")
                    RecvDp.output()

            else:
                pass
        
        #处理超时询问
        delete_list = []
        now_time = datetime.datetime.now()
        for each_IDrecord in id_map:
            delta_time = (now_time - id_map[each_IDrecord].create_time).total_seconds()
            # print(delta_time)
            if delta_time >= 1.0:
                delete_list.append(each_IDrecord)
        for each in delete_list:
            del id_map[each]
            if debug_level >= 1:
                print("发生超时！")
        del delete_list


        if debug_level>=1:
            print("********************************************************************************")
            print()

        
    #关闭服务，释放socket
    server.close()


#TODO：单元测试
if(__name__=="__main__"):
    main()