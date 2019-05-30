import os
#TODO:输入指令，分析，确定调试等级
def ParseCommand():
    '''
    之所以要解析命令行，是因为 ：
    调试级别可选
    采用的外部dns-server可选or默认学校的
    已有的dnsrelay本地对照表可选or默认

    以及 对错误指令的反馈
    '''
    flag = 0
    dbLevel = 0
    serverIp = '10.3.9.5'
    #TODO：通过ipconfig/all指令可知，学校的dns服务器的ip地址为上面的dns server ip（其实有两个，选一个）
    dbFile = 'dnsrelay.txt'
    #TODO：我们默认选择dnsrelay.txt作为默认的dns本地对照表
    while flag != 1:
        print('***************************************************************************************')
        command = input('Usage: dnsrelay [-d | -dd] [<dns-server>] [<db-file>]\n'
                        '(Default DNS and Local DNS Table:10.3.9.5 dnsrelay.txt)\n')
        command = command.split()  # 按空格分开，检测输入指令,并且按照模块进行解读
        if len(command) == 1:
            if command[0] == 'dnsrelay':
                dbLevel = 0  # 0级调试
                flag = 1  # 开启功能
                print('无调试信息输出')
            else:
                print('Bad Command!')  # 输入错误
        elif len(command) == 2:
            if command[0] == 'dnsrelay' and command[1] == '-d':  # 1级调试，开启功能
                dbLevel = 1
                flag = 1
                print('调试信息级别1（仅输出时间坐标，序号，客户端IP地址，查询的域名)')
            elif command[0] == 'dnsrelay' and command[1] == '-dd':  # 2级调试，开启功能
                dbLevel = 2
                flag = 1
                print('调试信息级别2，输出冗长的调试信息')
            else:
                print('Bad Command!')

        elif len(command) == 3:
            if command[0] == 'dnsrelay' and command[1] == '-d' and len(command[2].split('.')) == 4:
                dbLevel = 1
                #TODO:可以选择相应的DNS server，但是学校的dns server是我们默认选用的
                serverIp = command[2]
                flag = 1
                print('调试信息级别1（仅输出时间坐标，序号，客户端IP地址，查询的域名)')
            elif command[0] == 'dnsrelay' and command[1] == '-dd' and len(command[2].split('.')) == 4:
                dbLevel = 2
                serverIp = command[2]  # 若输入了三个参数，那么第三个参数作为我们的指定的，名字服务器，否则使用默认的名字服务器
                flag = 1
                print('调试信息级别2，输出冗长的调试信息')
            else:
                print('Bad Command!')
        elif len(command) == 4:
            if command[0] == 'dnsrelay' and command[1] == '-d' and len(command[2].split('.')) == 4:
                if os.path.exists(command[3]):  # 判断
                    dbLevel = 1
                    serverIp = command[2]
                    #TODO：同理，我们给出的dns对照表也是可以修改的，只是默认我们用的是dnsrelay.txt
                    dbFile = command[3]  # 分析同上，第四个参数为我们从哪里取出用于本地查询的文档
                    flag = 1
                    print('调试信息级别1（仅输出时间坐标，序号，客户端IP地址，查询的域名)')
                else:
                    print("Your file_path " + command[3] + "Not found!")
            elif command[0] == 'dnsrelay' and command[1] == '-dd' and len(command[2].split('.')) == 4:
                if os.path.exists(command[3]):
                    dbLevel = 2
                    serverIp = command[2]
                    dbFile = command[3]
                    flag = 1
                    print('调试信息级别2，输出冗长的调试信息')
                else:
                    print("Your file_path " + command[3] + "Not found!")
            else:
                print('Bad Command!')
        else:
            print('Bad Command!')

    print('=======================================================================================')
    return dbLevel, serverIp, dbFile  # 这是Python的多返回值特性,封装成为一个元组tuple
