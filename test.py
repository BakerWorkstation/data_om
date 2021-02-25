'''
@Author: your name
@Date: 2020-01-16 15:16:37
@LastEditTime : 2020-01-16 15:18:54
@LastEditors  : Please set LastEditors
@Description: In User Settings Edit
@FilePath: /opt/data_service/test.py
'''

from struct import unpack
from socket import AF_INET,inet_pton,inet_aton

def check_private_addr(ip):
        """
        判断ip是否是内网地址，若返回2的话则为内网ip，若返回1则是外部网络ip
        """
        f = unpack('!I', inet_pton(AF_INET, ip))[0]
        '''
        下面网段可选
        '''
        private = (

            [2130706432, 4278190080],  # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
            [3232235520, 4294901760],  # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
            [2886729728, 4293918720],  # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
            [167772160, 4278190080],   # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
        )  
        for net in private:
            if (f & net[1]) == net[0]:
                return 2
        return 1


# 判断是否是公司的外部资产
def External_Asset(str_ip):   
    int_ip = unpack('!I', inet_aton(str_ip))[0]
    # 1.189.209.202 - 1.189.209.254 公司外部资产的ip范围
    if 29217226 <= int_ip and int_ip <= 29217278:
        return 2
    else:
        return 1


ip_addr = "222.171.72.161"
print(check_private_addr(ip_addr))
print(External_Asset(ip_addr))