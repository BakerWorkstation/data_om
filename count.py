'''
@Author: sdc
@Date: 2020-01-08 09:25:58
@LastEditTime: 2020-04-01 09:13:03
@LastEditors: Please set LastEditors
@Description: 数据运营脚本
@FilePath: /opt/data_service/count.py
'''


#!/usr/bin/env python3.6
# -*- coding:utf-8 -*-
# __author__: sdc

import re
import os
import sys
import time
import json
import uuid
import redis
import base64
import asyncio
import datetime
import psycopg2
import requests
import threading
import psycopg2.extras
import confluent_kafka
from struct import unpack
from socket import AF_INET,inet_pton,inet_aton
from multiprocessing import Process
from DBUtils.PooledDB import PooledDB
from confluent_kafka import Consumer, KafkaError, TopicPartition

main_thread_lock = threading.Lock()


'''
@description:    将字符型IP地址转换成整形数值
@param {type}    ip(string)
@return:         value(int)
'''
def convert_ip_to_number(ip_str):
    ret = 0
    ip_str=ip_str.strip()
    parts = ip_str.split('.')
    if len(parts) == 4:
        ret = int(parts[0]) * 256 * 256 * 256 + int(parts[1]) * 256 * 256 + int(parts[2]) * 256  + int(parts[3])
    return ret


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
                return True
        return False


def jugg_ip(str_ip):
    int_ip = unpack('!I', inet_aton(str_ip))[0]
    # 1.189.209.202 - 1.189.209.254 公司外部资产的ip范围
    if 29217226 <= int_ip and int_ip <= 29217278:
        return True
    else:
        return False


'''
@description:    解析ptd原始数据
@param {type}    message(list),  write_offset(int),  redis_conn(object)
@return:         write_offset(int)
'''
def ptd_parse(message, write_offset, redis_conn):
    today = datetime.datetime.now().strftime("%Y%m%d")
    logtime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tmpdict = {}
    assetlog = {}
    for eachmsg in message:
        if eachmsg.error():
            print('error: %s' % eachmsg.error())
            write_offset += 1
            continue
        #print('%s -> %s' % (eachmsg.partition(), eachmsg.offset()))
        result = json.loads(eachmsg.value())
        total = result.get("count")
        data = result.get("data")
        dev = ""
        ipmac = {}
        for eachlog in data:
            try:
                dev = eachlog.get("dev")
                if not dev in ["BCNHYW2", "CJXJWW2", "2102311QGK10HA000177", "BC3CYW2", "BBMHYW2", "1NKVRT2", "C0GDWW2"]:
                    break
                if not dev in assetlog.keys():
                    assetlog[dev] = {}
                if not dev in tmpdict.keys():
                    tmpdict[dev] = {"total": 0, "black": 0, "gray": 0, "asset": {}}
                # 判黑
                if eachlog.get("is_malicious") or eachlog.get("alert"):
                    tmpdict[dev]["black"] += 1
                # 置灰
                else:
                    tmpdict[dev]["gray"] += 1
                # 找出资产ip对应的mac
                sip = eachlog.get("src").get("ip")
                smac = eachlog.get("src").get("mac")
                dip = eachlog.get("dst").get("ip")
                dmac = eachlog.get("dst").get("mac")
                if check_private_addr(sip) or jugg_ip(sip):
                    ipmac[sip] = smac
                    if not sip in assetlog[dev].keys():
                        assetlog[dev][sip] = 0 
                    assetlog[dev][sip] += 1
                if check_private_addr(dip) or jugg_ip(dip):
                    ipmac[dip] = dmac
                    if not dip in assetlog[dev].keys():
                        assetlog[dev][dip] = 0
                    assetlog[dev][dip] += 1
                #print(len(ipmac))
                #print(len(assetlog[dev]))
            except Exception as e:
                #print(type(eachlog))
                #print('error, message : %s' % str(e))
                continue
        if not dev:
            continue
        #print("dev: %s " % dev)
        redis_conn.set("ptd_%s" % dev, logtime)
        tmpdict[dev]["total"] += total
        tmpdict[dev]["asset"]= dict( tmpdict[dev]["asset"], **ipmac )

        write_offset += 1

    # 往redis同步计数
    with main_thread_lock:
        count = redis_conn.get("ptd_%s" % today)
        if not count:
            count = tmpdict
        else:
            count = json.loads(count)
            for eachdevice, number in tmpdict.items():
                if not eachdevice in count.keys():
                    count[eachdevice] = {"total": 0, "black": 0, "gray": 0, "asset": {}}
                total = number["total"]
                black = number["black"]
                gray = number["gray"]
                asset = number["asset"]
                count[eachdevice]["total"] += total
                count[eachdevice]["black"] += black
                count[eachdevice]["gray"] += gray
                for ip, mac in asset.items():
                    if not ip in count[eachdevice]["asset"].keys():
                        count[eachdevice]["asset"][ip] = mac
                count[eachdevice]["asset_count"] = len(count[eachdevice]["asset"])
        redis_conn.set("ptd_%s" % today, json.dumps(count))
        
        logcount = redis_conn.get("ptd_assetlog_%s" % today)
        if not logcount:
            logcount = assetlog
        else:
            logcount = json.loads(logcount)
            for eachdevice, number in assetlog.items():
                if not eachdevice in logcount.keys():
                    logcount[eachdevice] = {}
                for eachip, count in number.items():
                    if not eachip in logcount[eachdevice].keys():
                        logcount[eachdevice][eachip] = 0
                    logcount[eachdevice][eachip] += count
        redis_conn.set("ptd_assetlog_%s" % today, json.dumps(logcount))

        ptd_asset_count = {}
        for device, number in assetlog.items():
            iplist = []
            for ip in number.keys():
                iplist.append(ip)
            ptd_asset_count[device] = iplist

        count = redis_conn.get("ptd_assets")
        if not count:
            count = {}
            for device, iplist in ptd_asset_count.items():
                count[device] = {}
                for ip in iplist:
                    count[device][ip] =  {"create_time": logtime, "update_time": logtime}
        else:
            count = json.loads(count)
            for device, iplist in ptd_asset_count.items():
                if not device in count.keys():
                    count[device] = {}
                for eachip in iplist:
                    if not eachip in count[device].keys():
                        count[device][eachip] = {"create_time": logtime, "update_time": logtime}
                    else:
                        count[device][eachip]["update_time"] = logtime
            #print(count)
        redis_conn.set("ptd_assets", json.dumps(count))

    return write_offset


'''
@description:    解析iep原始数据
@param {type}    message(list),  write_offset(int),  redis_conn(object)
@return:         write_offset(int)
'''
def iep_parse(message, write_offset, redis_conn):
    today = datetime.datetime.now().strftime("%Y%m%d")
    logtime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tmpdict = {}
    ipmac = {}
    for eachmsg in message:
        if eachmsg.error():
            print('error: %s' % eachmsg.error())
            write_offset += 1
            continue
        try:
            eachlog = json.loads(eachmsg.value())
            ip = eachlog.get("client").get("ip")
            server_ip = eachlog.get("client").get("server_ip")
            if not server_ip in ["10.255.49.17", "10.255.52.122"]:
                continue
            if not server_ip in tmpdict.keys():
                tmpdict[server_ip] = {"total": 0, "black": 0, "gray": 0, "asset": {}}
            # 判黑
            if eachlog.get("data").get("i").get("1")[0].get("8"):
                tmpdict[server_ip]["black"] += 1
            # 置灰
            else:
                tmpdict[server_ip]["gray"] += 1
            tmpdict[server_ip]["total"] += 1
            # 找出资产ip对应的mac
            for eachinfo in eachlog.get("data").get("d").get("1"):
                asset_ip = eachinfo["1"]
                asset_mac = eachinfo["2"]
                if ip == asset_ip:
                    ipmac[ip] = asset_mac
                else:
                    ipmac[ip] = ""
        except Exception as e:
            print('error,  message: %s' % str(e))
            continue
        redis_conn.set("iep_%s" % server_ip, logtime)
        write_offset += 1
        #tmpdict[server_ip]["asset"] = ipmac
        tmpdict[server_ip]["asset"]= dict( tmpdict[server_ip]["asset"], **ipmac )
    # 往redis同步计数
    with main_thread_lock:
        count = redis_conn.get("iep_%s" % today)
        if not count:
            count = tmpdict
        else:
            count = json.loads(count)
            for eachdevice, number in tmpdict.items():
                if not eachdevice in count.keys():
                    count[eachdevice] = {"total": 0, "black": 0, "gray": 0, "asset": {}}
                total = number["total"]
                black = number["black"]
                gray = number["gray"]
                asset = number["asset"]
                count[eachdevice]["total"] += total
                count[eachdevice]["black"] += black
                count[eachdevice]["gray"] += gray
                for ip, mac in asset.items():
                    if not ip in count[eachdevice]["asset"].keys():
                        count[eachdevice]["asset"][ip] = mac
                count[eachdevice]["asset_count"] = len(count[eachdevice]["asset"])
        redis_conn.set("iep_%s" % today, json.dumps(count))

    return write_offset


'''
@description:    解析防火墙原始数据
@param {type}    message(list),  write_offset(int),  redis_conn(object)
@return:         write_offset(int)
'''
def firewall_parse(message, write_offset, redis_conn):
    today = datetime.datetime.now().strftime("%Y%m%d")
    logtime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    zhenguan = {}
    for eachmsg in message:
        if eachmsg.error():
            print('error: %s' % eachmsg.error())
            write_offset += 1
            continue
        eachlog = json.loads(eachmsg.value())
        server_ip = eachlog.get("host")
        eachlog = eachlog.get("data")

            # zhenguan[today][server_ip] = {
            #                               "total": 0, "APP_POLICY": 0, "NAT": 0, "IPS": 0, "AV": 0, "ATTACK": 0, 
            #                               "FILTER": 0, "IF_INFO": 0, "HA": 0, "VRRP": 0, "OSPF": 0, "HM": 0, 
            #                               "SYSTEM": 0, "RIP": 0, "IPSEC": 0, "CONFIG": 0, "APP_IM": 0, "APP_SE":0,
            #                               "APP_SN": 0, "APP_EMAIL": 0, "APP_FILE": 0, "APP_SHOPPING": 0, "APP_OTHERS": 0,
            #                               "WEB_ACCESS": 0, "FLOW": 0
            # }
        try:
            # 判断镇关type
            if re.match(r'(?P<level><\d+>)(?P<date>\w+\ +\d+ \d{2}:\d{2}:\d{2}) (?P<host>[a-zA-Z0-9_\-]+) (?P<type>APP_POLICY|ADSL):', eachlog):
                firetype = eachlog.split(" ")[4].split(":")[0]
            else:
                firetype = None
        except Exception as e:
            print("error -> %s" % str(e))
            firetype = None
        # 命中类型
        if firetype:
            if not server_ip in zhenguan.keys():
                zhenguan[server_ip] = {"total": 0, "APP_POLICY": 0, "ADSL": 0}
            zhenguan[server_ip][firetype] += 1
            zhenguan[server_ip]["total"] += 1
        # 未命中
        else:
            pass
        redis_conn.set("firewall_%s" % server_ip, logtime)
        write_offset += 1

    # 往redis同步计数
    with main_thread_lock:
        count = redis_conn.get("zhenguan_%s" % today)
        if not count:
            count = zhenguan
        else:
            count = json.loads(count)
            for eachdevice, number in zhenguan.items():
                if not eachdevice in count.keys():
                    count[eachdevice] = {"total": 0, "APP_POLICY": 0, "ADSL": 0}
                total = number["total"]
                policy = number["APP_POLICY"]
                adsl = number["ADSL"]
                count[eachdevice]["total"] += total
                count[eachdevice]["APP_POLICY"] += policy
                count[eachdevice]["ADSL"] += adsl
        redis_conn.set("zhenguan_%s" % today, json.dumps(count))

    return write_offset


'''
@description:    解析标准化黑数据
@param {type}    message(list),  write_offset(int),  redis_conn(object)
@return:         write_offset(int)
'''
def stand_black(message, write_offset, redis_conn):
    today = datetime.datetime.now().strftime("%Y%m%d")
    tmpdict = {}
    device = ""
    for eachmsg in message:
        if eachmsg.error():
            print('error: %s' % eachmsg.error())
            write_offset += 1
            continue
        eachlog = json.loads(eachmsg.value())
        detect = eachlog.get("threat_info").get("source_endpoint").get("detect")
        detect_type = detect.get("detect_pro")
        if detect_type == "PTD":
            device = detect.get("detect_pro_id")
            if not device in ["BCNHYW2", "CJXJWW2", "2102311QGK10HA000177", "BC3CYW2", "BBMHYW2", "1NKVRT2", "C0GDWW2"]:
                continue
        else:
            ip = eachlog.get("threat_info").get("source_endpoint").get("ip_info").get("ip")
            result = redis_conn.get("iep_%s" % today)
            if result:
                result = json.loads(result)
            else:
                result = {}
            for server_ip, asset in result.items():
                if ip in str(asset) and server_ip in ["10.255.49.17", "10.255.52.122"]:
                    device = server_ip
                    break
        if device:
            if not device in tmpdict.keys():
                tmpdict[device] = 0
            tmpdict[device] += 1
        write_offset += 1
    
    with main_thread_lock:
        count = redis_conn.get("stand_black_%s" % today)
        if not count:
            count = tmpdict
        else:
            count = json.loads(count)
            for eachdevice, number in tmpdict.items():
                if not eachdevice in count.keys():
                    count[eachdevice] = 0
                count[eachdevice] += number
        redis_conn.set("stand_black_%s" % today, json.dumps(count))

    return write_offset


'''
@description:    解析标准化白数据
@param {type}    message(list),  write_offset(int),  redis_conn(object)
@return:         write_offset(int)
'''
def stand_white(message, write_offset, redis_conn):
    today = datetime.datetime.now().strftime("%Y%m%d")
    tmpdict = {}
    device = ""
    for eachmsg in message:
        if eachmsg.error():
            print('error: %s' % eachmsg.error())
            write_offset += 1
            continue
        eachlog = json.loads(eachmsg.value())
        detect = eachlog.get("threat_info").get("source_endpoint").get("detect")
        detect_type = detect.get("detect_pro")
        if detect_type == "PTD":
            device = detect.get("detect_pro_id")
            if not device in ["BCNHYW2", "CJXJWW2", "2102311QGK10HA000177", "BC3CYW2", "BBMHYW2", "1NKVRT2", "C0GDWW2"]:
                continue
        else:
            ip = eachlog.get("threat_info").get("source_endpoint").get("ip_info").get("ip")
            result = redis_conn.get("iep_%s" % today)
            if result:
                result = json.loads(result)
            else:
                result = {}
            for server_ip, asset in result.items():
                if ip in str(asset) and server_ip in ["10.255.49.17", "10.255.52.122"]:
                    device = server_ip
                    break
        if device:
            if not device in tmpdict.keys():
                tmpdict[device] = 0
            tmpdict[device] += 1
        write_offset += 1
    
    with main_thread_lock:
        count = redis_conn.get("stand_white_%s" % today)
        if not count:
            count = tmpdict
        else:
            count = json.loads(count)
            for eachdevice, number in tmpdict.items():
                if not eachdevice in count.keys():
                    count[eachdevice] = 0
                count[eachdevice] += number
        redis_conn.set("stand_white_%s" % today, json.dumps(count))

    return write_offset



'''
@description:    kafka消费者处理数据函数
@param {type}    topic(string),  partition(int),  functions(object),  redis_conn(object),  pg_conn(object),  config(dict),  logger(object)
@return:
'''
def consumeData(topic, partition, functions, redis_conn, config):
    offsetkey = "%s_%s" % (topic, partition)
    redis_offset = redis_conn.get(offsetkey)
    broker_list = "%s:%s" % (config["kafka_ip"], config["kafka_port"])
    tp_c = TopicPartition(topic, partition, 0)
    consume = Consumer({
                        'bootstrap.servers': broker_list,
                        'group.id': config["kafka_group_id"],
                        'enable.auto.commit': False,
                        'max.poll.interval.ms': config["kafka_max_poll"],
                        'default.topic.config': {'auto.offset.reset': config["kafka_reset"]}
    })
    # 获取数据对应最小offset 与 redis记录中的offset比较
    kafka_offset = consume.get_watermark_offsets(tp_c)[0]
    if not redis_offset:
        offset = kafka_offset
    else:
        if int(redis_offset) > kafka_offset:
            offset = int(redis_offset)
        else:
            offset = kafka_offset
    # 重新绑定offset 消费
    tp_c = TopicPartition(topic, partition, offset)
    consume.assign([tp_c])
    data = consume.consume(config["length"], 3)
    write_offset = offset
    if data:
        print("topic: %s\tpartition: %s\tdata length : %s" % (topic, partition, len(data)))
        # 处理日志数据函数  flag: 'parse'(消息解析错误)/'error'(消息处理失败)/'success'(消息处理成功)
        write_offset = functions[topic](data, write_offset, redis_conn)
    else:
        print("topic: %s\tpartition: %s\t无数据" % (topic, partition))
    # 处理结束后， redis中更新offset
    tp_c = TopicPartition(topic, partition, write_offset)
    # 获取当前分区偏移量
    kafka_offset = consume.position([tp_c])[0].offset
    # 当前分区有消费的数据, 存在偏移量
    if kafka_offset >= 0:
        # 当redis维护的offset发成超限时，重置offset
        if write_offset > kafka_offset:
            write_offset = kafka_offset
    redis_conn.set(offsetkey, write_offset)
    consume.commit(offsets=[tp_c])


'''
@description:    kafka阻塞式消费数据
@param {type}    topic(string),  partition(int),  functions(object),  redis_conn(object),  pg_conn(object),  config(dict)
@return:
'''
def reset_offset(topic, partition, functions, redis_conn, config):
    """
        假定kafka配置60分区  一个线程轮询消费10个分区
    """
    number = partition * 10
    while True:
        try:
            consumeData(topic, number, functions, redis_conn, config)
            number += 1
            time.sleep(1)
            if number % 10 == 0:
                number = partition * 10
        except Exception as e:
            print("Error: consumeData function -> message: %s" % str(e))
            continue


'''
@description:    进程对应一个话题，进程开启多线程对应话题分区数量，同时消费数据
@param {type}    topic(string),  partition(int),  config(dict)
@return:
'''
def threatsConsume(topic, functions, config):
    print('Run child process (%s)...' % (os.getpid()))
    # 子进程启动多线程方式消费当前分配的话题数据，线程数和分区数要匹配

    # 开启redis连接池
    redis_pool = redis.ConnectionPool(
                                        host=config["redis_ip"],
                                        port=config["redis_port"],
                                        db=config["redis_db"],
                                        password=config["redis_passwd"],
                                        decode_responses=True
    )
    redis_conn = redis.Redis(connection_pool=redis_pool)
    threads = []
    try:
        for partition in range(config["thread"]):
            child_thread = threading.Thread(
                                            target=reset_offset, 
                                            args=(
                                                    topic, 
                                                    partition, 
                                                    functions, 
                                                    redis_conn,
                                                    config, 
                                            ),
                                            name='LoopThread'
            )
            threads.append(child_thread)
        for eachthread in threads:
            eachthread.start()
        for eachthread in threads:
            eachthread.join()
        print("exit program with 0")
    except Exception as e:
        print("Error: threatsConsume function threads fail-> message: %s" % str(e))


'''
@description: 主程序
'''
def main():
    config = {
              "kafka_ip": "10.255.175.92",
              "kafka_port": 6667,
              "kafka_group_id": "sdc_test_1",
              "kafka_session_timeout": 6000,
              "kafka_reset": "smallest",
              "kafka_max_poll": 10000000,
              "kafka_partitions": 60,
              "thread": 6,
              "length": 1000,
              "redis_ip": "10.255.175.96",
              "redis_port": 6379,
              "redis_db": 9,
              "redis_passwd": "antiy?pmc"
        }
    functions = {
                "PTD_BlackData_Processed3": ptd_parse,
                "ACD_eventlog": iep_parse,
                "origin_syslog": firewall_parse,
                "Standardization_BlackData": stand_black,
                "Standardization_WhiteData": stand_white
    }
    topics = ["PTD_BlackData_Processed3", "ACD_eventlog", "origin_syslog", "Standardization_BlackData", "Standardization_WhiteData"]  # 待消费话题集合
    #topics = functions.keys()
    processes = []
    print('Parent process %s.' % os.getpid())
    # 启动多进程方式同时消费所有话题
    for eachtopic in topics:
        p = Process(target=threatsConsume, args=(eachtopic, functions, config, ))
        print('Child process will start.')
        processes.append(p)
    for eachprocess in processes:
        eachprocess.start()
    for eachprocess in processes:
        eachprocess.join()
    print('Child process end.')


if __name__ == "__main__":
    main()
