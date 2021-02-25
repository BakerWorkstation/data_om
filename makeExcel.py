'''
@Author: sdc
@Date: 2020-01-08 09:47:23
@LastEditTime : 2020-01-19 13:57:54
@LastEditors  : Please set LastEditors
@Description:  生成数据运营报告(excel)脚本
@FilePath: /opt/data_service/makeExcel.py
'''


#!/usr/bin/env python3.6
# -*- coding:utf-8 -*-
# __author__: sdc

import json
import redis
import datetime
import xlsxwriter   

class BuildExcel(object):

    def __init__(self, ip, port, db, passwd):
        self.redis_ip = ip
        self.redis_port = port
        self.redis_db = db
        self.redis_passwd = passwd

    def connect_redis(self):
        # 开启redis连接池
        redis_pool = redis.ConnectionPool(
                                            host=self.redis_ip,
                                            port=self.redis_port,
                                            db=self.redis_db,
                                            password=self.redis_passwd,
                                            decode_responses=True
        )
        redis_conn = redis.Redis(connection_pool=redis_pool)
        return redis_conn

    def get_data(self, redis_conn, day):
        # 获取ptd原始日志相关数据
        ptd_info = redis_conn.get("ptd_%s" % day)
        if ptd_info:
            ptd_info = json.loads(ptd_info)
        else:
            ptd_info = {}

        # 获取iep原始日志相关数据
        iep_info = redis_conn.get("iep_%s" % day)
        if iep_info:
            iep_info = json.loads(iep_info)
        else:
            iep_info = {}

        # 获取防火墙原始日志相关数据
        zhenguan_info = redis_conn.get("zhenguan_%s" % day)
        if zhenguan_info:
            zhenguan_info = json.loads(zhenguan_info)
        else:
            zhenguan_info = {}

        # 获取ptd设备最后活跃时间
        ptd_timestamp = {}
        for device in ["BCNHYW2", "CJXJWW2", "2102311QGK10HA000177", "BC3CYW2", "BBMHYW2", "1NKVRT2", "C0GDWW2"]:
            hearttime = redis_conn.get("ptd_%s" % device)
            ptd_timestamp[device] = hearttime

        # 获取iep设备最后活跃时间
        iep_timestamp = {}
        for server_ip in ["10.255.49.17", "10.255.52.122"]:
            hearttime = redis_conn.get("iep_%s" % server_ip)
            iep_timestamp[server_ip] = hearttime
        
        # 获取标准化数量
        stand_black = redis_conn.get("stand_black_%s" % day)
        if stand_black:
            stand_black = json.loads(stand_black)
        else:
            stand_black = {}
        stand_white = redis_conn.get("stand_white_%s" % day)
        if stand_white:
            stand_white = json.loads(stand_white)
        else:
            stand_white = {}

        # 获取iep设备最后活跃时间
        firewall_timestamp = {}
        for server_ip in ["10.255.192.242", "10.0.0.17", "10.255.192.249"]:
            hearttime = redis_conn.get("firewall_%s" % server_ip)
            firewall_timestamp[server_ip] = hearttime

        # 获取PTD统计日志数量
        result = redis_conn.get("ptd_assetlog_%s" % day)
        if result:
            log_count = json.loads(result)
        else:
            log_count = {}

        # 获取PTD捕获资产IP
        result = redis_conn.get("ptd_assets")
        if result:
            ptd_assets = json.loads(result)
        else:
            ptd_assets = {}


        data = {
                "ptd_info": ptd_info,
                "iep_info": iep_info,
                "zhenguan_info": zhenguan_info,
                "ptd_timestamp": ptd_timestamp,
                "iep_timestamp": iep_timestamp,
                "firewall_timestamp": firewall_timestamp,
                "stand_black": stand_black,
                "stand_white": stand_white,
                "log_count": log_count,
                "ptd_assets": ptd_assets
        }


        return data
        
    def write2excel(self, day, data):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ptd_info = data["ptd_info"]
        iep_info = data["iep_info"]
        zhenguan_info = data["zhenguan_info"]
        ptd_timestamp = data["ptd_timestamp"]
        iep_timestamp = data["iep_timestamp"]
        firewall_timestamp = data["firewall_timestamp"]
        stand_white = data["stand_white"]
        stand_black = data["stand_black"]
        log_count = data["log_count"]
        ptd_assets = data["ptd_assets"]
        sub = "试运营数据报告"
        filename = u'{0}-{1}.xlsx'.format(sub, day)
        workbook = xlsxwriter.Workbook("/opt/data_service/excel/%s" % filename)
        titleConfig = {
            'border': 1,  # 单元格边框宽度
            'font_name': '楷体',
            'font_size':14,  #字体大小
            'align': 'left',
            'valign': 'vcenter',  # 字体对齐方式
            'fg_color': '#F4B084',  # 单元格背景颜色
        }
        titleConfig_nobg = {
            'border': 1,  # 单元格边框宽度
            'font_name': '楷体',
            'font_size':14,  #字体大小
            'align': 'center',
            'valign': 'vcenter',  # 字体对齐方式
        }
        contentConfig = {
            'border': 1,  # 单元格边框宽度
            'font_name': '楷体',
            'font_size':14,                #字体大小
            'align': 'center',
            'valign': 'vcenter',  # 字体对齐方式
            'text_wrap': True,  # 是否自动换行
            #'num_format':'yyyy-mm-dd'
        }
        #'font_color':'#FEFEFE',        #字体颜色
        dataConfig = {
            'border': 1,  # 单元格边框宽度
            'font_name': '楷体',
            'font_size':14,  #字体大小
            'align': 'center',
            'valign': 'vcenter',  # 字体对齐方式
            'font_color': '#FF0000'
        }
        # 生成ptd相关数据
        worksheet = workbook.add_worksheet('ptd') 
        worksheet.set_column('A:I', 30)
        for eachrow in range(0, 2000):
            worksheet.set_row(eachrow, 30)
        titlebold = workbook.add_format(titleConfig)
        contentbold = workbook.add_format(contentConfig)
        title = ["设备编号", "部署位置", "IP地址", "是否全要素", "最近活跃时间", "原始总日志数量", "原始黑日志数量", "原始灰日志数量", "捕获资产数量", "标准化黑日志数量", "标准化灰日志数量"]
        ptddevice = [
                     ["BCNHYW2", "墙外-电信镜像(外网)", "10.255.190.2", "是"], 
                     ["CJXJWW2", "墙外-联通镜像(外网)", "10.255.190.3", "是"],
                     ["2102311QGK10HA000177", "墙内-办公网镜像(内网)", "10.255.49.100", "是"], 
                     ["BC3CYW2", "机房d排(内网)", "10.255.190.5", "是"],
                     ["BBMHYW2", "机房c排(内网)", "10.255.190.6", "是"],
                     ["1NKVRT2", "机房a排(内网)", "10.255.190.7", "是"],
                     ["C0GDWW2", "机房e排(内网)", "10.255.190.8", "是"],
                     ["CPBLWW2", "wifi(内网)-暂未接入", "10.255.190.1", "", "", "", "", "", "", "", ""]
        ]
        worksheet.merge_range('A1:I1','根据%s当天运营数据总结   报告生成时间 %s' % (day, timestamp), titlebold)  
        worksheet.write_column('A2', title, contentbold)
        flag = 0
        for eachdevice in ptddevice:
            worksheet.write_column('%s2' % chr(ord('B') + flag), eachdevice, contentbold)
            flag += 1
        flag = 0
        for eachdevice in ptddevice:
            device = eachdevice[0]
            if device == "CPBLWW2":
                continue
            hearttime = ptd_timestamp.get(device)
            if not hearttime:
                hearttime = ""
            worksheet.write_column('%s6' % chr(ord('B') + flag), [hearttime], contentbold)
            count = ptd_info.get(device)
            if count:
                total = count.get("total")
                gray = count.get("gray")
                black = count.get("black")
                asset_count = count.get("asset_count")
            else:
                total = 0
                gray = 0
                black = 0
                asset_count = 0
            worksheet.write_column('%s7' % chr(ord('B') + flag), [total], contentbold)
            worksheet.write_column('%s8' % chr(ord('B') + flag), [black], contentbold)
            worksheet.write_column('%s9' % chr(ord('B') + flag), [gray], contentbold)
            worksheet.write_column('%s10' % chr(ord('B') + flag), [asset_count], contentbold)
            if stand_black:
                black = stand_black.get(device)
                if not black:
                    black = 0
            else:
                black = 0
            worksheet.write_column('%s11' % chr(ord('B') + flag), [black], contentbold)
            if stand_white:
                white = stand_white.get(device)
                if not white:
                    white = 0
            else:
                white = 0
            worksheet.write_column('%s12' % chr(ord('B') + flag), [white], contentbold)
            flag += 1

        # 生成iep相关数据
        worksheet = workbook.add_worksheet('iep')
        worksheet.set_column('A:I', 55)
        for eachrow in range(0, 2000):
            worksheet.set_row(eachrow, 30)
        titlebold = workbook.add_format(titleConfig)
        contentbold = workbook.add_format(contentConfig)
        title = ["设备编号", "部署位置", "IP地址", "最近活跃时间", "原始总日志数量", "原始黑日志数量", "原始灰日志数量", "捕获资产数量", "标准化黑日志数量", "标准化灰日志数量"]
        iepdevice = [
                     ["fdd27420-1c6a-42a0-aaa2-cc8e6519b681", "C11-37-38(内网)", "10.255.49.17"],
                     ["51dd13ad8deeba44208f34e648d63918", "C11-40-41(内网)", "10.255.52.122"]
        ]
        worksheet.merge_range('A1:C1','根据%s当天运营数据总结   报告生成时间 %s' % (day, timestamp), titlebold)  
        worksheet.write_column('A2', title, contentbold)
        flag = 0
        for eachserver in iepdevice:
            worksheet.write_column('%s2' % chr(ord('B') + flag), eachserver, contentbold)
            flag += 1

        flag = 0
        for eachserver in iepdevice:
            server_ip = eachserver[2]
            hearttime = iep_timestamp.get(server_ip)
            if not hearttime:
                hearttime = ""
            worksheet.write_column('%s5' % chr(ord('B') + flag), [hearttime], contentbold)

            count = iep_info.get(server_ip)
            if count:
                total = count.get("total")
                gray = count.get("gray")
                black = count.get("black")
                asset_count = count.get("asset_count")
            else:
                total = 0
                gray = 0
                black = 0
                asset_count = 0
            worksheet.write_column('%s6' % chr(ord('B') + flag), [total], contentbold)
            worksheet.write_column('%s7' % chr(ord('B') + flag), [black], contentbold)
            worksheet.write_column('%s8' % chr(ord('B') + flag), [gray], contentbold)
            worksheet.write_column('%s9' % chr(ord('B') + flag), [asset_count], contentbold)
            if stand_black:
                black = stand_black.get(server_ip)
                if not black:
                    black = 0
            else:
                black = 0
            worksheet.write_column('%s10' % chr(ord('B') + flag), [black], contentbold)
            if stand_white:
                white = stand_white.get(server_ip)
                if not white:
                    white = 0
            else:
                white = 0
            worksheet.write_column('%s11' % chr(ord('B') + flag), [white], contentbold)

            flag += 1

        # 生成防火墙相关数据
        worksheet = workbook.add_worksheet('防火墙') 
        worksheet.set_column('A:I', 50)
        for eachrow in range(0, 2000):
            worksheet.set_row(eachrow, 30)
        titlebold = workbook.add_format(titleConfig)
        contentbold = workbook.add_format(contentConfig)
        title = ["设备编号", "部署位置", "IP地址", "最近活跃时间", "原始总日志数量", "APP_POLICY", "ADSL"]
        firewalldevice = [
                          ["镇关-办公网防火墙", "办公网透明过滤防火墙", "10.255.192.242"],
                          ["华为-联通出口防火墙", "联通光纤出口NAT和透明过滤防火墙", "10.0.0.17"],
                          ["华为-出口入侵检测", "联通、电信、ADSL出口入侵检测", "10.255.192.249"]
        ]
        worksheet.merge_range('A1:D1','根据%s当天运营数据总结   报告生成时间 %s' % (day, timestamp), titlebold)
        worksheet.write_column('A2', title, contentbold)
        flag = 0
        for eachdevice in firewalldevice:
            worksheet.write_column('%s2' % chr(ord('B') + flag), eachdevice, contentbold)
            flag += 1
        
        flag = 0
        for eachdevice in firewalldevice:
            device = eachdevice[2]
            hearttime = firewall_timestamp.get(device)
            if not hearttime:
                hearttime = ""
            worksheet.write_column('%s5' % chr(ord('B') + flag), [hearttime], contentbold)
            count = zhenguan_info.get(device)
            if count:
                total = count["total"]
                policy = count["APP_POLICY"]
                adsl = count["ADSL"]
            else:
                total = 0
                policy = 0
                adsl = 0
            worksheet.write_column('%s6' % chr(ord('B') + flag), [total], contentbold)
            worksheet.write_column('%s7' % chr(ord('B') + flag), [policy], contentbold)
            worksheet.write_column('%s8' % chr(ord('B') + flag), [adsl], contentbold)

            flag += 1
        
        # 生成PTD与IEP资产IP交集数据
        try:
            iep_17 = iep_info.get("10.255.49.17").get("asset").keys()
        except:
            iep_17 = []
        try:
            iep_122 = iep_info.get("10.255.52.122").get("asset").keys()
        except:
            iep_122 = []
        for devicename, content in ptd_info.items():
            worksheet = workbook.add_worksheet('ptd(%s)交集资产' % devicename)
            worksheet.set_column('A:I', 30)
            for eachrow in range(0, 2000):
                worksheet.set_row(eachrow, 30)
            titlebold = workbook.add_format(titleConfig)
            contentbold = workbook.add_format(contentConfig)
            contentbold_nobg = workbook.add_format(titleConfig_nobg)
            databold = workbook.add_format(dataConfig)
            #title = ["设备编号", "部署位置", "IP地址", "最近活跃时间", "原始总日志数量", "APP_POLICY", "ADSL"]
            worksheet.merge_range('A1:D1','根据%s当天运营数据总结   报告生成时间 %s' % (day, timestamp), titlebold)
            #worksheet.write_column('A2', ['PTD设备'], contentbold)
            worksheet.merge_range('A2:B2','PTD设备', contentbold_nobg)
            worksheet.merge_range('C2:D2','IEP设备', contentbold_nobg)
            worksheet.write_row('A3', [devicename, "日志数量", "10.255.49.17", "10.255.52.122"], contentbold)
            line = 4
            countdata = log_count[devicename]
            loglist = sorted(countdata.items(), key=lambda x:x[1], reverse=True)
            #print(loglist)
            for eachdata in loglist:
                ip_addr = eachdata[0]
                number = eachdata[1]
                worksheet.write_row('A%s' % line, [ip_addr], contentbold)
                worksheet.write_row('B%s' % line, [number], contentbold)

                # worksheet.write_row('A%s' % line, [eachptd_ip], contentbold)
                # #print(devicename)
                # #print(log_count[devicename])
                # try:
                #     worksheet.write_row('B%s' % line, [log_count[devicename][eachptd_ip]], contentbold)
                # except:
                #     worksheet.write_row('B%s' % line, [""], contentbold)
                if ip_addr in iep_17:
                    # dataConfig
                    worksheet.write_row('C%s' % line, [ip_addr], databold)
                else:
                    worksheet.write_row('C%s' % line, [""], databold)
                if ip_addr in iep_122:
                    worksheet.write_row('D%s' % line, [ip_addr], databold)
                else:
                    worksheet.write_row('D%s' % line, [""], databold)
                line += 1
        
        # 生成ptd捕获资产ip全列表数据
        worksheet = workbook.add_worksheet('ptd捕获资产ip全列表') 
        worksheet.set_column('A:P', 30)
        for eachrow in range(0, 2000):
            worksheet.set_row(eachrow, 30)
        titlebold = workbook.add_format(titleConfig)
        contentbold = workbook.add_format(contentConfig)
        #print(ptd_assets)
        flag = 0
        for device, ipinfo in ptd_assets.items():
            unit = '%s1:%s1' % (chr(ord('A') + flag), chr(ord('C') + flag))
            #print(unit)
            worksheet.merge_range(unit, device, contentbold)
            worksheet.write_row('%s2' % (chr(ord('A') + flag)), ["ip地址", "首次发现时间", "最后更新时间"], contentbold)
            #print(ipinfo)
            line = 3
            for ip, timeinfo in ipinfo.items():
                worksheet.write_row('%s%s' % (chr(ord('A') + flag), line), [ip, timeinfo["create_time"], timeinfo["update_time"]], contentbold)
                line += 1

            flag += 3

        # # 图表
        # chart_col = workbook.add_chart({'type':'line'})        #新建图表格式 line为折线图
        # chart_col.add_series(                                   #给图表设置格式，填充内容
        #     {
        #         'name':'=ptd!$B$1',
        #         'categories':'=ptd!$A$2:$A$7',
        #         'values':   '=ptd!$B$2:$B$7',
        #         'line': {'color': 'red'},
        #     }
        # )
        # chart_col.set_title({'name':'测试'})
        # chart_col.set_x_axis({'name':"x轴"})
        # chart_col.set_y_axis({'name':'y轴'})          #设置图表表头及坐标轴
        # chart_col.set_style(1)
        # worksheet.insert_chart('A14',chart_col,{'x_offset':25,'y_offset':10})   #放置图表位置

        workbook.close()

def makeExcel(today):
    ip = "10.255.175.96"
    port = 6379
    db = 9
    passwd = "antiy?pmc"
    build = BuildExcel(ip, port, db, passwd)
    redis_conn = build.connect_redis()
    data = build.get_data(redis_conn, today)
    build.write2excel(today, data)

if __name__ == "__main__":
    today = datetime.datetime.now().strftime("%Y%m%d")
    makeExcel(today)

