#!/usr/bin/python


from pyspark import SparkConf, SparkContext
from pyspark.sql import SQLContext, Row
from pyspark.sql import SparkSession
import pygeoip
import pandas as pd
import pygal
import pygal_maps_world
from pygal.style import LightenStyle
#import pythonwhois
#import whois
from user_agents import parse
from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from matplotlib import cm
import os
import time
import win_inet_pton

def filter_dataset():
    filedir = "H:\\ipv6"
    protocol_dirs = os.listdir(filedir)
    print protocol_dirs
    for protocol_dir in protocol_dirs:
        print protocol_dir
        date_dirs = os.listdir(filedir + "\\" + protocol_dir)
        print date_dirs
        for date_dir in date_dirs:
            num = 0
            filenames = os.listdir(filedir + "\\" + protocol_dir + "\\" + date_dir)
            for filename in filenames:
                file_path = filedir + "\\" + protocol_dir + "\\" + date_dir + "\\" + filename
                if protocol_dir == "dns":
                    file_data = ""
                    print file_path
                    with open(file_path, "r") as f:
                        for line in f:
                            if "\x00" in line:
                                continue
                            file_data += line
                    with open(file_path, "w") as f:
                        f.write(file_data)
                    dns_df = spark.read.json(file_path)
                    test_file = dns_df.toPandas()
                    print num
                    num = num + 1
                if protocol_dir == "ssl":
                    print file_path
                    ssl_df = spark.read.json(file_path)
                    test_file = ssl_df.toPandas()
                    print num
                    num = num + 1
                if protocol_dir == "tcp_udp":
                    print file_path
                    tcp_udp_df = spark.read.json(file_path)
                    test_file = tcp_udp_df.toPandas()
                    print num
                    num = num + 1
                if protocol_dir == "http":
                    print file_path
                    file_data = ""
                    with open(file_path, "r") as f:
                        for line in f:
                            if "\x00" in line:
                                continue
                            else:
                                if line.count("CONT_TYPE") == 2:
                                    index = line.rfind("CONT_TYPE")
                                    line = line[0:index] + "RES_CONT_TYPE" + line[index + 9:]
                                if line.count("VIA") == 2:
                                    index = line.rfind("VIA")
                                    line = line[0:index] + "RES_VIA" + line[index + 4:]
                                if line.count("DATE") == 2:
                                    index = line.rfind("DATE")
                                    line = line[0:index] + "RES_DATE" + line[index + 5:]
                                if line.count("User_Agent") == 2:
                                    index = line.rfind("User_Agent")
                                    line = line[0:index] + "RES_User_Agent" + line[index + 11:]
                                if line.count("COOKIE") == 2:
                                    index = line.rfind("COOKIE")
                                    line = line[0:index] + "RES_COOKIE" + line[index + 7:]
                            file_data += line
                    with open(file_path, "w") as f:
                        f.write(file_data)
                    http_df = spark.read.json(file_path)
                    test_file = http_df.toPandas()
                    print num
                    num = num + 1

def get_ip(ip):
    file = open("file_test", "w")
    file.writelines(ip)
    file.close()

def get_ip_by_all(tcp_udp_df, ip_version):
    print("### start Get_Ip_By_All ###")
    ip_df = tcp_udp_df.select("sip").union(tcp_udp_df.select("dip")).withColumnRenamed("sip", "ip")
    ip_count_df = ip_df.groupBy("ip").count()
    #ip_count_df.show()
    ip_list = []
    #ip_list = ip_count_df.rdd.map(lambda row: row.ip).collect()
    if os.path.exists("E:\\tempfile\\ip6_file"):
        files = os.listdir("E:\\tempfile\\ip6_file")
        for afile in files:
            os.remove("E:\\tempfile\\ip6_file\\" + afile)
        os.rmdir("E:\\tempfile\\ip6_file")
    if os.path.exists("E:\\tempfile\\ip4_file"):
        files = os.listdir("E:\\tempfile\\ip4_file")
        for afile in files:
            os.remove("E:\\tempfile\\ip4_file\\" + afile)
        os.rmdir("E:\\tempfile\\ip4_file")
    if ip_version == 6:
        ip_count_df.rdd.map(lambda row: row.ip).repartition(1).saveAsTextFile("E:\\tempfile\\ip6_file")
        f = open("E:\\tempfile\\ip6_file\\part-00000", "r")
    else:
        ip_count_df.rdd.map(lambda row: row.ip).repartition(1).saveAsTextFile("E:\\tempfile\\ip4_file")
        f = open("E:\\tempfile\\ip4_file\\part-00000", "r")
    while 1:
        lines = f.readlines(10000)
        if not lines:
            break
        for line in lines:
            ip_list.append(line[:-1])
    f.close()
    #print ip_list
    print "### finish running Get_Ip_By_All ###"
    return(ip_list, ip_count_df)


def get_ipv4_by_all(dns_df, ssl_df, http_df):
    ip_df = dns_df.select(dns_df['sip']).union(dns_df.select(dns_df['dip'])).union(ssl_df.select(ssl_df['sip'])) \
        .union(ssl_df.select(ssl_df['dip'])).union(http_df.select(http_df['sip'])).union(http_df.select(http_df['dip'])) \
        .withColumnRenamed("sip", "ip")

    #ip_count_df = ip_df.groupBy("ip").count().sort("count")
    ip_count_df = ip_df.groupBy("ip").count()
    ip_list = []
    #ip_count_df.rdd.map(lambda row: row.ip).foreach(get_ip)
    #num = ip_count_df.rdd.map(lambda row: row.ip).count()
    #ip_list = ip_count_df.rdd.map(lambda row: row.ip).collect()
    #ip_count_df.rdd.map(lambda row: row.ip).repartition(1).saveAsTextFile("E:\\test_ssl.txt")

    if os.path.exists("E:\\tempfile\\ip4_file"):
        files = os.listdir("E:\\tempfile\\ip4_file")
        for afile in files:
            os.remove("E:\\tempfile\\ip4_file\\" + afile)
        os.rmdir("E:\\tempfile\\ip4_file")
    ip_count_df.rdd.map(lambda row: row.ip).repartition(1).saveAsTextFile("E:\\tempfile\\ip4_file")
    f = open("E:\\tempfile\\ip4_file\\part-00000", "r")
    while 1:
        lines = f.readlines(10000)
        if not lines:
            break
        for line in lines:
            ip_list.append(line[:-1])
    f.close()
    #print ip_list
    ip_count_df.show()
    return(ip_list, ip_count_df)



def devide_v4_and_v6_by_all(ip_list):
    total_dns_df = spark.sql("SELECT count(1) from DNS_All").withColumnRenamed("count(1)", "num").show()
    total_ssl_df = spark.sql("SELECT count(1) from SSL_All").withColumnRenamed("count(1)", "num").show()
    total_http_df = spark.sql("SELECT count(1) from HTTP_All").withColumnRenamed("count(1)", "num").show()
    #total = total_df.rdd.map(lambda row: row.num).collect()
    #dns_df.describe("sip", "dip").show()
    #for col in range(0, total[0]):
        #print(dns_df.take(col))
    ipv4_list = []
    ipv6_list = []
    #print(ip_list)
    for ip_element in ip_list:
        if str(ip_element).find(".") != -1:
            ipv4_list.append(ip_element)
        elif str(ip_element).find(":") != -1:
            ipv6_list.append(ip_element)
    #print(ipv4_list)
    #print(ipv6_list)
    #if len(ipv4_list):
    ipv4_RDD = sc.parallelize(ipv4_list)
    ipv4_df = spark.read.json(ipv4_RDD).withColumnRenamed("_corrupt_record", "ipv4")
    #if len(ipv6_list):
    ipv6_RDD = sc.parallelize(ipv6_list)
    ipv6_df = spark.read.json(ipv6_RDD).withColumnRenamed("_corrupt_record", "ipv6")
    #ipv4_df.show()
    #ipv6_df.show()

    return(ipv4_df, ipv6_df)

def get_devide_detail_by_v4_and_v6(ipv4_df, ipv6_df, dns_df, ssl_df, http_df):
    if len(ipv4_df.rdd.map(lambda row: row[0]).collect()) != 0:
        ipv4_dns_df = ipv4_df.withColumnRenamed("ipv4", "sip").join(dns_df, "sip")
        ipv4_dns_df.describe().show()

        ipv4_ssl_df = ipv4_df.withColumnRenamed("ipv4", "sip").join(ssl_df, "sip")
        ipv4_ssl_df.describe().show()

        ipv4_http_df = ipv6_df.withColumnRenamed("ipv4", "sip").join(http_df, "sip")
        ipv4_http_df.describe().show()

    if len(ipv6_df.rdd.map(lambda row: row[0]).collect()) != 0:
        ipv6_dns_df = ipv6_df.withColumnRenamed("ipv6", "sip").join(dns_df, "sip")
    # ipv6_dns_2_df = ipv6_df.withColumnRenamed("ipv6", "dip").join(dns_df, "dip")
        ipv6_dns_df.describe().show()
    # ipv6_dns_2_df.describe().show()
        ipv6_ssl_df = ipv6_df.withColumnRenamed("ipv6", "sip").join(ssl_df, "sip")
    # ipv6_ssl_2_df = ipv6_df.withColumnRenamed("ipv6", "dip").join(ssl_df, "dip")
        ipv6_ssl_df.describe().show()
    # ipv6_ssl_2_df.describe().show()
        ipv6_http_df = ipv6_df.withColumnRenamed("ipv6", "sip").join(http_df, "sip")
    # ipv6_http_2_df = ipv6_df.withColumnRenamed("ipv6", "dip").join(http_df, "dip")
        ipv6_http_df.describe().show()
    # ipv6_http_2_df.describe().show()


def get_geo_by_ip(ip_list, ip_count_df):
    print "### start Get_Geo_By_Ip ###"
    geoip_list = []
    geo_list = []
    num = 0
    geoip = pygeoip.GeoIP("E:\\GeoLiteCity.dat")
    geoip6 = pygeoip.GeoIP("E:\\GeoLiteCityv6.dat")
    for ip_element in ip_list:
        if '.' in ip_element:
            rec = geoip.record_by_addr(str(ip_element))
        elif ':' in ip_element:
            rec = geoip6.record_by_addr(str(ip_element))
        geoip_list.append(rec)
    #print(geoip_list)

    for geoip_element in geoip_list:
        if geoip_element != None:
            geo_list.append({"ip": str(ip_list[num])})
            geo_list[num]["country_name"] = geoip_element["country_name"]
            geo_list[num]["latitude"] = geoip_element["latitude"]
            geo_list[num]["longitude"] = geoip_element["longitude"]
            geo_list[num]["country_code"] = geoip_element["country_code"].lower()
            num += 1
    #print(geo_list)
    geo_RDD = sc.parallelize(geo_list)
    geo_df = spark.read.json(geo_RDD)
    #geo_df.show()

    geo_count_df = geo_df.groupBy("country_code").count()
    #geo_count_df.show()
    total_geo_ip_count_df = geo_df.join(ip_count_df, "ip")
    #total_geo_ip_count_df.show()
    geo_total_df = total_geo_ip_count_df.select("country_code", "count").groupBy("country_code").sum("count")
    print "### finish running Get_Geo_By_Ip ###"
    return(geo_df, geo_count_df, geo_total_df, total_geo_ip_count_df)

def get_CS_by_dns(dns_df, ip_version):
    print "### start Get_CS_By_DNS ###"
    if ip_version == 6:
        dns_queries_df = spark.sql("SELECT * FROM DNS_All WHERE query.queries.name is not null")
        dns_answers_df = spark.sql("SELECT * FROM DNS_ALL WHERE response.queries.name is not null")
    else:
        dns_queries_df = spark.sql("SELECT * FROM IPv4_DNS_All WHERE query.queries.name is not null")
        dns_answers_df = spark.sql("SELECT * FROM IPv4_DNS_ALL WHERE response.queries.name is not null")

    cs_queries_df = dns_queries_df.select("query.queries.name", "sip", "dip")
    cs_answers_df = dns_answers_df.select("response.queries.name", "response.answers.ipv4", \
                                      "response.answers.ipv6", "response.answers.cname", "sip", "dip")

    cs_queries_count_df = cs_queries_df.groupBy("name").count().sort("count")
    cs_answers_count_df = cs_answers_df.groupBy("name").count().sort("count")
    #cs_queries_count_df.show()
    #cs_answers_count_df.show()

    cs_dns_df = dns_queries_df.select("query.queries.name", "response.queries.name", "response.answers.ipv4", \
                                      "response.answers.ipv6", "response.answers.cname", "sip", "dip")
    #cs_dns_df.show()

    print "### finish running Get_CS_By_DNS ###"
    return(cs_queries_count_df, cs_answers_count_df)

def get_IPv6_stack_by_dns(dns_df, ip_version):
    print "### start Get_IPv6_Stack_By_DNS ###"
    if ip_version == 6:
        dns_ipv6_stack_df = spark.sql("SELECT * FROM DNS_ALL WHERE response.answers.ipv6[0] is not null") \
            .select("response.queries.name", "response.answers.ipv6", "response.answers.cname")
        dns_ipv4_stack_df = spark.sql("SELECT * FROM DNS_ALL WHERE response.answers.ipv4[0] is not null") \
            .select("response.queries.name", "response.answers.ipv4", "response.answers.cname")
    else:
        dns_ipv6_stack_df = spark.sql("SELECT * FROM IPv4_DNS_ALL WHERE response.answers.ipv6[0] is not null") \
            .select("response.queries.name", "response.answers.ipv6", "response.answers.cname")
        dns_ipv4_stack_df = spark.sql("SELECT * FROM IPv4_DNS_ALL WHERE response.answers.ipv4[0] is not null") \
            .select("response.queries.name", "response.answers.ipv4", "response.answers.cname")
    #dns_ipv6_stack_df.show()
    #dns_ipv4_stack_df.show()
    ipv6_dual_stack_df = dns_ipv6_stack_df.join(dns_ipv4_stack_df, "name")
    #ipv6_dual_stack_df.show()
    dns_ipv4_stack_count_df = dns_ipv4_stack_df.groupBy("ipv4").count()
    dns_ipv6_stack_count_df = dns_ipv6_stack_df.groupBy("ipv6").count()
    ipv6_dual_stack_count_df = ipv6_dual_stack_df.groupBy("ipv6").count()

    #name_list = dns_ipv4_stack_df.select("name").rdd.map(lambda row: row["name"]).collect()
    #whois_list = []
    #for name in name_list:
        #whois_list.append(whois.whois(name))
    #print(whois_list)

    ipv4_list = dns_ipv4_stack_count_df.select("ipv4").rdd.map(lambda row: row["ipv4"]).collect()
    ipv6_list = dns_ipv6_stack_count_df.select("ipv6").rdd.map(lambda row: row["ipv6"]).collect()
    dual_list = ipv6_dual_stack_count_df.select("ipv6").rdd.map(lambda row: row["ipv6"]).collect()

    geoipv4_list = []
    geoipv6_list = []
    geoipdual_list = []
    geo4_list = []
    geo6_list = []
    geodual_list = []

    geoip = pygeoip.GeoIP("E:\\GeoLiteCity.dat")
    geoip6 = pygeoip.GeoIP("E:\\GeoLiteCityv6.dat")
    for ip_element in ipv4_list:
        geoipv4_list.append(geoip.record_by_addr(str(ip_element[0])))
    for ip_element in ipv6_list:
        geoipv6_list.append(geoip6.record_by_addr(str(ip_element[0])))
    for ip_element in dual_list:
        geoipdual_list.append(geoip6.record_by_addr(str(ip_element[0])))

    num = 0
    for geoip_element in geoipv4_list:
        if geoip_element != None:
            geo4_list.append({"ip": str(ipv4_list[num])})
            geo4_list[num]["country_name"] = geoip_element["country_name"]
            geo4_list[num]["latitude"] = geoip_element["latitude"]
            geo4_list[num]["longitude"] = geoip_element["longitude"]
            geo4_list[num]["country_code"] = geoip_element["country_code"].lower()
            num += 1
    #print(geo4_list)

    num = 0
    for geoip_element in geoipv6_list:
        if geoip_element != None:
            geo6_list.append({"ip": str(ipv6_list[num])})
            geo6_list[num]["country_name"] = geoip_element["country_name"]
            geo6_list[num]["latitude"] = geoip_element["latitude"]
            geo6_list[num]["longitude"] = geoip_element["longitude"]
            geo6_list[num]["country_code"] = geoip_element["country_code"].lower()
            num += 1
    #print(geo6_list)
    num = 0
    for geoip_element in geoipdual_list:
        if geoip_element != None:
            geodual_list.append({"ip": str(dual_list[num])})
            geodual_list[num]["country_name"] = geoip_element["country_name"]
            geodual_list[num]["latitude"] = geoip_element["latitude"]
            geodual_list[num]["longitude"] = geoip_element["longitude"]
            geodual_list[num]["country_code"] = geoip_element["country_code"].lower()
            num += 1
    #print(geodual_list)

    geo4_RDD = sc.parallelize(geo4_list)
    geo4_df = spark.read.json(geo4_RDD)
    #geo4_df.show()
    geo4_count_df = geo4_df.groupBy("country_code").count()

    geo6_RDD = sc.parallelize(geo6_list)
    geo6_df = spark.read.json(geo6_RDD)
    #geo6_df.show()
    geo6_count_df = geo6_df.groupBy("country_code").count()

    if geodual_list != []:
        geodual_RDD = sc.parallelize(geodual_list)
        geodual_df = spark.read.json(geodual_RDD)
        geodual_df.show()
        geodual_count_df = geodual_df.groupBy("country_code").count()
        print "### finish running Get_IPv6_Stack_By_DNS ###"
        return (dns_ipv6_stack_df, ipv6_dual_stack_df, geo4_count_df, geo6_count_df, geodual_count_df)
    else:
        print "### finish running Get_IPv6_Stack_By_DNS ###"
        return (dns_ipv6_stack_df, 0, geo4_count_df, geo6_count_df, 0)






'''
def get_whois_by_CS(cs_answers_count_df):
    cs_list = cs_answers_count_df.rdd.map(lambda row: row["name"]).collect()
    print(cs_list)
    cs_geo_list = []
    num = 0
    for cs in cs_list:
        cs_geo_list.append({"cs_name": cs})
        print(cs)
        print(str(cs))
        cs_geo_list[num]["country_code"] = str(whois.whois(str(cs)).get("country")).lower()
        print(cs_geo_list[num]["country_code"])
        num = num + 1
    print(cs_geo_list)

    cs_geo_df = spark.createDataFrame(cs_geo_list)
    cs_geo_df.show()
    cs_geo_count_df = cs_geo_df.groupBy("country_code").count()
    cs_geo_count_df.show()

    return(cs_geo_count_df)
'''

def get_CS_by_ssl(ssl_df, ip_version):
    print "### start Get_CS_By_SSL ###"
    if ip_version == 6:
        ssl_client_df = spark.sql("SELECT * FROM SSL_All WHERE client is not null")
    else:
        ssl_client_df = spark.sql("SELECT * FROM IPv4_SSL_All WHERE client is not null")
    cs_ssl_df = ssl_client_df.select("client.host", "sip", "dip")
    cs_ssl_count_df = cs_ssl_df.groupBy("host").count()
    #cs_ssl_df.show()
    print "### finish running Get_CS_By_SSL ###"
    return(cs_ssl_df, cs_ssl_count_df)

def get_CS_by_http(http_df, ip_version):
    print "### start Get_CS_By_HTTP ###"
    cs_http_df = http_df.select("SERVER", "Host", "User_Agent", "sip", "dip")
    #http_server_count_df = cs_http_df.groupBy("SERVER").count()
    if ip_version == 6:
        http_server_df = spark.sql("SELECT * FROM HTTP_ALL WHERE SERVER is not null")
        http_server_count_df = http_server_df.groupBy("SERVER").count()
        http_host_df = spark.sql("SELECT * FROM HTTP_ALL WHERE Host is not null")
        http_host_count_df = http_host_df.groupBy("Host").count()
        http_user_agent_df = spark.sql("SELECT * FROM HTTP_ALL WHERE User_Agent is not null")
        http_user_agent_count_df = http_user_agent_df.groupBy("User_Agent").count()
    else:
        http_server_df = spark.sql("SELECT * FROM IPv4_HTTP_ALL WHERE SERVER is not null")
        http_server_count_df = http_server_df.groupBy("SERVER").count()
        http_host_df = spark.sql("SELECT * FROM IPv4_HTTP_ALL WHERE Host is not null")
        http_host_count_df = http_host_df.groupBy("Host").count()
        http_user_agent_df = spark.sql("SELECT * FROM IPv4_HTTP_ALL WHERE User_Agent is not null")
        http_user_agent_count_df = http_user_agent_df.groupBy("User_Agent").count()
    #http_host_count_df = cs_http_df.groupBy("Host").count()
    #http_user_agent_count_df = cs_http_df.groupBy("User_Agent").count()
    #cs_http_df.show()
    print "### finish running Get_CS_By_HTTP ###"
    return(http_server_count_df, http_host_count_df, http_user_agent_count_df, cs_http_df)

def get_content_type_by_http(content_type_file_path, http_df, ip_version):
    print "### start Get_Content_Type_By_HTTP ###"
    content_type_file = open(content_type_file_path, 'r')
    temp_list = []
    temp_list.append(content_type_file.read())
    str_list = temp_list[0].split(', \n')
    str2_list = []
    content_type_list = []
    for i in range(0, len(str_list)):
        str2_list.append(str_list[i][str_list[i].find('.'):len(str_list[i]) - 1])
        content_type_list.append(
            [str2_list[i][str2_list[i].find("\'") + 4:len(str2_list[i])], str2_list[i][0:str2_list[i].find("\'")]])
    content_type_dict = dict(content_type_list)
    #content_type_key_list = content_type_dict.keys()
    #print(content_type_list)
    #print(content_type_dict)
    content_type_file.close()

    cont_type_df = http_df.select("CONT_TYPE")
    #cont_type_list = cont_type_df.rdd.map(lambda row: row.CONT_TYPE).collect()
    cont_type_list = []
    if os.path.exists("E:\\tempfile\\ip6_cont_type_file"):
        files = os.listdir("E:\\tempfile\\ip6_cont_type_file")
        for afile in files:
            os.remove("E:\\tempfile\\ip6_cont_type_file\\" + afile)
        os.rmdir("E:\\tempfile\\ip6_cont_type_file")
    if os.path.exists("E:\\tempfile\\ip4_cont_type_file"):
        files = os.listdir("E:\\tempfile\\ip4_cont_type_file")
        for afile in files:
            os.remove("E:\\tempfile\\ip4_cont_type_file\\" + afile)
        os.rmdir("E:\\tempfile\\ip4_cont_type_file")
    if ip_version == 6:
        cont_type_df.rdd.map(lambda row: row.CONT_TYPE).repartition(1).saveAsTextFile("E:\\tempfile\\ip6_cont_type_file")
        f = open("E:\\tempfile\\ip6_cont_type_file\\part-00000", "r")
    else:
        cont_type_df.rdd.map(lambda row: row.CONT_TYPE).repartition(1).saveAsTextFile("E:\\tempfile\\ip4_cont_type_file")
        f = open("E:\\tempfile\\ip4_cont_type_file\\part-00000", "r")
    while 1:
        lines = f.readlines(10000)
        if not lines:
            break
        for line in lines:
            cont_type_list.append(line[:-1])
    # print(cont_type_list)

    file_list = []
    total_list = [{"none_total": 0, "text_total": 0, "java_total": 0, "image_total": 0, "audio_total": 0, \
                   "video_total": 0, "Model_total": 0, "drawing_total": 0, "message_total": 0, "application_total": 0}]
    for cont_type_element in cont_type_list:
        if str(cont_type_element)[0:4] == "None":

            total_list[0]["none_total"] += 1
            file_list.append("none")

        elif str(cont_type_element)[0:4] == "text":

            total_list[0]["text_total"] += 1
            if content_type_dict.has_key(cont_type_element):
                file_list.append(content_type_dict.get(cont_type_element))
            else:
                file_list.append("other text class")

        elif str(cont_type_element)[0:4] == "java":

            total_list[0]["java_total"] += 1
            if content_type_dict.has_key(cont_type_element):
                file_list.append(content_type_dict.get(cont_type_element))
            else:
                file_list.append("other java class")

        elif str(cont_type_element)[0:5] == "image":

            total_list[0]["image_total"] += 1
            if content_type_dict.has_key(cont_type_element):
                file_list.append(content_type_dict.get(cont_type_element))
            else:
                file_list.append("other image class")

        elif str(cont_type_element)[0:5] == "audio":

            total_list[0]["audio_total"] += 1
            if content_type_dict.has_key(cont_type_element):
                file_list.append(content_type_dict.get(cont_type_element))
            else:
                file_list.append("other audio class")

        elif str(cont_type_element)[0:5] == "video":

            total_list[0]["video_total"] += 1
            if content_type_dict.has_key(cont_type_element):
                file_list.append(content_type_dict.get(cont_type_element))
            else:
                file_list.append("other video class")

        elif str(cont_type_element)[0:5] == "model":

            total_list[0]["model_total"] += 1
            if content_type_dict.has_key(cont_type_element):
                file_list.append(content_type_dict.get(cont_type_element))
            else:
                file_list.append("other model class")

        elif str(cont_type_element)[0:7] == "drawing":

            total_list[0]["drawing_total"] += 1
            if content_type_dict.has_key(cont_type_element):
                file_list.append(content_type_dict.get(cont_type_element))
            else:
                file_list.append("other drawing class")
        elif str(cont_type_element)[0:7] == "message":

            total_list[0]["message_total"] += 1
            if content_type_dict.has_key(cont_type_element):
                file_list.append(content_type_dict.get(cont_type_element))
            else:
                file_list.append("other message class")

        elif str(cont_type_element)[0:11] == "application":

            total_list[0]["application_total"] += 1
            if content_type_dict.has_key(cont_type_element):
                file_list.append(content_type_dict.get(cont_type_element))
            else:
                file_list.append("other application class")
        else:
            file_list.append("can't match")
    #print(file_list)

    #print(total_list)

    total_RDD = sc.parallelize(total_list)
    total_cont_type_df = spark.read.json(total_RDD)
    #total_cont_type_df.show()

    cont_type_file_list = []
    for (cont_type_element, file_element) in zip(cont_type_list, file_list):
        cont_type_file_list.append([cont_type_element, file_element])
    #print(cont_type_file_list)

    cont_type_file_RDD = sc.parallelize(cont_type_file_list)
    cont_type_file_df = spark.createDataFrame(cont_type_file_RDD, ["content_type", "extend_name"])
    cont_type_file_count_df = cont_type_file_df.groupBy("content_type", "extend_name").count().sort("count")
    #cont_type_file_count_df.show()
    print "### finish running Get_Content_Type_By_HTTP ###"
    return(total_cont_type_df, cont_type_file_count_df)

def get_certificate_by_ssl(ssl_df, ip_version):
    print "### start Get_Certificate_By_SSL ###"
    if ip_version == 6:
        ssl_cert_detail_df = spark.sql("SELECT * FROM SSL_All WHERE cert_detail is not null")
    else:
        ssl_cert_detail_df = spark.sql("SELECT * FROM IPv4_SSL_All WHERE cert_detail is not null")
    ssl_certificate_df = ssl_cert_detail_df.select("cert_detail.cert.version", "cert_detail.cert.AlgID", \
                                                   "cert_detail.cert.SerialNum", "cert_detail.cert.Issuer", \
                                                   "cert_detail.cert.Subject", "cert_detail.cert.From", \
                                                   "cert_detail.cert.To").distinct()
    #ssl_certificate_df.show()

    ssl_certificate_issuer_count_df = ssl_certificate_df.groupBy("Issuer").count()
    print "### finish running Get_Certificate_By_SSL ###"
    return(ssl_certificate_df, ssl_certificate_issuer_count_df)

def get_version_by_ssl(ssl_df, ip_version):
    print "### start Get_Version_By_SSL ###"
    if ip_version == 6:
        ssl_client_df = spark.sql("SELECT * FROM SSL_ALL WHERE client is not null")
        ssl_server_df = spark.sql("SELECT * FROM SSL_ALL WHERE server is not null")
    else:
        ssl_client_df = spark.sql("SELECT * FROM IPv4_SSL_ALL WHERE client is not null")
        ssl_server_df = spark.sql("SELECT * FROM IPv4_SSL_ALL WHERE server is not null")
    ssl_client_record_version_df = ssl_client_df.groupBy("client.record_version").count()
    ssl_client_client_version_df = ssl_client_df.groupBy("client.client_version").count()
    ssl_server_record_version_df = ssl_server_df.groupBy("server.record_version").count()
    ssl_server_client_version_df = ssl_server_df.groupBy("server.client_version").count()

    print "### finish running Get_Version_By_SSL ###"
    return ssl_client_record_version_df, ssl_client_client_version_df, ssl_server_record_version_df, ssl_server_client_version_df

def get_teredo_by_udp(teredo_df):
    print "### start Get_Teredo_By_UDP ###"
    teredo_df = spark.sql("SELECT * FROM TEREDO WHERE teredo is not null")

    teredo_total_df = teredo_df.groupBy("teredo").count().select("count").withColumnRenamed("count", "teredo")
    #teredo_total_df.show()
    print "### finish running Get_Teredo_By_UDP ###"
    return teredo_total_df

def get_ip9_tunnel(ip9_tunnel_df):
    print "### start Get_Ip9_Tunnel ###"
    tunnel_6to4_df = spark.sql("SELECT * FROM IP9 WHERE 6to4 is not null")
    tunnel_6in4_df = spark.sql("SELECT * FROM IP9 WHERE 6in4 is not null")
    tunnel_6over4_df = spark.sql("SELECT * FROM IP9 WHERE 6over4 is not null")
    tunnel_6to4_total_df = tunnel_6to4_df.groupBy("6to4").count().select("count").withColumnRenamed("count", "6to4")
    tunnel_6in4_total_df = tunnel_6in4_df.groupBy("6in4").count().select("count").withColumnRenamed("count", "6in4")
    tunnel_6over4_total_df = tunnel_6over4_df.groupBy("6over4").count().select("count").withColumnRenamed("count", "6over4")
    print "### finish running Get_Ip9_Tunnel ###"
    return tunnel_6to4_total_df, tunnel_6in4_total_df, tunnel_6over4_total_df


def get_tunnel_by_all(dns_df, ssl_df, http_df):
    print "### start Get_Tunnel_By_All ###"
    total_dns_tunnel_list = [[0, 0, 0]]
    total_ssl_tunnel_list = [[0, 0, 0]]
    total_http_tunnel_list = [[0, 0, 0]]

    tunnel_dns_df = spark.sql("SELECT * FROM IP9_DNS WHERE sip is null")
    #tunnel_dns_df.show()
    if str(dns_df.rdd.collect()).find("6in4=") != -1:
        tunnel_dns_6in4_df = spark.sql("SELECT * FROM IP9_DNS WHERE 6in4 is not null")
        #tunnel_dns_6in4_df.describe().show()
        total_dns_tunnel_list[0][0] = str(tunnel_dns_6in4_df.describe().rdd.map(lambda row: row[2]).collect()[0])
        #tunnel_dns_6in4_df.show()
        tunnel_dns_df = tunnel_dns_df.union(tunnel_dns_6in4_df)
    if str(dns_df.rdd.collect()).find("6to4=") != -1:
        tunnel_dns_6to4_df = spark.sql("SELECT * FROM IP9_DNS WHERE 6to4 is not null")
        total_dns_tunnel_list[0][1] = str(tunnel_dns_6to4_df.describe().rdd.map(lambda row: row[2]).collect()[0])
        #tunnel_dns_6to4_df.describe().show()
        #tunnel_dns_6to4_df.show()
        tunnel_dns_df = tunnel_dns_df.union(tunnel_dns_6to4_df)
    if str(dns_df.rdd.collect()).find("6over4=") != -1:
        tunnel_dns_6over4_df = spark.sql("SELECT * FROM IP9_DNS WHERE 6over4 is not null")
        total_dns_tunnel_list[0][2] = str(tunnel_dns_6over4_df.describe().rdd.map(lambda row: row[2]).collect()[0])
        #tunnel_dns_6over4_df.describe().show()
        #tunnel_dns_6over4_df.show()
        tunnel_dns_df = tunnel_dns_df.union(tunnel_dns_6over4_df)
    #if str(dns_df.rdd.collect()).find("teredo=") != -1:
    #    tunnel_dns_teredo_df = spark.sql("SELECT * FROM DNS_All WHERE teredo is not null")
    #    total_dns_tunnel_list[0][3] = str(tunnel_dns_teredo_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_dns_teredo_df.show()
    #    tunnel_dns_df = tunnel_dns_df.union(tunnel_dns_teredo_df)
    #if str(dns_df.rdd.collect()).find("ISATAP=") != -1:
    #    tunnel_dns_ISATAP_df = spark.sql("SELECT * FROM DNS_All WHERE ISATAP is not null")
    #    total_dns_tunnel_list[0][4] = str(tunnel_dns_ISATAP_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_dns_ISATAP_df.show()
    #    tunnel_dns_df = tunnel_dns_df.union(tunnel_dns_ISATAP_df)
    #if str(dns_df.rdd.collect()).find("GRE=") != -1:
    #    tunnel_dns_GRE_df = spark.sql("SELECT * FROM DNS_All WHERE GRE is not null")
    #    total_dns_tunnel_list[0][5] = str(tunnel_dns_GRE_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_dns_GRE_df.show()
    #    tunnel_dns_df = tunnel_dns_df.union(tunnel_dns_GRE_df)

    #tunnel_dns_df.show()

    tunnel_ssl_df = spark.sql("SELECT * FROM IP9_SSL WHERE sip is null")
    #tunnel_ssl_df.show()
    if str(ssl_df.rdd.collect()).find("6in4=") != -1:
        tunnel_ssl_6in4_df = spark.sql("SELECT * FROM IP9_SSL WHERE 6in4 is not null")
        total_ssl_tunnel_list[0][0] = str(tunnel_ssl_6in4_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_ssl_6in4_df.show()
        tunnel_ssl_df = tunnel_ssl_df.union(tunnel_ssl_6in4_df)
    if str(ssl_df.rdd.collect()).find("6to4=") != -1:
        tunnel_ssl_6to4_df = spark.sql("SELECT * FROM IP9_SSL WHERE 6to4 is not null")
        total_ssl_tunnel_list[0][1] = str(tunnel_ssl_6to4_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_ssl_6to4_df.show()
        tunnel_ssl_df = tunnel_ssl_df.union(tunnel_ssl_6to4_df)
    if str(ssl_df.rdd.collect()).find("6over4=") != -1:
        tunnel_ssl_6over4_df = spark.sql("SELECT * FROM IP9_SSL WHERE 6over4 is not null")
        total_ssl_tunnel_list[0][2] = str(tunnel_ssl_6over4_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_ssl_6over4_df.show()
        tunnel_ssl_df = tunnel_ssl_df.union(tunnel_ssl_6over4_df)
    #if str(ssl_df.rdd.collect()).find("teredo=") != -1:
    #    tunnel_ssl_teredo_df = spark.sql("SELECT * FROM IP9_SSL WHERE teredo is not null")
    #    total_ssl_tunnel_list[0][3] = str(tunnel_ssl_teredo_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_ssl_teredo_df.show()
    #    tunnel_ssl_df = tunnel_ssl_df.union(tunnel_ssl_teredo_df)
    #if str(ssl_df.rdd.collect()).find("ISATAP=") != -1:
    #    tunnel_ssl_ISATAP_df = spark.sql("SELECT * FROM IP9_SSL WHERE ISATAP is not null")
    #    total_ssl_tunnel_list[0][4] = str(tunnel_ssl_ISATAP_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_ssl_ISATAP_df.show()
    #    tunnel_ssl_df = tunnel_ssl_df.union(tunnel_ssl_ISATAP_df)
    #if str(ssl_df.rdd.collect()).find("GRE=") != -1:
    #    tunnel_ssl_GRE_df = spark.sql("SELECT * FROM IP9_SSL WHERE GRE is not null")
    #    total_ssl_tunnel_list[0][5] = str(tunnel_ssl_GRE_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_ssl_GRE_df.show()
    #    tunnel_ssl_df = tunnel_ssl_df.union(tunnel_ssl_GRE_df)

    #tunnel_ssl_df.show()

    tunnel_http_df = spark.sql("SELECT * FROM IP9_HTTP WHERE sip is null")

    if str(http_df.rdd.collect()).find("6in4=") != -1:
        tunnel_http_6in4_df = spark.sql("SELECT * FROM IP9_HTTP WHERE 6in4 is not null")
        total_http_tunnel_list[0][0] = str(tunnel_http_6in4_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_http_6in4_df.show()
        tunnel_http_df = tunnel_http_df.union(tunnel_http_6in4_df)
    if str(http_df.rdd.collect()).find("6to4=") != -1:
        tunnel_http_6to4_df = spark.sql("SELECT * FROM IP9_HTTP WHERE 6to4 is not null")
        total_http_tunnel_list[0][1] = str(tunnel_http_6to4_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_http_6to4_df.show()
        tunnel_http_df = tunnel_http_df.union(tunnel_http_6to4_df)
    if str(http_df.rdd.collect()).find("6over4=") != -1:
        tunnel_http_6over4_df = spark.sql("SELECT * FROM IP9_HTTP WHERE 6over4 is not null")
        total_http_tunnel_list[0][2] = str(tunnel_http_6over4_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_http_6over4_df.show()
        tunnel_http_df = tunnel_http_df.union(tunnel_http_6over4_df)
    #if str(http_df.rdd.collect()).find("teredo=") != -1:
    #    tunnel_http_teredo_df = spark.sql("SELECT * FROM IP9_HTTP WHERE teredo is not null")
    #    total_http_tunnel_list[0][3] = str(tunnel_http_teredo_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_http_teredo_df.show()
    #    tunnel_http_df = tunnel_http_df.union(tunnel_http_teredo_df)
    #if str(http_df.rdd.collect()).find("ISATAP=") != -1:
    #    tunnel_http_ISATAP_df = spark.sql("SELECT * FROM IP9_HTTP WHERE ISATAP is not null")
    #    total_http_tunnel_list[0][4] = str(tunnel_http_ISATAP_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_http_ISATAP_df.show()
    #    tunnel_http_df = tunnel_http_df.union(tunnel_http_ISATAP_df)
    #if str(http_df.rdd.collect()).find("GRE=") != -1:
    #    tunnel_http_GRE_df = spark.sql("SELECT * FROM IP9_HTTP WHERE GRE is not null")
    #    total_http_tunnel_list[0][5] = str(tunnel_http_GRE_df.describe().rdd.map(lambda row: row[1]).collect()[0])
        #tunnel_http_GRE_df.show()
    #    tunnel_http_df = tunnel_http_df.union(tunnel_http_GRE_df)

    #tunnel_http_df.show()
    #print(total_dns_tunnel_list,total_ssl_tunnel_list,total_http_tunnel_list)

    total_tunnel_list = [[0, 0, 0]]
    for i in range(0, 2):
        total_tunnel_list[0][i] = int(total_dns_tunnel_list[0][i]) + int(total_ssl_tunnel_list[0][i]) + int(total_http_tunnel_list[0][i])
        total_tunnel_list[0][i] = str(total_tunnel_list[0][i])

    total_dns_tunnel_RDD = sc.parallelize(total_dns_tunnel_list)
    total_ssl_tunnel_RDD = sc.parallelize(total_ssl_tunnel_list)
    total_http_tunnel_RDD = sc.parallelize(total_http_tunnel_list)
    total_tunnel_RDD = sc.parallelize(total_tunnel_list)
    total_dns_tunnel_df = spark.createDataFrame(total_dns_tunnel_RDD, ["6in4", "6to4", "6over4"])
    total_ssl_tunnel_df = spark.createDataFrame(total_ssl_tunnel_RDD, ["6in4", "6to4", "6over4"])
    total_http_tunnel_df = spark.createDataFrame(total_http_tunnel_RDD, ["6in4", "6to4", "6over4"])
    total_tunnel_df = spark.createDataFrame(total_tunnel_RDD, ["6in4", "6to4", "6over4"])

    #total_dns_tunnel_df.show()
    #total_ssl_tunnel_df.show()
    #total_http_tunnel_df.show()
    #total_tunnel_df.show()
    print "### finish running Get_Tunnel_By_All ###"
    return(total_dns_tunnel_df, total_ssl_tunnel_df, total_http_tunnel_df, total_tunnel_df)

def get_detail_by_all(dns_df, ssl_df, http_df, ip_version):
    print "### start Get_Detail_By_All ###"
    if ip_version == 6:
        total_dns_df = spark.sql("SELECT count(1) from DNS_All").withColumnRenamed("count(1)", "dns_num")
        total_ssl_df = spark.sql("SELECT count(1) from SSL_All").withColumnRenamed("count(1)", "ssl_num")
        total_http_df = spark.sql("SELECT count(1) from HTTP_All").withColumnRenamed("count(1)", "http_num")
    else:
        total_dns_df = spark.sql("SELECT count(1) from IPv4_DNS_All").withColumnRenamed("count(1)", "dns_num")
        total_ssl_df = spark.sql("SELECT count(1) from IPv4_SSL_All").withColumnRenamed("count(1)", "ssl_num")
        total_http_df = spark.sql("SELECT count(1) from IPv4_HTTP_All").withColumnRenamed("count(1)", "http_num")
    dns_num = total_dns_df.rdd.map(lambda row: row[0]).take(1)[0]
    ssl_num = total_ssl_df.rdd.map(lambda row: row[0]).take(1)[0]
    http_num = total_http_df.rdd.map(lambda row: row[0]).take(1)[0]
    all_detail_list = [[dns_num, ssl_num, http_num]]
    all_detail_RDD = sc.parallelize(all_detail_list)
    all_detail_df = spark.createDataFrame(all_detail_RDD, ["dns_num", "ssl_num", "http_num"])
    #all_detail_df.show()
    print "### finish running Get_Detail_By_All ###"

def get_detail_by_tcp_udp(port_file_path, tcp_udp_df, ip_version):
    print "### start Get_Detail_By_TCP_UDP ###"
    port_file = open(port_file_path, 'r')
    temp_list = []
    temp_list.append(port_file.read())
    port_file.close()
    str_list = temp_list[0].split('\n')

    port_list = []
    for i in range(0, len(str_list)):
        port_list.append([str_list[i][0:str_list[i].find('\t')], str_list[i][str_list[i].find('\t')+1:len(str_list[i])]])
    port_dict = dict(port_list)
    #print(port_dict)

    tcp_udp_dport_df = tcp_udp_df.select("dport")
    #dport_list = tcp_udp_dport_df.rdd.map(lambda row: row.dport).collect()
    dport_list = []
    if os.path.exists("E:\\tempfile\\ip6_dport_file"):
        files = os.listdir("E:\\tempfile\\ip6_dport_file")
        for afile in files:
            os.remove("E:\\tempfile\\ip6_dport_file\\" + afile)
        os.rmdir("E:\\tempfile\\ip6_dport_file")
    if os.path.exists("E:\\tempfile\\ip4_dport_file"):
        files = os.listdir("E:\\tempfile\\ip4_dport_file")
        for afile in files:
            os.remove("E:\\tempfile\\ip4_dport_file\\" + afile)
        os.rmdir("E:\\tempfile\\ip4_dport_file")
    if ip_version == 6:
        tcp_udp_dport_df.rdd.map(lambda row: row.dport).repartition(1).saveAsTextFile("E:\\tempfile\\ip6_dport_file")
        f = open("E:\\tempfile\\ip6_dport_file\\part-00000", "r")
    else:
        tcp_udp_dport_df.rdd.map(lambda row: row.dport).repartition(1).saveAsTextFile("E:\\tempfile\\ip4_dport_file")
        f = open("E:\\tempfile\\ip4_dport_file\\part-00000", "r")
    while 1:
        lines = f.readlines(10000)
        if not lines:
            break
        for line in lines:
            dport_list.append(line[:-1])

    #print dport_list

    protocol_list = []

    for dport in dport_list:
        if port_dict.has_key(str(dport)):
            protocol_list.append({"protocol": port_dict.get(str(dport))})
        else:
            protocol_list.append({"protocol": "no protocol"})
    #print protocol_list

    protocol_RDD = sc.parallelize(protocol_list)
    protocol_df = spark.read.json(protocol_RDD)
    #protocol_df.show()
    protocol_count_df = protocol_df.groupBy("protocol").count().sort("count")
    print "### finish running Get_Detail_By_TCP_UDP ###"
    return(protocol_count_df)

def get_tor_meek_by_ssl(ssl_df):
    print "### start Get_Tor_Meek_By_SSL ###"
    ssl_select_df = ssl_df.select("sip", "dip", "sport", "dport", "client.host", "client.ciphersuites",  \
                                  "client.extension.length", "client.extension.num", "client.extension.type")
    ssl_select_df.createOrReplaceTempView("SSL_SELECT")
    ssl_select_host_df = spark.sql("select * from SSL_SELECT where host = 'a0.awsstatic.com' or host = 'ajax.aspnetcdn.com' \
and length = 117 or length = 119 and num =10")
    ssl_select_host_df.createOrReplaceTempView("SSL_SELECT_HOST")
    tor_meek_df = spark.sql("select * from SSL_SELECT_HOST where ciphersuites[0] = 'c02b' and ciphersuites[1] = 'c02f' and  \
ciphersuites[2] = 'cca9' and ciphersuites[3] = 'cca8' and ciphersuites[4] = 'c02c' and ciphersuites[5] = 'c030' and \
ciphersuites[6] = 'c00a' and ciphersuites[7] = 'c009' and ciphersuites[8] = 'c013' and ciphersuites[9] = 'c014' and  \
ciphersuites[10] = '0033' and ciphersuites[11] = '0039' and ciphersuites[12] = '002f' and ciphersuites[13] = '0035' and ciphersuites[14] = '000a' \
and type[0] = '0000' and type[1] = '0017' and type[2] = 'ff01' and type[3] = '000a' and type[4] = '000b' and \
type[5] = '0023' and type[6] = '0010' and type[7] = '0005' and type[8] = 'ff03' and type[9] = '000d'")
    #tor_meek_df.show()
    tor_meek_ip_list = tor_meek_df.rdd.map(lambda row: row.dip).collect()
    print "### finish running Get_Tor_Meek_By_SSL ###"
    print tor_meek_ip_list

def json_output(df):
    #json_list = spark.sql("select * from TEST_ALL").toJSON().collect()
    json_list = df.toJSON().collect()
    print json_list
    json_file = open("json_file", "w")
    for element in json_list:
        json_file.write(str(element))
    json_file.close()

def combine_file(ip_version):
    print "### start Combine_File ###"
    if ip_version == 6:
        filedir = "E:\\ipv6"
        protocol_dirs = os.listdir(filedir)
        print protocol_dirs
        for protocol_dir in protocol_dirs:
            print protocol_dir
            date_dirs = os.listdir(filedir + "\\" + protocol_dir)
            print date_dirs
            for date_dir in date_dirs:
                if protocol_dir == "http":
                    if date_dir == "20180322":
                        filenames = os.listdir(filedir + "\\" + protocol_dir + "\\" + date_dir)
                        f = open("ipv6_" + protocol_dir + "_" + date_dir + "_all", "w")
                        for filename in filenames:
                            file_path = filedir + "\\" + protocol_dir + "\\" + date_dir + "\\" + filename
                            for line in open(file_path):
                                if line.count("CONT_TYPE") == 2:
                                    index = line.rfind("CONT_TYPE")
                                    line = line[0:index] + "RES_CONT_TYPE" + line[index + 9:]
                                if line.count("VIA") == 2:
                                    index = line.rfind("VIA")
                                    line = line[0:index] + "RES_VIA" + line[index + 4:]
                                if line.count("DATE") == 2:
                                    index = line.rfind("DATE")
                                    line = line[0:index] + "RES_DATE" + line[index + 5:]
                                if line.count("User_Agent") == 2:
                                    index = line.rfind("User_Agent")
                                    line = line[0:index] + "RES_User_Agent" + line[index + 11:]
                                if line.count("COOKIE") == 2:
                                    index = line.rfind("COOKIE")
                                    line = line[0:index] + "RES_COOKIE" + line[index + 7:]
                                f.writelines(line)
                        f.close()
    elif ip_version == 4:
        filedir = "E:\\ipv4"
        protocol_dirs = os.listdir(filedir)
        print protocol_dirs
        for protocol_dir in protocol_dirs:
            print protocol_dir
            date_dirs = os.listdir(filedir + "\\" + protocol_dir)
            print date_dirs
            for date_dir in date_dirs:
                filenames = os.listdir(filedir + "\\" + protocol_dir + "\\" + date_dir)
                f = open("ipv4_" + protocol_dir + "_" + date_dir + "_all", "w")
                for filename in filenames:
                    file_path = filedir + "\\" + protocol_dir + "\\" + date_dir + "\\" + filename
                    for line in open(file_path):
                        if line.count("CONT_TYPE") == 2:
                            index = line.rfind("CONT_TYPE")
                            line = line[0:index] + "RES_CONT_TYPE" + line[index + 9:]
                        if line.count("VIA") == 2:
                            index = line.rfind("VIA")
                            line = line[0:index] + "RES_VIA" + line[index + 4:]
                        if line.count("DATE") == 2:
                            index = line.rfind("DATE")
                            line = line[0:index] + "RES_DATE" + line[index + 5:]
                        if line.count("User_Agent") == 2:
                            index = line.rfind("User_Agent")
                            line = line[0:index] + "RES_User_Agent" + line[index + 11:]
                        if line.count("COOKIE") == 2:
                            index = line.rfind("COOKIE")
                            line = line[0:index] + "RES_COOKIE" + line[index + 7:]
                        f.writelines(line)
                f.close()
    elif ip_version == 9:
        filedir = "E:\\ip9"
        protocol_dirs = os.listdir(filedir)
        print protocol_dirs
        for protocol_dir in protocol_dirs:
            print protocol_dir
            date_dirs = os.listdir(filedir + "\\" + protocol_dir)
            print date_dirs
            for date_dir in date_dirs:
                filenames = os.listdir(filedir + "\\" + protocol_dir + "\\" + date_dir)
                f = open("ip9_" + protocol_dir + "_" + date_dir + "_all", "w")
                for filename in filenames:
                    file_path = filedir + "\\" + protocol_dir + "\\" + date_dir + "\\" + filename
                    for line in open(file_path):
                        if line.count("CONT_TYPE") == 2:
                            index = line.rfind("CONT_TYPE")
                            line = line[0:index] + "RES_CONT_TYPE" + line[index + 9:]
                        if line.count("VIA") == 2:
                            index = line.rfind("VIA")
                            line = line[0:index] + "RES_VIA" + line[index + 4:]
                        if line.count("DATE") == 2:
                            index = line.rfind("DATE")
                            line = line[0:index] + "RES_DATE" + line[index + 5:]
                        if line.count("User_Agent") == 2:
                            index = line.rfind("User_Agent")
                            line = line[0:index] + "RES_User_Agent" + line[index + 11:]
                        if line.count("COOKIE") == 2:
                            index = line.rfind("COOKIE")
                            line = line[0:index] + "RES_COOKIE" + line[index + 7:]
                        f.writelines(line)
                f.close()
    print "### finish running Combine_File ###"

def draw_ip_count(df, ip_version):
    ip_count = df.toPandas()
    ip_count = ip_count.sort_values("count", ascending=False)[:25]
    bar_chart = pygal.Bar(width=800, height=600, legend_at_bottom=True, human_readable=True)
    if ip_version == 6:
        bar_chart.title = "IPv6 Address Count Bar Chart"
        for index, row in ip_count.iterrows():
            bar_chart.add(row["ip"], row["count"])
        bar_chart.render_to_file("IPv6 Address Count Bar Chart.svg")
    else:
        bar_chart.title = "IPv4 Address Count Bar Chart"
        for index, row in ip_count.iterrows():
            bar_chart.add(row["ip"], row["count"])
        bar_chart.render_to_file("IPv4 Address Count Bar Chart.svg")

def draw_ipv6_geoip(geo_count_df, geo_total_df):
    geoip = geo_count_df.toPandas()
    dark_lighten_style = LightenStyle('#004466')
    worldmap_chart = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic', human_readable=True)
    worldmap_chart.title = "IPv6 World Geographic Distribution Address Count in World Map Chart"
    geo_count_dict = {}
    for index, row in geoip.iterrows():
        geo_count_dict[row["country_code"]] = row["count"]
    worldmap_chart.add("IPv6", geo_count_dict)
    worldmap_chart.render_to_file("IPv6 World Geographic Distribution Address Count in World Map Chart.svg")

    geo_total = geo_total_df.toPandas()
    worldmap_chart_total = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic',
                                            human_readable=True)
    worldmap_chart_total.title = "IPv6 World Geographic Distribution Packets Count in World Map Chart"
    geo_total_count_dict = {}
    for index, row in geo_total.iterrows():
        geo_total_count_dict[row["country_code"]] = row["sum(count)"]
    print(geo_total_count_dict)
    worldmap_chart_total.add("IPv6 Packets", geo_total_count_dict)
    worldmap_chart_total.render_to_file("IPv6 World Geographic Distribution Packets Count in World Map Chart.svg")

def draw_ipv4_geoip(ipv4_geo_count_df, ipv4_geo_total_df):

    ipv4_geoip = ipv4_geo_count_df.toPandas()
    dark_lighten_style = LightenStyle('#004466')
    worldmap_chart = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic', human_readable=True)
    worldmap_chart.title = "IPv4 World Geographic Distribution Address Count in World Map Chart"
    ipv4_geo_count_dict = {}
    for index, row in ipv4_geoip.iterrows():
        ipv4_geo_count_dict[row["country_code"]] = row["count"]
    worldmap_chart.add("IPv4", ipv4_geo_count_dict)
    worldmap_chart.render_to_file("IPv4 World Geographic Distribution Address Count in World Map Chart.svg")


    ipv4_geo_total = ipv4_geo_total_df.toPandas()
    worldmap_chart_total = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic',
                                            human_readable=True)
    worldmap_chart_total.title = "IPv4 World Geographic Distribution Packets Count in World Map Chart"
    ipv4_geo_total_count_dict = {}
    for index, row in ipv4_geo_total.iterrows():
        ipv4_geo_total_count_dict[row["country_code"]] = row["sum(count)"]
    print(ipv4_geo_total_count_dict)
    worldmap_chart_total.add("IPv4 Packets", ipv4_geo_total_count_dict)
    worldmap_chart_total.render_to_file("IPv4 World Geographic Distribution Packets Count in World Map Chart.svg")

def draw_geo_stack_server(geo4_count_df, geo6_count_df, geodual_count_df, ip_version):
    if ip_version == 6:

        geo4 = geo4_count_df.toPandas()
        dark_lighten_style = LightenStyle('#004466')
        worldmap_chart = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic',
                                                human_readable=True)
        worldmap_chart.title = "IPv4 Server Count Accessing By IPv6 in World Map Chart"
        geo_count_dict = {}
        for index, row in geo4.iterrows():
            geo_count_dict[row["country_code"]] = row["count"]
        worldmap_chart.add("IPv4", geo_count_dict)
        worldmap_chart.render_to_file("IPv4 Server Count Accessing By IPv6 in World Map Chart.svg")

        geo6 = geo6_count_df.toPandas()
        dark_lighten_style = LightenStyle('#004466')
        worldmap_chart = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic',
                                                human_readable=True)
        worldmap_chart.title = "IPv6 Server Count Accessing By IPv6 in World Map Chart"
        geo_count_dict = {}
        for index, row in geo6.iterrows():
            geo_count_dict[row["country_code"]] = row["count"]
        worldmap_chart.add("IPv6", geo_count_dict)
        worldmap_chart.render_to_file("IPv6 Server Count Accessing By IPv6 in World Map Chart.svg")

        if geodual_count_df != 0:
            geodual = geodual_count_df.toPandas()
            dark_lighten_style = LightenStyle('#004466')
            worldmap_chart = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic',
                                                    human_readable=True)
            worldmap_chart.title = "Dual Stack Server Count Accessing By IPv6 in World Map Chart"
            geo_count_dict = {}
            for index, row in geodual.iterrows():
                geo_count_dict[row["country_code"]] = row["count"]
            worldmap_chart.add("Dual Stack", geo_count_dict)
            worldmap_chart.render_to_file("Dual Stack Server Count Accessing By IPv6 in World Map Chart.svg")

    else:
        geo4 = geo4_count_df.toPandas()
        dark_lighten_style = LightenStyle('#004466')
        worldmap_chart = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic',
                                                human_readable=True)
        worldmap_chart.title = "IPv4 Server Count Accessing By IPv4 in World Map Chart"
        geo_count_dict = {}
        for index, row in geo4.iterrows():
            geo_count_dict[row["country_code"]] = row["count"]
        worldmap_chart.add("IPv4", geo_count_dict)
        worldmap_chart.render_to_file("IPv4 Server Count Accessing By IPv4 in World Map Chart.svg")

        geo6 = geo6_count_df.toPandas()
        dark_lighten_style = LightenStyle('#004466')
        worldmap_chart = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic',
                                                human_readable=True)
        worldmap_chart.title = "IPv6 Server Count Accessing By IPv4 in World Map Chart"
        geo_count_dict = {}
        for index, row in geo6.iterrows():
            geo_count_dict[row["country_code"]] = row["count"]
        worldmap_chart.add("IPv6", geo_count_dict)
        worldmap_chart.render_to_file("IPv6 Server Count Accessing By IPv4 in World Map Chart.svg")

        if geodual_count_df != 0:
            geodual = geodual_count_df.toPandas()
            dark_lighten_style = LightenStyle('#004466')
            worldmap_chart = pygal.maps.world.World(fill=True, style=dark_lighten_style, interpolate='cubic',
                                                    human_readable=True)
            worldmap_chart.title = "Dual Stack Server Count Accessing By IPv4 in World Map Chart"
            geo_count_dict = {}
            for index, row in geodual.iterrows():
                geo_count_dict[row["country_code"]] = row["count"]
            worldmap_chart.add("Dual Stack", geo_count_dict)
            worldmap_chart.render_to_file("Dual Stack Server Count Accessing By IPv4 in World Map Chart.svg")


def draw_geo_lat_lon(total_geo_ip_count_df, ip_version):
    #map = Basemap(projection='stere', lat_0=90, lon_0=-105, \
     #             llcrnrlat=23.41, urcrnrlat=45.44, \
      #            llcrnrlon=-118.67, urcrnrlon=-64.52, \
       #           rsphere=6371200., resolution='l', area_thresh=10000)
    map = Basemap(projection='stere', lat_0=35, lon_0=110, \
                  llcrnrlat=3.01, urcrnrlat=53.123, \
                  llcrnrlon=82.33, urcrnrlon=138.16, \
                  rsphere=6371200., resolution='l', area_thresh=10000)
    map.drawmapboundary()
    #map.fillcontinents()
    map.drawstates()
    map.drawcoastlines()
    map.drawcountries()
    map.drawcounties()
    map.readshapefile("E:\\CHN_adm_shp\\CHN_adm1", 'states', drawbounds=True)

    parallels = np.arange(0., 90, 10.)
    map.drawparallels(parallels, labels=[1, 0, 0, 0], fontsize=10)

    #meridians = np.arange(-110., -60., 10.)
    #map.drawmeridians(meridians, labels=[0, 0, 0, 1], fontsize=10)
    meridians = np.arange(80., 140., 10.)
    map.drawmeridians(meridians, labels=[0, 0, 0, 1], fontsize=10)
    posi = total_geo_ip_count_df.toPandas()
    lat = np.array(posi["latitude"])
    lon = np.array(posi["longitude"])
    count = np.array(posi["count"], dtype=float)

    size = (count/np.max(count))*1000
    x, y = map(lon, lat)

    map.scatter(x, y, s=size)
    if ip_version == 6:
        plt.title("IPv6 Address Position In China")
    else:
        plt.title("IPv4 Address Position In China")
    plt.show()

    map_America = Basemap(projection='stere', lat_0=90, lon_0=-105, \
                 llcrnrlat=23.41, urcrnrlat=45.44, \
                llcrnrlon=-118.67, urcrnrlon=-64.52, \
               rsphere=6371200., resolution='l', area_thresh=10000)
    #map = Basemap(projection='stere', lat_0=35, lon_0=110, \
     #             llcrnrlat=3.01, urcrnrlat=53.123, \
      #            llcrnrlon=82.33, urcrnrlon=138.16, \
       #           rsphere=6371200., resolution='l', area_thresh=10000)
    map_America.drawmapboundary()
    # map.fillcontinents()
    map_America.drawstates()
    map_America.drawcoastlines()
    map_America.drawcountries()
    map_America.drawcounties()
    #map.readshapefile("E:\\CHN_adm_shp\\CHN_adm1", 'states', drawbounds=True)

    parallels = np.arange(0., 90, 10.)
    map_America.drawparallels(parallels, labels=[1, 0, 0, 0], fontsize=10)

    meridians = np.arange(-110., -60., 10.)
    map_America.drawmeridians(meridians, labels=[0, 0, 0, 1], fontsize=10)
    #meridians = np.arange(80., 140., 10.)
    #map.drawmeridians(meridians, labels=[0, 0, 0, 1], fontsize=10)
    #posi = total_geo_ip_count_df.toPandas()
    #lat = np.array(posi["latitude"])
    #lon = np.array(posi["longitude"])
    #count = np.array(posi["count"], dtype=float)

    size = (count / np.max(count)) * 5000
    x, y = map_America(lon, lat)

    map_America.scatter(x, y, s=size)
    if ip_version == 6:
        plt.title("IPv6 Address Position In America")
    else:
        plt.title("IPv4 Address Position In America")
    plt.show()

    map_world = Basemap(projection='mill', llcrnrlat=-90, urcrnrlat=90, \
                        llcrnrlon=-180, urcrnrlon=180, resolution='c')
    map_world.drawcoastlines()
    map_world.drawcountries()

    map_world.drawparallels(np.arange(-90., 91., 30.))
    map_world.drawmeridians(np.arange(-180., 181., 60.))
    map_world.drawmapboundary()
    size = (count / np.max(count)) * 200
    x, y = map_world(lon, lat)

    map_world.scatter(x, y, s=size)
    if ip_version == 6:
        plt.title("IPv6 Address Position In the World")
    else:
        plt.title("IPv4 Address Position In the World")
    plt.show()



def draw_IPv6_dual_stack_count(ipv6_dual_stack_df, ip_version):
    if ipv6_dual_stack_df != 0:
        ipv6_dual_stack_count_df = ipv6_dual_stack_df.groupBy("name").count()
        dual_stack = ipv6_dual_stack_count_df.toPandas()
        dual_stack = dual_stack.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        if ip_version == 6:
            bar_chart.title = "IPv6 Dual Stack Count Bar Chart"
            for index, row in dual_stack.iterrows():
                bar_chart.add(row["name"], row["count"])
            bar_chart.render_to_file("IPv6 Dual Stack Count Bar Chart.svg")
        else:
            bar_chart.title = "IPv4 Dual Stack Count Bar Chart"
            for index, row in dual_stack.iterrows():
                bar_chart.add(row["name"], row["count"])
            bar_chart.render_to_file("IPv4 Dual Stack Count Bar Chart.svg")

def draw_dns_domain_name(cs_queries_count_df, cs_answers_count_df, ip_version):
    dns_queries_domain_name = cs_queries_count_df.toPandas()
    dns_queries_domain_name = dns_queries_domain_name.sort_values("count", ascending=False)[:25]
    bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
    if ip_version == 6:
        bar_chart.title = "IPv6 DNS Queries Domain Name Count Bar Chart"
        for index, row in dns_queries_domain_name.iterrows():
            bar_chart.add(row["name"], row["count"])
        bar_chart.render_to_file("IPv6 DNS Queries Domain Name Count Bar Chart.svg")
    else:
        bar_chart.title = "IPv4 DNS Queries Domain Name Count Bar Chart"
        for index, row in dns_queries_domain_name.iterrows():
            bar_chart.add(row["name"], row["count"])
        bar_chart.render_to_file("IPv4 DNS Queries Domain Name Count Bar Chart.svg")

    dns_answers_domain_name = cs_answers_count_df.toPandas()
    dns_answers_domain_name = dns_answers_domain_name.sort_values("count", ascending=False)[:25]
    bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
    if ip_version == 6:
        bar_chart.title = "IPv6 DNS Answers Domain Name Count Bar Chart"
        for index, row in dns_answers_domain_name.iterrows():
            bar_chart.add(row["name"], row["count"])
        bar_chart.render_to_file("IPv6 DNS Answers Domain Name Count Bar Chart.svg")
    else:
        bar_chart.title = "IPv4 DNS Answers Domain Name Count Bar Chart"
        for index, row in dns_answers_domain_name.iterrows():
            bar_chart.add(row["name"], row["count"])
        bar_chart.render_to_file("IPv4 DNS Answers Domain Name Count Bar Chart.svg")

def draw_dns_detail(ip_version):
    if ip_version == 6:
        query_num = \
        spark.sql("select count(1) from DNS_ALL where query is not null").rdd.map(lambda row: row[0]).collect()[0]
        response_num = \
        spark.sql("select count(1) from DNS_ALL where response is not null").rdd.map(lambda row: row[0]).collect()[0]
        total_num = \
        spark.sql("select count(1) from DNS_ALL").rdd.map(lambda row: row[0]).collect()[0]

        gauge = pygal.SolidGauge(
            half_pie=True, inner_radius=0.70,
            style=pygal.style.styles["default"](value_font_size=10)
        )
        percent_formatter = lambda x: '{:.10g}'.format(x)
        gauge.value_formatter = percent_formatter
        gauge.add("query", [{'value': query_num, 'max_value': total_num}])
        gauge.add("response", [{'value': response_num, 'max_value': total_num}])
        gauge.render_to_file("IPv6 DNS Protocol Detail Rauge.svg")
    else:
        query_num = \
            spark.sql("select count(1) from IPv4_DNS_ALL where query is not null").rdd.map(lambda row: row[0]).collect()[0]
        response_num = \
            spark.sql("select count(1) from IPv4_DNS_ALL where response is not null").rdd.map(lambda row: row[0]).collect()[
                0]
        total_num = \
            spark.sql("select count(1) from IPv4_DNS_ALL").rdd.map(lambda row: row[0]).collect()[0]

        gauge = pygal.SolidGauge(
            half_pie=True, inner_radius=0.70,
            style=pygal.style.styles["default"](value_font_size=10)
        )
        percent_formatter = lambda x: '{:.10g}'.format(x)
        gauge.value_formatter = percent_formatter
        gauge.add("query", [{'value': query_num, 'max_value': total_num}])
        gauge.add("response", [{'value': response_num, 'max_value': total_num}])
        gauge.render_to_file("IPv4 DNS Protocol Detail Rauge.svg")

def draw_ssl_sni(cs_ssl_count_df, ip_version):
    sni = cs_ssl_count_df.toPandas()
    sni = sni.sort_values("count", ascending=False)[:25]
    bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
    if ip_version == 6:
        bar_chart.title = "IPv6 SSL SNI Count Bar Chart"
        for index, row in sni.iterrows():
            bar_chart.add(row["host"], row["count"])
        bar_chart.render_to_file("IPv6 SSL SNI Count Bar Chart.svg")
    else:
        bar_chart.title = "IPv4 SSL SNI Count Bar Chart"
        for index, row in sni.iterrows():
            bar_chart.add(row["host"], row["count"])
        bar_chart.render_to_file("IPv4 SSL SNI Count Bar Chart.svg")

def draw_ssl_certificate(ssl_certificate_df, ssl_certificate_issuer_count_df, ip_version):
    if ip_version == 6:
        ssl_certificate_issuer = ssl_certificate_issuer_count_df.toPandas()
        ssl_certificate_issuer = ssl_certificate_issuer.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 SSL Certificate Issuer Count Bar Chart"
        for index, row in ssl_certificate_issuer.iterrows():
            bar_chart.add(row["Issuer"], row["count"])
        bar_chart.render_to_file("IPv6 SSL Certificate Issuer Count Bar Chart.svg")

        ssl_certificate_time = ssl_certificate_df.toPandas()
        xy_chart = pygal.XY(stroke=False, show_legend=False, human_readable=True)
        xy_chart.title = "IPv6 SSL Certificate Subject Issue Time in XY Chart"
        for index, row in ssl_certificate_time.iterrows():
            xy_chart.add(row["Subject"], [(float(row["From"][0:5].replace("-", ".")), float(row["To"][0:5].replace("-", ".")))])
        xy_chart.render_to_file("IPv6 SSL Certificate Subject Issue Time in XY Chart.svg")
    else:
        ssl_certificate_issuer = ssl_certificate_issuer_count_df.toPandas()
        ssl_certificate_issuer = ssl_certificate_issuer.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 SSL Certificate Issuer Count Bar Chart"
        for index, row in ssl_certificate_issuer.iterrows():
            bar_chart.add(row["Issuer"], row["count"])
        bar_chart.render_to_file("IPv4 SSL Certificate Issuer Count Bar Chart.svg")

        ssl_certificate_time = ssl_certificate_df.toPandas()
        xy_chart = pygal.XY(stroke=False, show_legend=False, human_readable=True)
        xy_chart.title = "IPv4 SSL Certificate Subject Issue Time in XY Chart"
        for index, row in ssl_certificate_time.iterrows():
            xy_chart.add(row["Subject"],
                         [(float(row["From"][0:5].replace("-", ".")), float(row["To"][0:5].replace("-", ".")))])
        xy_chart.render_to_file("IPv4 SSL Certificate Subject Issue Time in XY Chart.svg")

def draw_ssl_version(ssl_client_record_version_df, ssl_client_client_version_df, ssl_server_record_version_df, ssl_server_client_version_df, ip_version):
    ssl_client_client_version = ssl_client_client_version_df.toPandas()
    ssl_server_client_version = ssl_server_client_version_df.toPandas()
    ssl_client_record_version = ssl_client_record_version_df.toPandas()
    ssl_server_record_version = ssl_server_record_version_df.toPandas()
    ssl_client_client_version_dict = {}
    ssl_client_record_version_dict = {}
    ssl_server_client_version_dict = {}
    ssl_server_record_version_dict = {}
    ssl_client_client_version_dict["tls1.0"] = 0
    ssl_client_record_version_dict["tls1.0"] = 0
    ssl_server_client_version_dict["tls1.0"] = 0
    ssl_server_record_version_dict["tls1.0"] = 0
    ssl_client_client_version_dict["tls1.2"] = 0
    ssl_client_record_version_dict["tls1.2"] = 0
    ssl_server_client_version_dict["tls1.2"] = 0
    ssl_server_record_version_dict["tls1.2"] = 0
    ssl_client_client_version_dict["tls1.1"] = 0
    ssl_client_record_version_dict["tls1.1"] = 0
    ssl_server_client_version_dict["tls1.1"] = 0
    ssl_server_record_version_dict["tls1.1"] = 0
    ssl_client_client_version_dict["sslv3"] = 0
    ssl_client_record_version_dict["sslv3"] = 0
    ssl_server_client_version_dict["sslv3"] = 0
    ssl_server_record_version_dict["sslv3"] = 0
    ssl_client_client_version_dict["sslv2"] = 0
    ssl_client_record_version_dict["sslv2"] = 0
    ssl_server_client_version_dict["sslv2"] = 0
    ssl_server_record_version_dict["sslv2"] = 0
    bar_chart = pygal.Bar()
    if ip_version == 6:
        bar_chart.title = "IPv6 SSL Verion in Client and Server Bar Chart"
        bar_chart.x_labels = ["record version in client", "client version in client", "record version in server", "client version in server"]
        for index, row in ssl_client_client_version.iterrows():
            ssl_client_client_version_dict[row["client_version"]] = row["count"]
        for index, row in ssl_client_record_version.iterrows():
            ssl_client_record_version_dict[row["record_version"]] = row["count"]
        for index, row in ssl_server_client_version.iterrows():
            ssl_server_client_version_dict[row["client_version"]] = row["count"]
        for index, row in ssl_server_record_version.iterrows():
            ssl_server_record_version_dict[row["record_version"]] = row["count"]
        print ssl_client_client_version_dict
        print ssl_client_record_version_dict
        print ssl_server_client_version_dict
        print ssl_server_record_version_dict
        bar_chart.add("tls1.0", [ssl_client_record_version_dict["tls1.0"], ssl_client_client_version_dict["tls1.0"], \
                                 ssl_server_record_version_dict["tls1.0"], ssl_server_client_version_dict["tls1.0"]])
        bar_chart.add("tls1.2", [ssl_client_record_version_dict["tls1.2"], ssl_client_client_version_dict["tls1.2"], \
                                 ssl_server_record_version_dict["tls1.2"], ssl_server_client_version_dict["tls1.2"]])
        bar_chart.add("tls1.1", [ssl_client_record_version_dict["tls1.1"], ssl_client_client_version_dict["tls1.1"], \
                                 ssl_server_record_version_dict["tls1.1"], ssl_server_client_version_dict["tls1.1"]])
        bar_chart.add("sslv3", [ssl_client_record_version_dict["sslv3"], ssl_client_client_version_dict["sslv3"], \
                                 ssl_server_record_version_dict["sslv3"], ssl_server_client_version_dict["sslv3"]])
        bar_chart.add("sslv2", [ssl_client_record_version_dict["sslv2"], ssl_client_client_version_dict["sslv2"], \
                                 ssl_server_record_version_dict["sslv2"], ssl_server_client_version_dict["sslv2"]])
        bar_chart.render_to_file("IPv6 SSL Verion in Client and Server Bar Chart.svg")
    else:
        bar_chart.title = "IPv4 SSL Verion in Client and Server Bar Chart"
        bar_chart.x_labels = ["record version in client", "client version in client", "record version in server",
                              "client version in server"]
        for index, row in ssl_client_client_version.iterrows():
            ssl_client_client_version_dict[row["client_version"]] = row["count"]
        for index, row in ssl_client_record_version.iterrows():
            ssl_client_record_version_dict[row["record_version"]] = row["count"]
        for index, row in ssl_server_client_version.iterrows():
            ssl_server_client_version_dict[row["client_version"]] = row["count"]
        for index, row in ssl_server_record_version.iterrows():
            ssl_server_record_version_dict[row["record_version"]] = row["count"]
        print ssl_client_client_version_dict
        print ssl_client_record_version_dict
        print ssl_server_client_version_dict
        print ssl_server_record_version_dict
        bar_chart.add("tls1.0", [ssl_client_record_version_dict["tls1.0"], ssl_client_client_version_dict["tls1.0"], \
                                 ssl_server_record_version_dict["tls1.0"], ssl_server_client_version_dict["tls1.0"]])
        bar_chart.add("tls1.2", [ssl_client_record_version_dict["tls1.2"], ssl_client_client_version_dict["tls1.2"], \
                                 ssl_server_record_version_dict["tls1.2"], ssl_server_client_version_dict["tls1.2"]])
        bar_chart.add("tls1.1", [ssl_client_record_version_dict["tls1.1"], ssl_client_client_version_dict["tls1.1"], \
                                 ssl_server_record_version_dict["tls1.1"], ssl_server_client_version_dict["tls1.1"]])
        bar_chart.add("sslv3", [ssl_client_record_version_dict["sslv3"], ssl_client_client_version_dict["sslv3"], \
                                ssl_server_record_version_dict["sslv3"], ssl_server_client_version_dict["sslv3"]])
        bar_chart.add("sslv2", [ssl_client_record_version_dict["sslv2"], ssl_client_client_version_dict["sslv2"], \
                                ssl_server_record_version_dict["sslv2"], ssl_server_client_version_dict["sslv2"]])
        bar_chart.render_to_file("IPv4 SSL Verion in Client and Server Bar Chart.svg")

def draw_ssl_detail():
    client_num = spark.sql("select count(1) from SSL_ALL where client is not null").rdd.map(lambda row: row[0]).collect()[0]
    server_num = spark.sql("select count(1) from SSL_ALL where server is not null").rdd.map(lambda row: row[0]).collect()[0]
    cert_detail_num = spark.sql("select count(1) from SSL_ALL where cert_detail is not null").rdd.map(lambda row: row[0]).collect()[0]
    total_num = \
        spark.sql("select count(1) from SSL_ALL").rdd.map(lambda row: row[0]).collect()[0]

    ipv4_client_num = \
    spark.sql("select count(1) from IPv4_SSL_ALL where client is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_server_num = \
    spark.sql("select count(1) from IPv4_SSL_ALL where server is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_cert_detail_num = \
    spark.sql("select count(1) from IPv4_SSL_ALL where cert_detail is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_total_num = \
        spark.sql("select count(1) from IPv4_SSL_ALL").rdd.map(lambda row: row[0]).collect()[0]

    radar_chart = pygal.Radar(margin=50)
    radar_chart.title = "SSL Protocol Detail Radar"
    radar_chart.x_labels = ["Client Hello", "Server Hello", "Certificate"]
    radar_chart.add("IPv6", [client_num, server_num, cert_detail_num])
    radar_chart.add("IPv4", [ipv4_client_num, ipv4_server_num, ipv4_cert_detail_num])
    radar_chart.render_to_file("SSL Protocol Detail Radar.svg")

    dot_chart = pygal.Dot(margin=50, x_label_rotation=30)
    dot_chart.title = "SSL Protocol Detail Dot Chart"
    dot_chart.x_labels = ["Client Hello", "Server Hello", "Certificate"]
    dot_chart.add("IPv6", [client_num, server_num, cert_detail_num])
    dot_chart.add("IPv4", [ipv4_client_num, ipv4_server_num, ipv4_cert_detail_num])
    dot_chart.render_to_file("SSL Protocol Detail Dot Chart.svg")

    gauge = pygal.SolidGauge(
        half_pie=True, inner_radius=0.70,
        style=pygal.style.styles["default"](value_font_size=10)
    )
    percent_formatter = lambda x: '{:.10g}'.format(x)
    gauge.value_formatter = percent_formatter
    gauge.add("Client Hello", [{'value': client_num, 'max_value': total_num}])
    gauge.add("Server Hello", [{'value': server_num, 'max_value': total_num}])
    gauge.add("Certificate", [{'value': cert_detail_num, 'max_value': total_num}])
    gauge.render_to_file("IPv6 SSL Protocol Detail Rauge.svg")

    gauge = pygal.SolidGauge(
        half_pie=True, inner_radius=0.70,
        style=pygal.style.styles["default"](value_font_size=10)
    )
    percent_formatter = lambda x: '{:.10g}'.format(x)
    gauge.value_formatter = percent_formatter
    gauge.add("Client Hello", [{'value': ipv4_client_num, 'max_value': ipv4_total_num}])
    gauge.add("Server Hello", [{'value': ipv4_server_num, 'max_value': ipv4_total_num}])
    gauge.add("Certificate", [{'value': ipv4_cert_detail_num, 'max_value': ipv4_total_num}])
    gauge.render_to_file("IPv4 SSL Protocol Detail Rauge.svg")

def draw_http_cs(http_server_count_df, http_host_count_df, http_user_agent_count_df, ip_version):
    if ip_version == 6:
        http_server = http_server_count_df.toPandas()
        http_server = http_server.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 HTTP Server Count Bar Chart"
        for index, row in http_server.iterrows():
            bar_chart.add(row["SERVER"], row["count"])
        bar_chart.render_to_file("IPv6 HTTP Server Count Bar Chart.svg")

        http_host = http_host_count_df.toPandas()
        http_host = http_host.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 HTTP Host Count Bar Chart"
        for index, row in http_host.iterrows():
            bar_chart.add(row["Host"], row["count"])
        bar_chart.render_to_file("IPv6 HTTP Host Count Bar Chart.svg")

        http_user_agent = http_user_agent_count_df.toPandas()
        http_user_agent = http_user_agent.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 HTTP User-Agent Count Bar Chart"
        for index, row in http_user_agent.iterrows():
            bar_chart.add(row["User_Agent"], row["count"])
        bar_chart.render_to_file("IPv6 HTTP User-Agent Count Bar Chart.svg")

    else:
        http_server = http_server_count_df.toPandas()
        http_server = http_server.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 HTTP Server Count Bar Chart"
        for index, row in http_server.iterrows():
            bar_chart.add(row["SERVER"], row["count"])
        bar_chart.render_to_file("IPv4 HTTP Server Count Bar Chart.svg")

        http_host = http_host_count_df.toPandas()
        http_host = http_host.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 HTTP Host Count Bar Chart"
        for index, row in http_host.iterrows():
            bar_chart.add(row["Host"], row["count"])
        bar_chart.render_to_file("IPv4 HTTP Host Count Bar Chart.svg")

        http_user_agent = http_user_agent_count_df.toPandas()
        http_user_agent = http_user_agent.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 HTTP User-Agent Count Bar Chart"
        for index, row in http_user_agent.iterrows():
            bar_chart.add(row["User_Agent"], row["count"])
        bar_chart.render_to_file("IPv4 HTTP User-Agent Count Bar Chart.svg")

def draw_http_cont_type(total_cont_type_df, cont_type_file_count_df, ip_version):
    if ip_version == 6:
        total_cont_type = total_cont_type_df.toPandas()
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 HTTP Content-Type Count Bar Chart"
        for index, row in total_cont_type.iterrows():
            bar_chart.add("Model_total", row["Model_total"])
            bar_chart.add("application_total", row["application_total"])
            bar_chart.add("audio_total", row["audio_total"])
            bar_chart.add("drawing_total", row["drawing_total"])
            bar_chart.add("image_total", row["image_total"])
            bar_chart.add("java_total", row["java_total"])
            bar_chart.add("message_total", row["message_total"])
            bar_chart.add("none_total", row["none_total"])
            bar_chart.add("text_total", row["text_total"])
            bar_chart.add("video_total", row["video_total"])
            total = row["Model_total"] + row["application_total"] + row["audio_total"] + row["drawing_total"] + row["image_total"] \
            + row["java_total"] + row["message_total"] + row["none_total"] + row["text_total"] + row["video_total"]
        bar_chart.render_to_file("IPv6 HTTP Total Content-Type Count Bar Chart.svg")

        content_type = cont_type_file_count_df.toPandas()
        content_type = content_type.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 HTTP Content-Type Count Bar Chart"
        for index, row in content_type.iterrows():
            bar_chart.add(row["content_type"], row["count"])
        bar_chart.render_to_file("IPv6 HTTP Content-Type Count Bar Chart.svg")

        pie_chart = pygal.Pie(legend_at_bottom=True, human_readable=True, inner_radius=.4)
        pie_chart.title = "IPv6 HTTP Content-Type Pie Chart"
        for index, row in total_cont_type.iterrows():
            pie_chart.add("Model_total", row["Model_total"]*100.0/float(total))
            pie_chart.add("application_total", row["application_total"]*100.0/float(total))
            pie_chart.add("audio_total", row["audio_total"]*100.0/float(total))
            pie_chart.add("drawing_total", row["drawing_total"]*100.0/float(total))
            pie_chart.add("image_total", row["image_total"]*100.0/float(total))
            pie_chart.add("java_total", row["java_total"]*100.0/float(total))
            pie_chart.add("message_total", row["message_total"]*100.0/float(total))
            pie_chart.add("none_total", row["none_total"]*100.0/float(total))
            pie_chart.add("text_total", row["text_total"]*100.0/float(total))
            pie_chart.add("video_total", row["video_total"]*100.0/float(total))
        pie_chart.render_to_file("IPv6 HTTP Content-Type Pie Chart.svg")

    else:
        total_cont_type = total_cont_type_df.toPandas()
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 HTTP Content-Type Count Bar Chart"
        for index, row in total_cont_type.iterrows():
            bar_chart.add("Model_total", row["Model_total"])
            bar_chart.add("application_total", row["application_total"])
            bar_chart.add("audio_total", row["audio_total"])
            bar_chart.add("drawing_total", row["drawing_total"])
            bar_chart.add("image_total", row["image_total"])
            bar_chart.add("java_total", row["java_total"])
            bar_chart.add("message_total", row["message_total"])
            bar_chart.add("none_total", row["none_total"])
            bar_chart.add("text_total", row["text_total"])
            bar_chart.add("video_total", row["video_total"])
            total = row["Model_total"] + row["application_total"] + row["audio_total"] + row["drawing_total"] + row[
                "image_total"] \
                    + row["java_total"] + row["message_total"] + row["none_total"] + row["text_total"] + row[
                        "video_total"]
        bar_chart.render_to_file("IPv4 HTTP Total Content-Type Count Bar Chart.svg")

        content_type = cont_type_file_count_df.toPandas()
        content_type = content_type.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 HTTP Content-Type Count Bar Chart"
        for index, row in content_type.iterrows():
            bar_chart.add(row["content_type"], row["count"])
        bar_chart.render_to_file("IPv4 HTTP Content-Type Count Bar Chart.svg")

        pie_chart = pygal.Pie(legend_at_bottom=True, human_readable=True, inner_radius=.4)
        pie_chart.title = "IPv4 HTTP Content-Type Pie Chart"
        for index, row in total_cont_type.iterrows():
            pie_chart.add("Model_total", row["Model_total"] * 100.0 / float(total))
            pie_chart.add("application_total", row["application_total"] * 100.0 / float(total))
            pie_chart.add("audio_total", row["audio_total"] * 100.0 / float(total))
            pie_chart.add("drawing_total", row["drawing_total"] * 100.0 / float(total))
            pie_chart.add("image_total", row["image_total"] * 100.0 / float(total))
            pie_chart.add("java_total", row["java_total"] * 100.0 / float(total))
            pie_chart.add("message_total", row["message_total"] * 100.0 / float(total))
            pie_chart.add("none_total", row["none_total"] * 100.0 / float(total))
            pie_chart.add("text_total", row["text_total"] * 100.0 / float(total))
            pie_chart.add("video_total", row["video_total"] * 100.0 / float(total))
        pie_chart.render_to_file("IPv4 HTTP Content-Type Pie Chart.svg")

def draw_http_detail():
    cont_type_num = spark.sql("select count(1) from HTTP_ALL where CONT_TYPE is not null").rdd.map(lambda row: row[0]).collect()[0]
    host_num = spark.sql("select count(1) from HTTP_ALL where Host is not null").rdd.map(lambda row: row[0]).collect()[0]
    message_url_num = spark.sql("select count(1) from HTTP_ALL where MESSAGE_URL is not null").rdd.map(lambda row: row[0]).collect()[0]
    req_line_num = spark.sql("select count(1) from HTTP_ALL where REQ_LINE is not null").rdd.map(lambda row: row[0]).collect()[0]
    res_line_num = spark.sql("select count(1) from HTTP_ALL where RES_LINE is not null").rdd.map(lambda row: row[0]).collect()[0]
    server_num = spark.sql("select count(1) from HTTP_ALL where SERVER is not null").rdd.map(lambda row: row[0]).collect()[0]
    uri_num = spark.sql("select count(1) from HTTP_ALL where URI is not null").rdd.map(lambda row: row[0]).collect()[0]
    user_agent_num = spark.sql("select count(1) from HTTP_ALL where User_Agent is not null").rdd.map(lambda row: row[0]).collect()[0]
    total_num = \
        spark.sql("select count(1) from HTTP_ALL").rdd.map(lambda row: row[0]).collect()[0]

    ipv4_cont_type_num = \
    spark.sql("select count(1) from IPv4_HTTP_ALL where CONT_TYPE is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_host_num = spark.sql("select count(1) from HTTP_ALL where Host is not null").rdd.map(lambda row: row[0]).collect()[
        0]
    ipv4_message_url_num = \
    spark.sql("select count(1) from IPv4_HTTP_ALL where MESSAGE_URL is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_req_line_num = \
    spark.sql("select count(1) from IPv4_HTTP_ALL where REQ_LINE is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_res_line_num = \
    spark.sql("select count(1) from IPv4_HTTP_ALL where RES_LINE is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_server_num = \
    spark.sql("select count(1) from IPv4_HTTP_ALL where SERVER is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_uri_num = spark.sql("select count(1) from HTTP_ALL where URI is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_user_agent_num = \
    spark.sql("select count(1) from IPv4_HTTP_ALL where User_Agent is not null").rdd.map(lambda row: row[0]).collect()[0]
    ipv4_total_num = \
        spark.sql("select count(1) from IPv4_HTTP_ALL").rdd.map(lambda row: row[0]).collect()[0]

    radar_chart = pygal.Radar(margin=50)
    radar_chart.title = "HTTP Protocol Detail Radar"
    radar_chart.x_labels = ["Content Type", "Host", "Message URL", "Request Line", "Response Line", "Server", "URI", "User Agent"]
    radar_chart.add("IPv6", [cont_type_num, host_num, message_url_num, req_line_num, res_line_num, server_num, uri_num, user_agent_num])
    radar_chart.add("IPv4", [ipv4_cont_type_num, ipv4_host_num, ipv4_message_url_num, ipv4_req_line_num, ipv4_res_line_num, ipv4_server_num, ipv4_uri_num,
                             ipv4_user_agent_num])
    radar_chart.render_to_file("HTTP Protocol Detail Radar.svg")

    dot_chart = pygal.Dot(margin=50, x_label_rotation=30)
    dot_chart.title = "HTTP Protocol Detail Dot Chart"
    dot_chart.x_labels = ["Content Type", "Host", "Message URL", "Request Line", "Response Line", "Server", "URI", "User Agent"]
    dot_chart.add("IPv6", [cont_type_num, host_num, message_url_num, req_line_num, res_line_num, server_num, uri_num, user_agent_num])
    dot_chart.add("IPv4", [ipv4_cont_type_num, ipv4_host_num, ipv4_message_url_num, ipv4_req_line_num, ipv4_res_line_num, ipv4_server_num, ipv4_uri_num,
                           ipv4_user_agent_num])
    dot_chart.render_to_file("HTTP Protocol Detail Dot Chart.svg")

    gauge = pygal.SolidGauge(
        half_pie=True, inner_radius=0.70,
        style=pygal.style.styles["default"](value_font_size=10)
    )
    percent_formatter = lambda x: '{:.10g}'.format(x)
    gauge.value_formatter = percent_formatter
    gauge.add("Content Type", [{'value': cont_type_num, 'max_value': total_num}])
    gauge.add("Host", [{'value': host_num, 'max_value': total_num}])
    gauge.add("Message URL", [{'value': message_url_num, 'max_value': total_num}])
    gauge.add("Request Line", [{'value': req_line_num, 'max_value': total_num}])
    gauge.add("Response Line", [{'value': res_line_num, 'max_value': total_num}])
    gauge.add("Server", [{'value': server_num, 'max_value': total_num}])
    gauge.add("URI", [{'value': uri_num, 'max_value': total_num}])
    gauge.add("User Agent", [{'value': user_agent_num, 'max_value': total_num}])
    gauge.render_to_file("IPv6 HTTP Protocol Detail Rauge.svg")

    gauge = pygal.SolidGauge(
        half_pie=True, inner_radius=0.70,
        style=pygal.style.styles["default"](value_font_size=10)
    )
    percent_formatter = lambda x: '{:.10g}'.format(x)
    gauge.value_formatter = percent_formatter
    gauge.add("Content Type", [{'value': ipv4_cont_type_num, 'max_value': ipv4_total_num}])
    gauge.add("Host", [{'value': ipv4_host_num, 'max_value': ipv4_total_num}])
    gauge.add("Message URL", [{'value': ipv4_message_url_num, 'max_value': ipv4_total_num}])
    gauge.add("Request Line", [{'value': ipv4_req_line_num, 'max_value': ipv4_total_num}])
    gauge.add("Response Line", [{'value': ipv4_res_line_num, 'max_value': ipv4_total_num}])
    gauge.add("Server", [{'value': ipv4_server_num, 'max_value': ipv4_total_num}])
    gauge.add("URI", [{'value': ipv4_uri_num, 'max_value': ipv4_total_num}])
    gauge.add("User Agent", [{'value': ipv4_user_agent_num, 'max_value': ipv4_total_num}])
    gauge.render_to_file("IPv4 HTTP Protocol Detail Rauge.svg")

def draw_tunnel(total_dns_tunnel_df, total_ssl_tunnel_df, total_http_tunnel_df, total_tunnel_df, ip_count_df, teredo_total_df):
    dns_tunnel = total_dns_tunnel_df.toPandas()
    ssl_tunnel = total_ssl_tunnel_df.toPandas()
    http_tunnel = total_http_tunnel_df.toPandas()
    bar_chart = pygal.Bar()
    bar_chart.title = "IPv6 Tunnel Count Bar Chart"
    bar_chart.x_labels = map(str, ["6in4", "6to4", "6over4"])
    for index, row in dns_tunnel.iterrows():
        bar_chart.add("DNS", [int(row["6in4"]), int(row["6to4"]), int(row["6over4"])])
    for index, row in ssl_tunnel.iterrows():
        bar_chart.add("SSL", [int(row["6in4"]), int(row["6to4"]), int(row["6over4"])])
    for index, row in http_tunnel.iterrows():
        bar_chart.add("HTTP", [int(row["6in4"]), int(row["6to4"]), int(row["6over4"])])
    bar_chart.render_to_file("IPv6 Tunnel Count Bar Chart.svg")

    tunnel_total = 0
    teredo_total = int(teredo_total_df.rdd.map(lambda row: row[0]).collect()[0])
    tunnel_total += teredo_total
    total_tunnel = total_tunnel_df.toPandas()
    pie_chart = pygal.Pie(legend_at_bottom=True, human_readable=True, inner_radius=.4)
    pie_chart.title = "IPv6 Tunnel Count Pie Chart"
    for index, row in total_tunnel.iterrows():
        tunnel_total += int(row["6in4"]) + int(row["6to4"]) + int(row["6over4"])
        pie_chart.add("6in4", int(row["6in4"]) * 100.0 / float(tunnel_total))
        pie_chart.add("6to4", int(row["6to4"]) * 100.0 / float(tunnel_total))
        pie_chart.add("6over4", int(row["6over4"]) * 100.0 / float(tunnel_total))
        pie_chart.add("teredo", teredo_total * 100.0 / float(tunnel_total))
        #pie_chart.add("teredo", int(row["teredo"]) * 100.0 / float(tunnel_total))
        #pie_chart.add("ISATAP", int(row["ISATAP"]) * 100.0 / float(tunnel_total))
    pie_chart.render_to_file("IPv6 Tunnel Count Pie Chart.svg")

    ip_total = 0
    ip_count = ip_count_df.toPandas()
    for index, row in ip_count.iterrows():
        ip_total = ip_total + row["count"]
    #print ip_total
    pie_chart_ip_tunnel = pygal.Pie(legend_at_bottom=True, human_readable=True, inner_radius=.4)
    pie_chart_ip_tunnel.title = "IPv6 Tunnel Count in IPv6 Total Count Pie Chart"
    pie_chart_ip_tunnel.add("IPv6 Tunnel", tunnel_total * 100.0 / (ip_total + tunnel_total))
    pie_chart_ip_tunnel.add("IPv6 Total", 100.0 - tunnel_total * 100.0 / (ip_total + tunnel_total))
    pie_chart_ip_tunnel.render_to_file("IPv6 Tunnel Count in IPv6 Total Count Pie Chart.svg")


def draw_protocol(protocol_count_df, ip_version):
    if ip_version == 6:
        protocol = protocol_count_df.toPandas()
        protocol = protocol.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 Protocol Count Bar Chart"
        total = 0
        for index, row in protocol.iterrows():
            bar_chart.add(row["protocol"], row["count"])
            total = total + row["count"]
        bar_chart.render_to_file("IPv6 Protocol Count Bar Chart.svg")

        pie_chart = pygal.Pie(legend_at_bottom=True, human_readable=True, inner_radius=.4)
        pie_chart.title = "IPv6 Protocol Count Pie Chart"
        for index, row in protocol.iterrows():
            pie_chart.add(row["protocol"], row["count"]*100.0/total)
        pie_chart.render_to_file("IPv6 Protocol Count Pie Chart.svg")
    else:
        protocol = protocol_count_df.toPandas()
        protocol = protocol.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 Protocol Count Bar Chart"
        total = 0
        for index, row in protocol.iterrows():
            bar_chart.add(row["protocol"], row["count"])
            total = total + row["count"]
        bar_chart.render_to_file("IPv4 Protocol Count Bar Chart.svg")

        pie_chart = pygal.Pie(legend_at_bottom=True, human_readable=True, inner_radius=.4)
        pie_chart.title = "IPv4 Protocol Count Pie Chart"
        for index, row in protocol.iterrows():
            pie_chart.add(row["protocol"], row["count"] * 100.0 / total)
        pie_chart.render_to_file("IPv4 Protocol Count Pie Chart.svg")

def draw_total_detail(ip_count_df, http_host_count_df, cs_ssl_count_df, cs_queries_count_df, ip_version):
    ip_count_df.createOrReplaceTempView("IP_All")
    ip_all_df = spark.sql("SELECT count(1) from IP_All").withColumnRenamed("count(1)", "ip_num")
    ip_all_df.show()

    http_host_count_df.createOrReplaceTempView("HTTP_CS_ALL")
    http_host_all_df = spark.sql("SELECT count(1) from HTTP_CS_ALL").withColumnRenamed("count(1)", "http_cs_num")
    http_host_all_df.show()

    cs_ssl_count_df.createOrReplaceTempView("SSL_CS_ALL")
    cs_ssl_all_df = spark.sql("SELECT count(1) from SSL_CS_ALL").withColumnRenamed("count(1)", "ssl_cs_num")
    cs_ssl_all_df.show()

    cs_queries_count_df.createOrReplaceTempView("DNS_CS_ALL")
    cs_queries_all_df = spark.sql("SELECT count(1) from DNS_CS_ALL").withColumnRenamed("count(1)", "dns_cs_num")
    cs_queries_all_df.show()

    tcp_udp_packet_total_df = spark.sql("SELECT count(1) from TCP_UDP_All").withColumnRenamed("count(1)", "tcp_udp_num")
    tcp_udp_packet_total_df.show()
    # if ip_version == 6:
    #     tcp_udp_packet_total_df = spark.sql("SELECT count(1) from TCP_UDP_All").withColumnRenamed("count(1)", "tcp_udp_num")
    #     tcp_udp_packet_total_df.show()
    #
    # else:
    #     tcp_udp_packet_total_df = spark.sql("SELECT count(1) from IPv4_TCP_UDP_All").withColumnRenamed("count(1)",
    #                                                                                               "tcp_udp_num")
    #     tcp_udp_packet_total_df.show()

    if ip_version == 6:
        line_chart = pygal.HorizontalBar(margin=50)
        line_chart.title = "IPv6 Total Number Detail Bar Chart"
        line_chart.add("IP", ip_all_df.rdd.map(lambda row: row[0]).collect()[0])
        line_chart.add("TCP/UDP packets", tcp_udp_packet_total_df.rdd.map(lambda row: row[0]).collect()[0])
        line_chart.add("HTTP-Host", http_host_all_df.rdd.map(lambda row: row[0]).collect()[0])
        line_chart.add("SSL-SNI", cs_ssl_all_df.rdd.map(lambda row: row[0]).collect()[0])
        line_chart.add("DNS-Queries Domain", cs_queries_all_df.rdd.map(lambda row: row[0]).collect()[0])
        line_chart.render_to_file("IPv6 Total Number Detail Bar Chart.svg")
    else:
        line_chart = pygal.HorizontalBar(margin=50)
        line_chart.title = "IPv4 Total Number Detail Bar Chart"
        line_chart.add("IP", ip_all_df.rdd.map(lambda row: row[0]).collect()[0])
        #line_chart.add("TCP/UDP packets", tcp_udp_packet_total_df.rdd.map(lambda row: row[0]).collect()[0])
        line_chart.add("HTTP-Host", http_host_all_df.rdd.map(lambda row: row[0]).collect()[0])
        line_chart.add("SSL-SNI", cs_ssl_all_df.rdd.map(lambda row: row[0]).collect()[0])
        line_chart.add("DNS-Queries Domain", cs_queries_all_df.rdd.map(lambda row: row[0]).collect()[0])
        line_chart.render_to_file("IPv4 Total Number Detail Bar Chart.svg")


def draw_day_detail(port_file_path):
    packet_list = []
    ip_list = []
    protocol_list = []
    tcp_udp_list = []
    day_file_path = "E:\\ipv6\\tcp_udp\\20180322"
    day_file_dirs = os.listdir(day_file_path)
    for dir in day_file_dirs:
        print(dir)
        hour_df = spark.read.json(day_file_path + "\\" + dir)
        hour_df.createOrReplaceTempView("HOUR_TCP_UDP")
        tcp_udp_count_df = hour_df.groupBy("protocol").count()
        tcp_udp_list.append(tcp_udp_count_df.rdd.map(lambda row: [row[0], row[1]]).collect())

        packet_list.append(spark.sql("select count(1) from HOUR_TCP_UDP").rdd.map(lambda row: row[0]).collect()[0])

        hour_df.select("sip").union(hour_df.select("dip")).distinct().createOrReplaceTempView("IP_TOTAL")
        ip_list.append(spark.sql("select count(1) from IP_TOTAL").rdd.map(lambda row: row[0]).collect()[0])

        protocol_count_df = get_detail_by_tcp_udp(port_file_path, hour_df, 6)
        protocol_list.append(protocol_count_df.rdd.map(lambda row: [row[0], row[1]]).collect())

    tcp_list = []
    udp_list = []
    for element in tcp_udp_list:
        tcp_list.append(element[0][1])
        udp_list.append(element[1][1])

    max_num = 0
    max_row_number = 0
    row_number = 0
    p_list = []
    for element in protocol_list:
        num = 0
        protocol_dict = {}
        for protocol in element:
            protocol_dict[protocol[0]] = protocol[1]
            num = num + 1
        if num > max_num:
            max_num = num
            max_row_number = row_number
        p_list.append(protocol_dict)
        row_number = row_number + 1

    line_chart = pygal.Line(interpolate='cubic')
    line_chart.title = "TCP and UDP Packets Count in Line Chart"
    line_chart.x_labels = map(str, range(0, 23))
    line_chart.add("TCP", tcp_list, fill=True)
    line_chart.add("UDP", udp_list, fill=True)
    line_chart.add("All", packet_list, fill=True)
    line_chart.render_to_file("TCP and UDP Packets Count in Line Chart.svg")

    line_chart = pygal.Line(interpolate='cubic')
    line_chart.title = "IPv6 Address Count in Line Chart"
    line_chart.x_labels = map(str, range(0, 23))
    line_chart.add("IPv6", ip_list, fill=True)
    line_chart.render_to_file("IPv6 Address Count in Line Chart.svg")

    line_chart = pygal.Line(interpolate='cubic')
    line_chart.title = "IPv6 Protocols Count in Line Chart"
    line_chart.x_labels = map(str, range(0, 24))
    draw_protocol_list = p_list[max_row_number].keys()
    print(max_row_number)
    print(draw_protocol_list)
    for proto in draw_protocol_list:
        for i in range(0, 24):
            if not p_list[i].has_key(proto):
                p_list[i][proto] = 0

        line_chart.add(proto, [p_list[0][proto], p_list[1][proto], p_list[2][proto], p_list[3][proto], p_list[4][proto], \
                               p_list[5][proto], p_list[6][proto], p_list[7][proto], p_list[8][proto], p_list[9][proto], \
                               p_list[10][proto], p_list[11][proto], p_list[12][proto], p_list[13][proto], p_list[14][proto], \
                               p_list[15][proto], p_list[16][proto], p_list[17][proto], p_list[18][proto], p_list[19][proto], \
                               p_list[20][proto], p_list[21][proto], p_list[22][proto], p_list[23][proto]])
    line_chart.render_to_file("IPv6 Protocols Count in Line Chart.svg")

def draw_hour_box():
    all_list = []
    filedir = "E:\\ipv6"
    protocol_dirs = os.listdir(filedir)
    print protocol_dirs
    for protocol_dir in protocol_dirs:
        print protocol_dir
        date_dirs = os.listdir(filedir + "\\" + protocol_dir)
        print date_dirs
        for date_dir in date_dirs:
            if protocol_dir == "tcp_udp":
                hour = 0
                hour_list = []
                filenames = os.listdir(filedir + "\\" + protocol_dir + "\\" + date_dir)
                for filename in filenames:
                    file_path = filedir + "\\" + protocol_dir + "\\" + date_dir + "\\" + filename
                    hour_df = spark.read.json(file_path)
                    hour_df.createOrReplaceTempView("HOUR_ALL")
                    hour_list.append(spark.sql("SELECT count(1) FROM HOUR_ALL").rdd.map(lambda row: row[0]).collect()[0])
                all_list.append(hour_list)
    box_plot = pygal.Box()
    box_plot.title = "IPv6 Daily Count in a Week Box Chart"
    box_plot.add("Monday", all_list[0])
    box_plot.add("Tuesday", all_list[1])
    box_plot.add("Wednesday", all_list[2])
    box_plot.add("Thursday", all_list[3])
    box_plot.add("Friday", all_list[4])
    box_plot.add("Saturday", all_list[5])
    box_plot.add("Sunday", all_list[6])
    box_plot.render_to_file("IPv6 Daily Count in a Week Box Chart.svg")


def draw_http_via(ip_version):
    if ip_version == 6:
        via_df = spark.sql("SELECT * FROM HTTP_ALL WHERE VIA is not null")
        via_count_df = via_df.groupBy("VIA").count()
        via_count = via_count_df.toPandas()
        via_count = via_count.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True)
        bar_chart.title = "IPv6 HTTP Via in Bar Chart"
        for index, row in via_count.iterrows():
            bar_chart.add(row["VIA"], row["count"])
        bar_chart.render_to_file("IPv6 HTTP Via in Bar Chart.svg")
    else:
        via_df = spark.sql("SELECT * FROM IPv4_HTTP_ALL WHERE VIA is not null")
        via_count_df = via_df.groupBy("VIA").count()
        via_count = via_count_df.toPandas()
        via_count = via_count.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True)
        bar_chart.title = "IPv4 HTTP Via in Bar Chart"
        for index, row in via_count.iterrows():
            bar_chart.add(row["VIA"], row["count"])
        bar_chart.render_to_file("IPv4 HTTP Via in Bar Chart.svg")

def draw_web_site_by_http(ip_version):
    if ip_version == 6:
        message_url_dict = {}
        message_url_df = spark.sql("SELECT * FROM HTTP_ALL WHERE MESSAGE_URL is not null")
        message_url_list = message_url_df.select("MESSAGE_URL").rdd.map(lambda row: row[0][:row[0].find("/")]).collect()
        for element in set(message_url_list):
            message_url_dict[element] = message_url_list.count(element)
        message_url = pd.DataFrame({"web_site": message_url_dict.keys(), "count": message_url_dict.values()})
        message_url = message_url.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True)
        bar_chart.title = "IPv6 Web Site in HTTP Message URL Bar Chart"
        for index, row in message_url.iterrows():
            bar_chart.add(row["web_site"], row["count"])
        bar_chart.render_to_file("IPv6 Web Site in HTTP Message URL Bar Chart.svg")
    else:
        message_url_dict = {}
        message_url_df = spark.sql("SELECT * FROM IPv4_HTTP_ALL WHERE MESSAGE_URL is not null")
        message_url_list = message_url_df.select("MESSAGE_URL").rdd.map(lambda row: row[0][:row[0].find("/")]).collect()
        for element in set(message_url_list):
            message_url_dict[element] = message_url_list.count(element)
        message_url = pd.DataFrame({"web_site": message_url_dict.keys(), "count": message_url_dict.values()})
        message_url = message_url.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True)
        bar_chart.title = "IPv4 Web Site in HTTP Message URL Bar Chart"
        for index, row in message_url.iterrows():
            bar_chart.add(row["web_site"], row["count"])
        bar_chart.render_to_file("IPv4 Web Site in HTTP Message URL Bar Chart.svg")

def draw_res_line_by_http(ip_version):
    if ip_version == 6:
        res_line_df = spark.sql("SELECT * FROM HTTP_ALL WHERE RES_LINE is not null")
        res_line_count_df = res_line_df.groupBy("RES_LINE").count()
        res_line = res_line_count_df.toPandas()
        res_line = res_line.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True)
        bar_chart.title = "IPv6 Res Line in HTTP Bar Chart"
        for index, row in res_line.iterrows():
            bar_chart.add(row["RES_LINE"], row["count"])
        bar_chart.render_to_file("IPv6 Res Line in HTTP Bar Chart.svg")
    else:
        res_line_df = spark.sql("SELECT * FROM IPv4_HTTP_ALL WHERE RES_LINE is not null")
        res_line_count_df = res_line_df.groupBy("RES_LINE").count()
        res_line = res_line_count_df.toPandas()
        res_line = res_line.sort_values("count", ascending=False)[:25]
        bar_chart = pygal.Bar(legend_at_bottom=True)
        bar_chart.title = "IPv4 Res Line in HTTP Bar Chart"
        for index, row in res_line.iterrows():
            bar_chart.add(row["RES_LINE"], row["count"])
        bar_chart.render_to_file("IPv4 Res Line in HTTP Bar Chart.svg")

def draw_browser_os_device_by_ua(http_user_agent_count_df, ip_version):
    ua_dict = {}
    browser_dict = {}
    os_dict= {}
    device_dict = {}
    mobile_count = 0
    tablet_count = 0
    pc_count = 0
    bot_count = 0
    http_user_agent_count = http_user_agent_count_df.toPandas()
    for index, row in http_user_agent_count.iterrows():
        ua_dict[row["User_Agent"]] = row["count"]
    for user_agent in ua_dict.keys():
        browser_name = parse(user_agent).browser.family
        if browser_dict.has_key(browser_name):
            browser_dict[browser_name] = browser_dict.get(browser_name) + ua_dict.get(user_agent)
        else:
            browser_dict[browser_name] = ua_dict.get(user_agent)

        os_name = parse(user_agent).os.family
        if os_dict.has_key(os_name):
            os_dict[os_name] = os_dict.get(os_name) + ua_dict.get(user_agent)
        else:
            os_dict[os_name] = ua_dict.get(user_agent)

        device_name = parse(user_agent).device.family
        if device_dict.has_key(device_name):
            device_dict[device_name] = device_dict.get(device_name) + ua_dict.get(user_agent)
        else:
            device_dict[device_name] = ua_dict.get(user_agent)

        if parse(user_agent).is_mobile:
            mobile_count += ua_dict.get(user_agent)

        if parse(user_agent).is_tablet:
            tablet_count += ua_dict.get(user_agent)

        if parse(user_agent).is_pc:
            pc_count += ua_dict.get(user_agent)

        if parse(user_agent).is_bot:
            bot_count += ua_dict.get(user_agent)

    print browser_dict
    print os_dict
    print device_dict
    print mobile_count
    print tablet_count
    print pc_count
    print bot_count

    browser_dict.pop("Other")
    os_dict.pop("Other")
    device_dict.pop("Other")

    device_type_total_count = bot_count + pc_count + tablet_count + mobile_count

    browser = pd.DataFrame({"browser_name": browser_dict.keys(), "count": browser_dict.values()})
    os = pd.DataFrame({"os_name": os_dict.keys(), "count": os_dict.values()})
    device = pd.DataFrame({"device_name": device_dict.keys(), "count": device_dict.values()})
    browser = browser.sort_values("count", ascending=False)[:25]
    os = os.sort_values("count", ascending=False)[:25]
    device = device.sort_values("count", ascending=False)[:25]


    if ip_version == 6:
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 Browser Count Bar Chart"
        for index, row in browser.iterrows():
            bar_chart.add(row["browser_name"], row["count"])
        bar_chart.render_to_file("IPv6 Browser Count Bar Chart.svg")

        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 OS Count Bar Chart"
        for index, row in os.iterrows():
            bar_chart.add(row["os_name"], row["count"])
        bar_chart.render_to_file("IPv6 OS Count Bar Chart.svg")

        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv6 Device Count Bar Chart"
        for index, row in device.iterrows():
            bar_chart.add(row["device_name"], row["count"])
        bar_chart.render_to_file("IPv6 Device Count Bar Chart.svg")

        pie_chart = pygal.Pie(legend_at_bottom=True, human_readable=True, inner_radius=.4)
        pie_chart.title = "IPv6 User Device Type Pie Chart"
        pie_chart.add("mobile", mobile_count * 100.0 / device_type_total_count)
        pie_chart.add("tablet", tablet_count * 100.0 / device_type_total_count)
        pie_chart.add("pc", pc_count * 100.0 / device_type_total_count)
        pie_chart.add("bot", bot_count * 100.0 / device_type_total_count)
        pie_chart.render_to_file("IPv6 User Device Type Pie Chart.svg")

    else:
        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 Browser Count Bar Chart"
        for index, row in browser.iterrows():
            bar_chart.add(row["browser_name"], row["count"])
        bar_chart.render_to_file("IPv4 Browser Count Bar Chart.svg")

        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 OS Count Bar Chart"
        for index, row in os.iterrows():
            bar_chart.add(row["os_name"], row["count"])
        bar_chart.render_to_file("IPv4 OS Count Bar Chart.svg")

        bar_chart = pygal.Bar(legend_at_bottom=True, human_readable=True)
        bar_chart.title = "IPv4 Device Count Bar Chart"
        for index, row in device.iterrows():
            bar_chart.add(row["device_name"], row["count"])
        bar_chart.render_to_file("IPv4 Device Count Bar Chart.svg")

        pie_chart = pygal.Pie(legend_at_bottom=True, human_readable=True, inner_radius=.4)
        pie_chart.title = "IPv4 User Device Type Pie Chart"
        pie_chart.add("mobile", mobile_count * 100.0 / device_type_total_count)
        pie_chart.add("tablet", tablet_count * 100.0 / device_type_total_count)
        pie_chart.add("pc", pc_count * 100.0 / device_type_total_count)
        pie_chart.add("bot", bot_count * 100.0 / device_type_total_count)
        pie_chart.render_to_file("IPv4 User Device Type Pie Chart.svg")


if __name__ == "__main__":

    #combine_file(4)
    #combine_file(6)
    #combine_file(9)

    dns_path = "H:\\ipv6_dns_20180322_all"#"E:\\ipv6_dns_20180322_all" #"E:\\dns_test"
    ssl_path = "H:\\ipv6_ssl_20180322_all"#"E:\\ipv6_ssl_20180322_all" #"E:\\ssl_test"
    http_path = "H:\\ipv6_http_20180322_all"#"E:\\ipv6_http_20180322_all"#"E:\\http_all"
    tcp_udp_path = "H:\\ipv6_tcp_udp_20180322_all"#"E:\\ipv6_tcp_udp_20180322_all" #"E:\\tcp_udp_test"

    ipv4_dns_path = "H:\\ipv4_dns_20180322_all"
    ipv4_ssl_path = "H:\\ipv4_ssl_20180322_all"
    ipv4_http_path = "H:\\ipv4_http_20180322_all"
    ipv4_tcp_udp_path = "E:\\tcp_udp_test"

    teredo_path = "H:\\teredo\\tcp_udp\\20180328\\tcp_udp_20180328_00"
    ip9_tunnel_path = "H:\\ip9_tcp_udp_20180328_all"
    ip9_dns_path = "H:\\ip9_dns_20180328_all"
    ip9_ssl_path = "H:\\ip9_ssl_20180328_all"
    ip9_http_path = "H:\\ip9_http_20180328_all"

    port_file_path = "E:\\port_file.txt"
    content_type_file_path = "E:\\content_type.txt"

    spark = SparkSession \
        .builder \
        .appName("Spark_Programing") \
        .config("spark.some.config.option", "some-value") \
        .getOrCreate()
    sc = spark.sparkContext



    dns_df = spark.read.json(dns_path)
    ssl_df = spark.read.json(ssl_path)
    http_df = spark.read.json(http_path)
    tcp_udp_df = spark.read.json(tcp_udp_path)

    ipv4_dns_df = spark.read.json(ipv4_dns_path)
    ipv4_ssl_df = spark.read.json(ipv4_ssl_path)
    ipv4_http_df = spark.read.json(ipv4_http_path)
    ipv4_tcp_udp_df = spark.read.json(ipv4_tcp_udp_path)

    teredo_df = spark.read.json(teredo_path)
    ip9_tunnel_df = spark.read.json(ip9_tunnel_path)
    ip9_dns_df = spark.read.json(ip9_dns_path)
    ip9_ssl_df = spark.read.json(ip9_ssl_path)
    ip9_http_df = spark.read.json(ip9_http_path)

    dns_df.createOrReplaceTempView("DNS_All")
    ssl_df.createOrReplaceTempView("SSL_All")
    http_df.createOrReplaceTempView("HTTP_All")
    tcp_udp_df.createOrReplaceTempView("TCP_UDP_ALL")

    ipv4_dns_df.createOrReplaceTempView("IPv4_DNS_All")
    ipv4_ssl_df.createOrReplaceTempView("IPv4_SSL_All")
    ipv4_http_df.createOrReplaceTempView("IPv4_HTTP_All")
    #ipv4_tcp_udp_df.createOrReplaceTempView("IPv4_TCP_UDP_ALL")

    # teredo_df.createOrReplaceTempView("TEREDO")
    # ip9_tunnel_df.createOrReplaceTempView("IP9")
    # ip9_dns_df.createOrReplaceTempView("IP9_DNS")
    # ip9_ssl_df.createOrReplaceTempView("IP9_SSL")
    # ip9_http_df.createOrReplaceTempView("IP9_HTTP")

    #dns_df.show()
    #ssl_df.show()
    #http_df.show()
    #tcp_udp_df.show()

    #ipv4_dns_df.show()
    #ipv4_ssl_df.show()
    #ipv4_http_df.show()
    #ipv4_tcp_udp_df.show()

    ip_list, ip_count_df = get_ip_by_all(tcp_udp_df, 6)
    ipv4_ip_list, ipv4_ip_count_df = get_ip_by_all(ipv4_tcp_udp_df, 4)
    # ip_list, ip_count_df = get_ip_by_all(dns_df, ssl_df, http_df)
    #ipv4_ip_list, ipv4_ip_count_df = get_ipv4_by_all(ipv4_dns_df, ipv4_ssl_df, ipv4_http_df)

    geo_df, geo_count_df, geo_total_df, total_geo_ip_count_df = get_geo_by_ip(ip_list, ip_count_df)
    ipv4_geo_df, ipv4_geo_count_df, ipv4_geo_total_df, ipv4_total_geo_ip_count_df = get_geo_by_ip(ipv4_ip_list, ipv4_ip_count_df)

    cs_queries_count_df, cs_answers_count_df = get_CS_by_dns(dns_df, 6)
    ipv4_cs_queries_count_df, ipv4_cs_answers_count_df = get_CS_by_dns(ipv4_dns_df, 4)

    cs_ssl_df, cs_ssl_count_df = get_CS_by_ssl(ssl_df, 6)
    ipv4_cs_ssl_df, ipv4_cs_ssl_count_df = get_CS_by_ssl(ipv4_ssl_df, 4)
    #
    http_server_count_df, http_host_count_df, http_user_agent_count_df, cs_http_df = get_CS_by_http(http_df, 6)
    ipv4_http_server_count_df, ipv4_http_host_count_df, ipv4_http_user_agent_count_df, ipv4_cs_http_df = get_CS_by_http(ipv4_http_df, 4)
    #
    ssl_certificate_df, ssl_certificate_issuer_count_df = get_certificate_by_ssl(ssl_df, 6)
    ipv4_ssl_certificate_df, ipv4_ssl_certificate_issuer_count_df = get_certificate_by_ssl(ipv4_ssl_df, 4)

    ssl_client_record_version_df, ssl_client_client_version_df, ssl_server_record_version_df, ssl_server_client_version_df = get_version_by_ssl(ssl_df, 6)
    ipv4_ssl_client_record_version_df, ipv4_ssl_client_client_version_df, ipv4_ssl_server_record_version_df, ipv4_ssl_server_client_version_df = get_version_by_ssl( \
        ipv4_ssl_df, 4)

    teredo_total_df = get_teredo_by_udp(teredo_df)

    total_dns_tunnel_df, total_ssl_tunnel_df, total_http_tunnel_df, total_tunnel_df = get_tunnel_by_all(ip9_dns_df, ip9_ssl_df, ip9_http_df)

    # ipv4_df, ipv6_df = devide_v4_and_v6_by_all(ip_list)
    #
    # get_devide_detail_by_v4_and_v6(ipv4_df, ipv6_df, dns_df, ssl_df, http_df)
    #
    # get_detail_by_all(dns_df, ssl_df, http_df, 6)
    # get_detail_by_all(ipv4_dns_df, ipv4_ssl_df, ipv4_http_df, 4)

    protocol_count_df = get_detail_by_tcp_udp(port_file_path, tcp_udp_df, 6)
    ipv4_protocol_count_df = get_detail_by_tcp_udp(port_file_path, ipv4_tcp_udp_df, 4)

    total_cont_type_df, cont_type_file_count_df = get_content_type_by_http(content_type_file_path, http_df, 6)
    ipv4_total_cont_type_df, ipv4_cont_type_file_count_df = get_content_type_by_http(content_type_file_path, ipv4_http_df, 4)

    dns_ipv6_stack_df, ipv6_dual_stack_df, geo4_count_df, geo6_count_df, geodual_count_df = get_IPv6_stack_by_dns(dns_df, 6)
    ipv4_dns_ipv6_stack_df, ipv4_ipv6_dual_stack_df, ipv4_geo4_count_df, ipv4_geo6_count_df, ipv4_geodual_count_df = get_IPv6_stack_by_dns(ipv4_dns_df, 4)
    #
    # #cs_geo_count_df = get_whois_by_CS(cs_answers_count_df)
    #
    # #tor_meek_test_df = spark.read.json("E:\\ipv6_ssl_20180322_all")
    # #get_tor_meek_by_ssl(tor_meek_test_df)
    #
    # #json_output(geo_df)
    #
    # #combine_file()
    #
    #
    draw_ssl_version(ssl_client_record_version_df, ssl_client_client_version_df, ssl_server_record_version_df, \
                     ssl_server_client_version_df, 6)
    draw_ssl_version(ipv4_ssl_client_record_version_df, ipv4_ssl_client_client_version_df, ipv4_ssl_server_record_version_df, \
                     ipv4_ssl_server_client_version_df, 4)

    draw_ip_count(ip_count_df, 6)
    draw_ip_count(ipv4_ip_count_df, 4)

    draw_ipv6_geoip(geo_count_df, geo_total_df)
    draw_ipv4_geoip(ipv4_geo_count_df, ipv4_geo_total_df)

    draw_dns_domain_name(cs_queries_count_df, cs_answers_count_df, 6)
    draw_dns_domain_name(ipv4_cs_queries_count_df, ipv4_cs_answers_count_df, 4)

    draw_ssl_sni(cs_ssl_count_df, 6)
    draw_ssl_sni(ipv4_cs_ssl_count_df, 4)

    draw_http_cs(http_server_count_df, http_host_count_df, http_user_agent_count_df, 6)
    draw_http_cs(ipv4_http_server_count_df, ipv4_http_host_count_df, ipv4_http_user_agent_count_df, 4)

    draw_http_cont_type(total_cont_type_df, cont_type_file_count_df, 6)
    draw_http_cont_type(ipv4_total_cont_type_df, ipv4_cont_type_file_count_df, 4)

    draw_ssl_certificate(ssl_certificate_df, ssl_certificate_issuer_count_df, 6)
    draw_ssl_certificate(ipv4_ssl_certificate_df, ipv4_ssl_certificate_issuer_count_df, 4)

    draw_tunnel(total_dns_tunnel_df, total_ssl_tunnel_df, total_http_tunnel_df, total_tunnel_df, ip_count_df, teredo_total_df)

    draw_protocol(protocol_count_df, 6)
    draw_protocol(ipv4_protocol_count_df, 4)

    draw_geo_stack_server(geo4_count_df, geo6_count_df, geodual_count_df, 6)
    draw_geo_stack_server(ipv4_geo4_count_df, ipv4_geo6_count_df, ipv4_geodual_count_df, 4)

    draw_IPv6_dual_stack_count(ipv6_dual_stack_df, 6)
    draw_IPv6_dual_stack_count(ipv4_ipv6_dual_stack_df, 4)

    draw_total_detail(ip_count_df, http_host_count_df, cs_ssl_count_df, cs_queries_count_df, 6)
    draw_total_detail(ipv4_ip_count_df, ipv4_http_host_count_df, ipv4_cs_ssl_count_df, ipv4_cs_queries_count_df, 4)

    draw_day_detail(port_file_path)

    draw_geo_lat_lon(total_geo_ip_count_df, 6)
    draw_geo_lat_lon(ipv4_total_geo_ip_count_df, 4)

    draw_http_detail()

    draw_ssl_detail()

    draw_dns_detail(6)
    draw_dns_detail(4)

    draw_hour_box()

    draw_http_via(4)
    draw_http_via(6)

    draw_web_site_by_http(6)
    draw_web_site_by_http(4)

    draw_res_line_by_http(6)
    draw_res_line_by_http(4)

    draw_browser_os_device_by_ua(http_user_agent_count_df, 6)
    draw_browser_os_device_by_ua(ipv4_http_user_agent_count_df, 4)
