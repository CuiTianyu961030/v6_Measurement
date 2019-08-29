import os

def apnic_getdata():
    file_list = os.listdir("./apnic")
    file_list.sort()
    print(file_list)
    g = open("apnic_allocation_count.txt", "w")
    for filename in file_list:
        if 'gz' in filename:
            pass
        else:
            f = open("./apnic/" + filename, 'r')
            for line in f:
                if 'ipv6' in line and 'summary' in line:
                    end = line.rfind('|summary')
                    start = line.rfind('*|') + len('*|')
                    g.write(line[start:end] + '\n')
            f.close()
    g.close()

def ripencc_getdata():
    file_list = os.listdir("./ripencc")
    file_list.sort()
    print(file_list)
    g = open("ripencc_allocation_count.txt", "w")
    for filename in file_list:
        if 'bz2' in filename:
            pass
        else:
            f = open("./ripencc/" + filename, 'r')
            for line in f:
                if 'ipv6' in line and 'summary' in line:
                    end = line.rfind('|summary')
                    start = line.rfind('*|') + len('*|')
                    g.write(line[start:end] + '\n')
            f.close()
    g.close()

def afrinic_getdata():
    g = open("afrinic_allocation_count.txt", "w")
    f = open("afrinic_allocated", "r")
    for line in f:
        end = line.rfind('|summary')
        start = line.rfind('*|') + len('*|')
        g.write(line[start:end] + '\n')
    f.close()
    g.close()

def arin_getdata():
    g = open("arin_allocation_count.txt", "w")
    f = open("arin_allocated", "r")
    for line in f:
        end = line.rfind('|summary')
        start = line.rfind('*|') + len('*|')
        g.write(line[start:end] + '\n')
    f.close()
    g.close()

def lacnic_getdata():
    g = open("lacnic_allocation_count.txt", "w")
    f = open("lacnic_allocated", "r")
    for line in f:
        end = line.rfind('|summary')
        start = line.rfind('*|') + len('*|')
        g.write(line[start:end] + '\n')
    f.close()
    g.close()

def announce_routeview():
    file_list = os.listdir("/Users/cuitianyu/Downloads/routeview6min")
    for file in file_list:
        if "_output" in file:

            flag = 0
            g = open("/Users/cuitianyu/Downloads/routeview6min/" + file + "_routeview_prefiex", "w")
            f = open("/Users/cuitianyu/Downloads/routeview6min/" + file, "r")
            for line in f:
                if flag == 1 and len(line) == 1:
                    flag = 0
                if flag == 1 and ":" in line:
                    g.write(line.split(" ")[-1])
                if "ANNOUNCE" in line:
                    flag = 1
            f.close()
            g.close()
            print(file + " announce finished")

    count_file = open("routeview_count", "w")
    file_list = os.listdir("/Users/cuitianyu/Downloads/routeview6min")
    for file in file_list:
        if "_routeview_prefiex" in file:
            h = open("/Users/cuitianyu/Downloads/routeview6min/" + file, "r")
            prefiex_list = []
            for line in h:
                if line not in prefiex_list:
                    prefiex_list.append(line)
            count_file.write(str(len(prefiex_list)) + "\n")
            print("the number of prefiex in " + file + " : " + str(len(prefiex_list)))
            h.close()
    count_file.close()


def announce_ripencc():
    # file_list = os.listdir("/Users/cuitianyu/Downloads/ripenccmin")
    # for file in file_list:
    #     if "_output" in file:
    #
    #         flag = 0
    #         g = open("/Users/cuitianyu/Downloads/ripenccmin/" + file + "_ripencc_prefiex", "w")
    #         f = open("/Users/cuitianyu/Downloads/ripenccmin/" + file, "r")
    #         for line in f:
    #             if flag == 1 and len(line) == 1:
    #                 flag = 0
    #             if flag == 1 and ":" in line:
    #                 g.write(line.split(" ")[-1])
    #             if "ANNOUNCE" in line:
    #                 flag = 1
    #         f.close()
    #         g.close()
    #         print(file + " announce finished")

    count_file = open("ripencc_count", "w")
    file_list = os.listdir("/Users/cuitianyu/Downloads/ripenccmin")
    file_list.sort()
    count = 0
    for file in file_list:
        if "_ripencc_prefiex" in file:
            h = open("/Users/cuitianyu/Downloads/ripenccmin/" + file, "r")
            if count == 0:
                prefiex_list = []
            for line in h:
                if line not in prefiex_list:
                    prefiex_list.append(line)
            count += 1
            if count == 3:
                print("the number of prefiex in " + file + " * 3 : " + str(len(prefiex_list)))
                count_file.write(str(len(prefiex_list)) + "\n")
                count = 0
            h.close()
    count_file.close()

def day_end_ip():
    # count = []
    # g = open("/Users/cuitianyu/工程/JupyterProject/day_count.txt")
    # for line in g:
    #     count.append(int(line))
    # g.close()
    ip = []
    if os.path.exists("/Volumes/崔天宇的移动硬盘/科研实验/ipv6用户行为的测量与分析/数据集/tcp_udp/tcp_udp_log"):
        date_name_list = os.listdir("/Volumes/崔天宇的移动硬盘/科研实验/ipv6用户行为的测量与分析/数据集/tcp_udp/tcp_udp_log")
        print(date_name_list)
        for date_name in date_name_list:
            hour_list_tcp = []
            hour_list_udp = []
            time_name_list = os.listdir("/Volumes/崔天宇的移动硬盘/科研实验/ipv6用户行为的测量与分析/数据集/tcp_udp/tcp_udp_log/" + date_name)
            time_name_list.sort()
            # print(time_name_list)
            i = 0
            for time_name in time_name_list:
                if '_23' in time_name:
                    f = open("/Volumes/崔天宇的移动硬盘/科研实验/ipv6用户行为的测量与分析/数据集/tcp_udp/tcp_udp_log/" + date_name + "/" + \
                         time_name, "r", encoding='gb18030', errors='ignore')
                    print(time_name)
                    last_line = f.readlines()[-1]
                    # print(last_line)
                    f.close()
                    ip.append(last_line[last_line.find("sip\":\"")+6:last_line.find("\",\"dip\":\"")])
                    ip.append(last_line[last_line.find("\",\"dip\":\"")+9:last_line.find("\",\"sport\":")])
    g = open("last_ip", "w")
    for sip in ip:
        g.write(sip + "\n")
    g.close()

def split_ip():
    alist = []
    f = open("split_ip", "w")
    g = open("global_AS.txt", "r", encoding='gb18030', errors='ignore')
    data_list = []
    data = 0
    count = 0
    for line in g:
        count += 1
        if line not in alist:
            data += 1
            alist.append(line)
        if count % 15505 == 0:
            data_list.append(data)

    for data in data_list:
        f.write(str(data)+ '\n')
    g.close()
    f.close()

def protocol():
    count_list = []
    count_udp = 0
    count_tcp = 0
    count_http = 0
    count_ssl = 0
    count_dns = 0
    if os.path.exists("/Volumes/崔天宇的移动硬盘/科研实验/ipv6用户行为的测量与分析/数据集/tcp_udp/tcp_udp_log"):
        date_name_list = os.listdir("/Volumes/崔天宇的移动硬盘/科研实验/ipv6用户行为的测量与分析/数据集/tcp_udp/tcp_udp_log")
        print(date_name_list)
        for date_name in date_name_list:
            hour_list_tcp = []
            hour_list_udp = []
            time_name_list = os.listdir("/Volumes/崔天宇的移动硬盘/科研实验/ipv6用户行为的测量与分析/数据集/tcp_udp/tcp_udp_log/" + date_name)
            # print(time_name_list)
            for time_name in time_name_list:
                f = open("/Volumes/崔天宇的移动硬盘/科研实验/ipv6用户行为的测量与分析/数据集/tcp_udp/tcp_udp_log/" + date_name + "/" + \
                         time_name, "r", encoding='gb18030', errors='ignore')
                print(time_name)
                if time_name >= "tcp_udp_20180401_00":
                    for line in f:
                        # print(line)
                        if "tcp" in line:
                            count_tcp += 1
                        if "udp" in line:
                            count_udp += 1
                        if (("dport\":80," in line) or ("sport\":80," in line)) and ("tcp" in line):
                            count_http += 1
                            # print(1)
                        if (("dport\":443," in line) or ("sport\":443," in line)) and ("tcp" in line):
                            count_ssl += 1
                        if (("dport\":53," in line) or ("sport\":53," in line)) and ("udp" in line):
                            count_dns += 1

                f.close()

                if time_name == "tcp_udp_20180501_00" or time_name == "tcp_udp_20180601_00" or time_name == "tcp_udp_20180701_00":
                    print(time_name + "1")
                    count_list.append([count_tcp, count_udp, count_dns, count_ssl, count_http])

    print(count_list)
    june_tcp = (count_list[1][0]-count_list[0][0])/(count_list[1][0]-count_list[0][0]+count_list[1][1]-count_list[0][1])
    june_udp = 1 - june_tcp
    june_dns = (count_list[1][2] - count_list[0][2])/ (count_list[1][1] - count_list[0][1])
    june_ssl = (count_list[1][3] - count_list[0][3]) / (count_list[1][0] - count_list[0][0])
    june_http = (count_list[1][4] - count_list[0][4]) / (count_list[1][0] - count_list[0][0])

    july_tcp = (count_list[2][0] - count_list[1][0]) / (count_list[2][0] - count_list[1][0] + count_list[2][1] - count_list[1][1])
    july_udp = 1 - july_tcp
    july_dns = (count_list[2][2] - count_list[1][2]) / (count_list[2][1] - count_list[1][1])
    july_ssl = (count_list[2][3] - count_list[1][3]) / (count_list[2][0] - count_list[1][0])
    july_http = (count_list[2][4] - count_list[1][4]) / (count_list[2][0] - count_list[1][0])

    print(june_tcp, june_udp, june_dns, june_ssl, june_http)
    print(july_tcp, july_udp, july_dns, july_ssl, july_http)


def tld_file():
    v4 = []
    v6 = []
    f = open("/Volumes/崔天宇的移动硬盘/科研实验/ipv6用户行为的测量与分析/数据集/public dataset/net.txt")
    for line in f:
        if line.split("\t")[3] == "a":
            v4.append(line.split("\t")[0])
        elif line.split("\t")[3] == "aaaa":
            v6.append(line.split("\t")[0])
    f.close()
    v4 = set(v4)
    v6 = set(v6)
    v4_only = list(set(v4).difference(set(v6)))
    v6_only = list(set(v6).difference(set(v4)))
    dual_stack = list(set(v4).intersection(set(v6)))
    print(".net statistics")
    print("v4: %d\nv6: %d\nv4 only: %d\nv6 only: %d\ndual stack: %d"
          % (len(v4), len(v6), len(v4_only), len(v6_only), len(dual_stack)))


if __name__ == "__main__":
    # apnic_getdata()
    # ripencc_getdata()
    # afrinic_getdata()
    # arin_getdata()
    # lacnic_getdata()
    # announce_routeview()
    # announce_ripencc()
    # day_end_ip()

    # split_ip()
    # protocol()
    tld_file()

    # s = []
    # all = []
    # f = open("china_AS.txt", "r", encoding='gb18030', errors='ignore')
    # g = open("last_ip", "r", encoding='gb18030', errors='ignore')
    # h = open("last_record", "w")
    # for line in g:
    #     count = 0
    #     temp = f.readlines()
    #     for fline in temp:
    #         count += 1
    #         print(line[:8], fline[14:22])
    #         if line[:8] == fline[14:22]:
    #             s.append(count)
    #     all.append(s)
    # for element in all:
    #     h.write(str(element)+"\n")
    # h.close()
    # g.close()
    # f.close()
