import os

secure_protocol_dict = {"ssl": 0, "ipsec_nat": 0, "ike": 0, "telnet": 0, "ssh": 0, "socks": 0, "pptp": 0, "l2tp": 0, \
                        "openvpn": 0, "set": 0, "stt": 0, "kerberos": 0, "total": 0}
line_count = 0
if os.path.exists("L:\\科研实验\\ipv6用户行为的测量与分析\\数据集\\tcp_udp"):
    date_name_list = os.listdir("L:\\科研实验\\ipv6用户行为的测量与分析\\数据集\\tcp_udp\\tcp_udp_log")
    for date_name in date_name_list:
        time_name_list = os.listdir("L:\\科研实验\\ipv6用户行为的测量与分析\\数据集\\tcp_udp\\tcp_udp_log\\" + date_name)
        for time_name in time_name_list:
            f = open("L:\\科研实验\\ipv6用户行为的测量与分析\\数据集\\tcp_udp\\tcp_udp_log\\" + date_name + "\\" + \
                     time_name, "r", encoding='gb18030', errors='ignore')
            print(time_name)

            # if time_name > "tcp_udp_20180323_21":
            for line in f:

                if "\x00" in line:
                    continue

                secure_protocol_dict["total"] += 1
                # if time_name == "tcp_udp_20180323_22":
                #     num += 1
                #     print(num)
                if "\"sport\":443" in line or "\"dport\":443" in line:
                    secure_protocol_dict["ssl"] = secure_protocol_dict["ssl"] + 1
                elif "\"sport\":4500" in line or "\"dport\":4500" in line:
                    secure_protocol_dict["ipsec_nat"] = secure_protocol_dict["ipsec_nat"] + 1
                elif "\"sport\":500" in line or "\"dport\":500" in line:
                    secure_protocol_dict["ike"] = secure_protocol_dict["ike"] + 1
                elif "\"sport\":23" in line or "\"dport\":23" in line:
                    secure_protocol_dict["telnet"] = secure_protocol_dict["telnet"] + 1
                elif "\"sport\":22" in line or "\"dport\":22" in line:
                    secure_protocol_dict["ssh"] = secure_protocol_dict["ssh"] + 1
                elif "\"sport\":1080" in line or "\"dport\":1080" in line:
                    secure_protocol_dict["socks"] = secure_protocol_dict["socks"] + 1
                elif "\"sport\":1723" in line or "\"dport\":1723" in line:
                    secure_protocol_dict["pptp"] = secure_protocol_dict["pptp"] + 1
                elif "\"sport\":1701" in line or "\"dport\":1701" in line:
                    secure_protocol_dict["l2tp"] = secure_protocol_dict["l2tp"] + 1
                elif "\"sport\":1194" in line or "\"dport\":1194" in line:
                    secure_protocol_dict["openvpn"] = secure_protocol_dict["openvpn"] + 1
                elif "\"sport\":257" in line or "\"dport\":257" in line:
                    secure_protocol_dict["set"] = secure_protocol_dict["set"] + 1
                elif "\"sport\":1607" in line or "\"dport\":1607" in line:
                    secure_protocol_dict["stt"] = secure_protocol_dict["stt"] + 1
                elif "\"sport\":88" in line or "\"dport\":88" in line or "\"sport\":749" in line or "\"dport\":749" in line:
                    secure_protocol_dict["kerberos"] = secure_protocol_dict["kerberos"] + 1
            f.close()
            print(secure_protocol_dict)
else:
    print("no path exist!")

g =open("secure_protocol", "w")
g.write(str(secure_protocol_dict))
g.close()



