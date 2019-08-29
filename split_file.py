
f = open("alexa-top-10000_Global.txt", "r")
data = str(f.readlines())
new_data = ""
old_data = data

# pos=old_data.find("}")
# pre =0
# while pos!=-1:
#     # print(old_data[pre:pos+1],pos)
#     new_data+=(old_data[pre:pos+1]+"\n")
#     print(new_data)
#     pre = pos+1
#     # old_data=old_data[pos+2:]
#     # print(pre,pos)
#     # print(old_data)
#     pos=old_data.find("}",pos+1)

s = ""
for a in data:
    if a == "}":
        new_data = old_data[0:old_data.find(a) + 1] + "\n"
        s += new_data
        old_data = old_data[old_data.find(a)+1:]
f.close()
s = s[2:]
# print s
g = open("alexa_top_100000_Global.txt", "w")
g.write(s)
g.close()

h = open("alexa_top_100000_Global.txt", "r")
m = open("global_100000.txt", "w")
for line in h:
    print(line)
    a = eval(line)
    m.writelines(a["domain"] + "\n")
m.close()
h.close()

# p_dict = eval(s)
# print p_dict
# a = list(data)
# p = a.index("}")
# a.insert(p + 1 , "\n")
# str_2 = "".join(a)
# print(str_2)
# # line = f.readline()
# # for i in range(0, int(line)):
# #     data = f.readlines()
# #     str(data).split(' ')
# import json
# with open("alexa_top_100000_CN.txt", "r") as h:
#     for line in h:
#         print(line)
#         line=line.replace('u','')
#         print(line)
#         a = json.loads(line)
#         print a