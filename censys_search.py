import censys.websites

UID = "cade2f6c-5b3b-465a-9ceb-ce48121c0245"
SECRET = "zHq5tOlH4cb7xfjGHDoRglca48qpjfUE"

websites = censys.websites.CensysWebsites(UID, SECRET)

count = 0
f = open("alexa-top-3500000-10000000_CN.txt", "w")
for c in websites.search("location.country_code: CN and alexa_rank: [3500001 TO 10000000]"):
    count = count + 1
    f.writelines(str(c))
    print c
# for c in websites.search("location.country_code: CN and alexa_rank: [50000 TO 100000]"):
#     count = count + 1
#     f.writelines(str(c))
#     print c
# f.close()
# print "The total number is %d" % count

f.close()
print "The total number is %d" % count

# count = 0
# f = open("alexa-top-8000-9000_Global.txt", "w")
# for c in websites.search("alexa_rank: [8001 TO 9000]"):
#         count = count + 1
#         f.writelines(str(c))
#         print c
# f.close()
# print "The total number is %d" % count