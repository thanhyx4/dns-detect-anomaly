import socket
import random
import time
import datetime
import pandas as pd
import struct
import pickle
import matplotlib.pyplot as plt
import logging


# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s: %(message)s', datefmt='%d-%m-%Y %H:%M')
ch.setFormatter(formatter)
logger.addHandler(ch)

HOST = "172.17.0.1"  # Standard loopback interface address (localhost)
PORT = 2004        # Port to send data to

# print(f"local.random.example2 {random.randint(100, 1000)}" + str(round(time.time())))
# exit(1)

df = pd.read_csv("result1.csv")
df['epoch_time'] =((df['time'] + 25200000)/1000).astype(int)
df['server'] = "203.119.73.80"
#generate examples of start, end,

def gen_data_point_flow(min_timestamp, max_timestamp, type_):
    begin = random.randint(min_timestamp, max_timestamp-600)
    end = begin + 300
    server = df['server'][0]
    if type_ == 'ip':
        subject = df.loc[(df['epoch_time']>= begin) & (df['epoch_time'] <= end), 'src'].value_counts().index[0]
    else:
        subject = df.loc[(df['epoch_time'] >= begin) & (df['epoch_time'] <= end), 'qname'].value_counts().index[0]

    return begin, end, subject, type_, server

def gen_data_point_global(min_timestamp, max_timestamp, feature):
    begin = random.randint(min_timestamp, max_timestamp - 600)
    end = begin + 300
    server = df['server'][0]

    return begin, end, feature, histogram, anomaly, server





#start, end, subject(ip, qname), type('ip', 'qname'), asn, server
def store_qlad_flow_graphite(begin, end, subject, type_, server):
    df_tmp = df[df['server'] == server].loc[(df['epoch_time'] >= begin) & (df['epoch_time'] <= end)]
        #use sql vs impala


    stat_total = df_tmp['epoch_time'].value_counts().sort_index().reset_index()
    if type_ == 'ip':
        stat_abnormal = df_tmp.loc[df_tmp['src'] == subject, 'epoch_time'].value_counts().sort_index().reset_index()
        stat_qname_from_ip = df_tmp.loc[df_tmp['src'] == subject, 'qname'].value_counts().sort_index().reset_index()
        metric_name = "a"
            #metric top qnames from ip (with tags = qnames)
    else:
        stat_abnormal = df_tmp.loc[df_tmp['qname'] == subject, 'epoch_time'].value_counts().sort_index().reset_index()
        stat_asn_from_qname = df_tmp.loc[df_tmp['qname'] == subject, 'asn'].value_counts().sort_index().reset_index()

    metrics_abnormal = []
    metrics_total = []
    datetime_name = ("." + str(datetime.datetime.fromtimestamp(begin).year) + "." + str(datetime.datetime.fromtimestamp(begin).month)
                   + "." + str(datetime.datetime.fromtimestamp(begin).day) + "." + str(datetime.datetime.fromtimestamp(begin).hour) + "." + str(datetime.datetime.fromtimestamp(begin).minute))
    server = str(server).replace(".", "_")
    subject = str(subject).replace(".", "_")

    metric_path_abnormal = "test1.flow." + server + "." + type_ + ".abnormal"  + datetime_name + "." + subject
        #server, ip, qname (tags)
    metric_path_total =  "test1.flow." + server + "." + type_ + ".total"  + datetime_name + "." + subject
    # plt.plot(pd.to_datetime(stat_abnormal_ip['epoch_time']), stat_abnormal_ip['count'])
    # plt.show()
    for index, row in stat_abnormal.iterrows():
        metrics_abnormal.append((metric_path_abnormal, (int(row['epoch_time']), int(row['count']) )))
        #convert to int python not in int numpy array (pandas)
    for index, row in stat_total.iterrows():
        metrics_total.append((metric_path_total, (int(row['epoch_time']), int(row['count']))))

    # Use sendall to ensure all data is sent
    payload_abnormal = pickle.dumps(metrics_abnormal, protocol=2)
    payload_total = pickle.dumps(metrics_total, protocol=2)
    logger.debug(f"Send {len(metrics_abnormal)} data points of abnormal metrics to Graphite")
    logger.debug(f"Send {len(metrics_total)} data points of total  metrics to Graphite")

    # Send data to Graphite
    sock = socket.socket()
    try:
        sock.connect((HOST, PORT))
        size_abnormal = struct.pack('!L', len(payload_abnormal))
        size_total = struct.pack('!L', len(payload_total))
        sock.sendall(size_abnormal + payload_abnormal)
        sock.sendall(size_total + payload_total)
        logger.debug(f"Sent {len(payload_abnormal)} bytes of abnormal data to Graphite")
        logger.debug(f"Sent {len(payload_total)} bytes of total data to Graphite")
    finally:
        sock.close()




#begin, end, options.server, features, histograms, anomalies
def store_qlad_global_graphite(begin,server, feature, entropy,  anomaly):

    #x: timestamp, y: entropy,
    #histogram: full histograms, entropy -> full of this window time
    #send entropy  with begin timestamp, tag anomalies with feature
    #

    metric_path = f"test.global."
    server = str(server).replace(".", "_")
    sock = socket.socket()
    try:
        sock.connect((HOST, 2003))
        if anomaly:
            sock.sendall((metric_path + server + "." + str(feature) + ".abnormal" + " " + str(entropy) + " " + str(begin) + "\n").encode())
        else:
            sock.sendall((metric_path + server + "." + str(feature) + ".normal" + " " + str(entropy) + " " + str(begin) + "\n").encode())

                #server: tags
                #anomaly tags

    finally:
        sock.close()






begins_flow=[]
ends_flow=[]
begins_global = []
ends_global = []
ips = []
qnames = []
features = ['domainname', 'qtype', 'src', 'rcode', 'asn', 'country', 'res_len']

min_timestamp = df['epoch_time'].min()
max_timestamp = df['epoch_time'].max()
for i in range(1):
    begin, end, subject, type_, server = gen_data_point_flow(min_timestamp, max_timestamp,'ip')
    store_qlad_flow_graphite(begin, end, subject, type_, server)
    begin, end, subject, type_, server = gen_data_point_flow(min_timestamp, max_timestamp, 'qname')
    store_qlad_flow_graphite(begin, end, subject, type_, server)


server =  "203.119.73.80"
tmp = min_timestamp
while tmp < max_timestamp:
    entropies = []
    for i, feature in enumerate(features):
        entropy = random.uniform(0, 0.6)
        if (entropy >= 0.5) | (entropy <= 0.1):
            anomaly = 1.3
        else: anomaly = None
        entropy += i
        store_qlad_global_graphite(tmp, server, feature, entropy, anomaly)
    tmp += 300

#
# while True:
#     data = f"local.random.example2 {random.randint(100, 1000)} " + str(round(time.time())) + '\n'
#     # Use sendall to ensure all data is sent
#     with socket.socket() as s:
#         s.settimeout(2)  # Set timeout of 1 second
#         s.connect((HOST, PORT))
#         #print(data.encode())
#         s.sendall(data.encode())

