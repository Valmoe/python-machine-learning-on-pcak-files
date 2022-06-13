from scapy.all import *
import numpy as np
import binascii
import seaborn as sns
import pandas as pd
sns.set(color_codes=True)
# %matplotlib inline

#this will be loaded into the flask web application in realtime.. 

def load_analyzer(datafile="dataset/manda-telescope-12-12-09-31-25-163929788500.pcap"):
    payload={}

    num_of_packets_to_sniff = 100
    pcap = sniff(count=num_of_packets_to_sniff)
    print(type(pcap))
    print(len(pcap))
    print(pcap)
    payload['pcap']=pcap[0]

    # rdpcap used to Read Pcap
    pcap = pcap + rdpcap(datafile)

    pcap

    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    02 04 05 a0 01 03 03 05 01 01 08 0a 1d 74 65 c5 00 00 00 00 04 02 00 00
    """
    payload['pcap_data']=pcap

    ethernet_frame = pcap[101]
    ip_packet = ethernet_frame.payload
    segment = ip_packet.payload
    data = segment.payload
    payload['ethernet_frame_summary']=ethernet_frame.summary()
    payload['packet_summary']=ip_packet.summary()
    payload['segment_summary']=segment.summary()
    payload['data_summary']=data.summary()
    ethernet_frame.show()

    payload['ethernet_frame_type']=ethernet_frame
    payload['ip_packet_type']=type(ip_packet)
    payload['segment_type']=type(segment)
    ethernet_type = type(ethernet_frame)

    ip_type = type(ip_packet)
    tcp_type = type(segment)
    payload['ethernet']=pcap[ethernet_type]
    payload['ip']= pcap[ip_type]
    payload['tcp']=pcap[tcp_type]

    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP
    from scapy.layers.inet import TCP, UDP
    payload['udp']=pcap[UDP]

    # Collect field names from IP/TCP/UDP (These will be columns in DF)
    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    udp_fields = [field.name for field in UDP().fields_desc]

    dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload','payload_raw','payload_hex']

    # Create blank DataFrame
    df = pd.DataFrame(columns=dataframe_fields)
    for packet in pcap[IP]:
        # Field array for each row of DataFrame
        field_values = []
        # Add all IP fields to dataframe
        for field in ip_fields:
            if field == 'options':
                # Retrieving number of options defined in IP Header
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])
        
        field_values.append(packet.time)
        
        layer_type = type(packet[IP].payload)
        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
            except:
                field_values.append(None)
        
        # Append payload
        field_values.append(len(packet[layer_type].payload))
        field_values.append(packet[layer_type].payload.original)
        field_values.append(binascii.hexlify(packet[layer_type].payload.original))
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append], axis=0)
    df = df.reset_index()
    df = df.drop(columns="index")

    payload['dfloc']=df.iloc[0]
    payload['df_shape']=df.shape
    payload['df_head']=df.head()
    payload['df_tail']=df.tail()
    payload['df_src']=df['src']
    df[['src','dst','sport','dport']]

    payload['top_source_addresses']=df['src'].describe()
    payload['top_destination_addresses']=df['dst'].describe()
    frequent_address = df['src'].describe()['top']
    payload['frequent_address']=frequent_address
    payload['whose_address_is_speaking_to']=df[df['src'] == frequent_address]['dst'].unique()
    payload['whose_top_address_destination_ports']=df[df['src'] == frequent_address]['dport'].unique()
    payload['top_source_ports']=df[df['src'] == frequent_address]['sport'].unique()
    payload['unique_addresses']=df['src'].unique()
    payload['unique_destination_address']=df['dst'].unique()

    source_addresses = df.groupby("src")['payload'].sum()
    source_addresses.plot(kind='barh',title="Addresses Sending Payloads",figsize=(8,5))
    payload['source_addresses']=source_addresses


    from tkinter import * 
    from tkinter import messagebox

    messagebox.showinfo("admin alert!", "Ploting the Network analysis for the file..")

    # Group by Destination Address and Payload Sum
    destination_addresses = df.groupby("dst")['payload'].sum()
    destination_addresses.plot(kind='barh', title="Destination Addresses (Bytes Received)",figsize=(8,5))

    # Group by Source Port and Payload Sum
    source_payloads = df.groupby("sport")['payload'].sum()
    source_payloads.plot(kind='barh',title="Source Ports (Bytes Sent)",figsize=(8,5))

    destination_payloads = df.groupby("dport")['payload'].sum()
    destination_payloads.plot(kind='barh',title="Destination Ports (Bytes Received)",figsize=(8,5))

    frequent_address_df = df[df['src'] == frequent_address]
    x = frequent_address_df['payload'].tolist()
    sns.barplot(x="time", y="payload", data=frequent_address_df[['payload','time']],
                label="Total", color="b").set_title("History of bytes sent by most frequent address")

    """# Investigating the payload

    """

    # Create dataframe with only converation from most frequent address
    frequent_address_df = df[df['src']==frequent_address]

    # Only display Src Address, Dst Address, and group by Payload 
    frequent_address_groupby = frequent_address_df[['src','dst','payload']].groupby("dst")['payload'].sum()

    # Plot the Frequent address is speaking to (By Payload)
    frequent_address_groupby.plot(kind='barh',title="Most Frequent Address is Speaking To (Bytes)",figsize=(8,5))

    # Which address has excahnged the most amount of bytes with most frequent address
    suspicious_ip = frequent_address_groupby.sort_values(ascending=False).index[0]
    print(suspicious_ip, "May be a suspicious address")
    payload['the following_ip_may_be_suspicious']=suspicious_ip

    # Create dataframe with only conversation from most frequent address and suspicious address
    suspicious_df = frequent_address_df[frequent_address_df['dst']==suspicious_ip]
    payload['suspicious_df']=suspicious_df
    # Store each payload in an array
    raw_stream = []
    for p in suspicious_df['payload_raw']:
        raw_stream.append(p)
        
    payload['raw_stream_suspicion_payload']=raw_stream
    return payload

