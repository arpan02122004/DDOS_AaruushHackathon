import socket
import struct
import textwrap
import psutil
from datetime import datetime
import threading
import time
import csv
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main():
    global start
    global extract_ip
    extract_ip = 0
    start = datetime.now()
    global endtime
    endtime = 0
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    global numbericmp
    global numbertcp
    global numberudp
    numbericmp = 0
    numbertcp = 0
    numberudp = 0
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f = open("thread1output.txt", "a")
    f.write("\n\nProgram Run Time and date : {}\n\n".format(dt_string))
    f.close()
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        #8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            one = TAB_1 + 'IPv4 Packet:'
            two = TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl)
            three = TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target)
            extract_ip = target
            f = open("thread1output.txt", "a")
            f.write("\n{}\n{}\n{}".format(one,two,three))

            #ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packets(data)
                print(TAB_1 + 'ICPM Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
                numbericmp += 1
                f.write("\n Numbericmp : {}".format(numbericmp))

            #TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
                numbertcp +=1
                f.write("\n Numbertcp : {}".format(numbertcp))

            #UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Sorce Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(format_multi_line(DATA_TAB_3, data))
                numberudp +=1
                f.write("\n Numberudp : {}".format(numberudp))

            #Other
            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))

            endtime = ((datetime.now() - start).total_seconds() * 10 ** 3)
            f.close()
        else:
            print(TAB_1 + 'Data:')
            print(format_multi_line(DATA_TAB_1, data))




def resource_check():
    global averageicmp
    global averagetcp
    global averageudp
    averageicmp = 0
    averagetcp = 0
    averageudp = 0

    print("\n\n\n endtime : ", endtime)
    #Average values are there by running NetwirkMonitor Script for 3 hours
    averageicmp = float(numbericmp/endtime)
    averagetcp = float(numbertcp/endtime)
    averageudp = float(numberudp/endtime)
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f = open("thread2output.txt", "a")
    f.write("\n\nProgram Run Time and date : {}\n\n".format(dt_string))
    f.close()
    while True:
        f = open("thread2output.txt", "a")
        f.write("\naverageicmp : {}\naveragetcp : {}\naverageudp : {}\n\n".format(averageicmp, averagetcp, averageudp))
        f.close()
        if ( endtime % 60000) == 0:
            if psutil.virtual_memory()[2] >= 70:
                load1, load5, load15 = psutil.getloadavg()
                cpu_usage = (load15 / os.cpu_count()) * 100
                if cpu_usage >= 60:
                    if (averageicmp >= 0.01) or (averagetcp >= 0.2) or (averageudp >= 0.003):
                        print("test Passed")
                        # have to create authentic traffic and fake traffic distinguish logic
                        data_list = [averageudp, averagetcp, averageicmp, extract_ip]
                        fields = ["averageudp", "averagetcp", "averageicmp", "extract_ip"]
                        filename = "iplist.csv"
                        with open(filename, 'w') as csvfile:
                            csvwriter = csv.writer(csvfile)
                            # writing the fields
                            csvwriter.writerow(fields)
                            # writing the data rows
                            csvwriter.writerows(rows)


# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Return properly formatted MAC address (ie AA: BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#Unpacks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


#Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


#Unpacks ICMP packet
def icmp_packets(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


#Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


#Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


#Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    t1 = threading.Thread(target=main)
    t2 = threading.Thread(target=resource_check)
    t1.start()
    time.sleep(5)
    t2.start()