import sys
import structs
import struct

first_packet = True
original_starting_time = 0

def main():
    file = sys.argv[1]
    f = open(file, "rb")
    globalHeaderBits = f.read(24)





    global_header = load_global_header(globalHeaderBits)

    for x in range(2):
        packet = load_packet(f)
        print("---------------------------")








def load_packet(f):
    packet_header = f.read(16)

    global first_packet #getting the original starting time if we are running through the first packet
    global original_starting_time
    if first_packet:
        orig_time_seconds = packet_header[0:4]
        orig_time_micro = packet_header[4:8]

        seconds = struct.unpack('I', orig_time_seconds)[0]
        microseconds = struct.unpack('I', orig_time_micro)[0]

        original_starting_time = seconds + microseconds/1000000
        first_packet = False


    packet = structs.packet()

    buffer1 = packet_header[0:4]
    buffer2 = packet_header[4:8]
    incl_len = packet_header[8:12]
    original_len = packet_header[12:16]

    packet.timestamp_set(buffer1,buffer2,original_starting_time)
    packet.set_incl_len(incl_len)

    print("TIME: ", packet.timestamp)
    print("INCL_LEN: ", packet.incl_len)


    #read packet data using incel length
    packet_data = f.read(packet.incl_len)

    #create ethernet header
    ethernet_header = structs.Ethernet_header()
    dest_MAC_address = packet_data[0:6]
    source_MAC_address = packet_data[6:12]
    ethernet_type = packet_data[12:14]

    #create ipv4 header
    IPV4_header = structs.IP_Header()
    header_length = packet_data[14:15]
    total_length = packet_data[16:18]
    source_address = packet_data[26:30]
    destination_adress = packet_data[30:34]


    IPV4_header.get_IP(source_address, destination_adress)
    IPV4_header.get_total_len(total_length)
    IPV4_header.get_header_len(header_length)

    print("SRC: ", IPV4_header.src_ip)
    print("DEST: ", IPV4_header.dst_ip)
    print("Total Length: ", IPV4_header.total_len)
    print("Header Length: ", IPV4_header.ip_header_len)


    #create TCP header
    TCP_header = structs.TCP_Header()
    src_port = packet_data[34:36]
    destination_port = packet_data[36:38]
    seq_number = packet_data[38:42]
    ack_number = packet_data[42:46]
    data_offset = packet_data[46:47]
    flags = packet_data[47:48]
    window_size1 = packet_data[48:49]
    window_size2 = packet_data[49:50]

    TCP_header.get_src_port(src_port)
    TCP_header.get_dst_port(destination_port)
    TCP_header.get_seq_num(seq_number)
    TCP_header.get_ack_num(ack_number)
    TCP_header.get_data_offset(data_offset)
    TCP_header.get_flags(flags)
    TCP_header.get_window_size(window_size1, window_size2)

    print("SRC: ", TCP_header.src_port)
    print("DEST: ", TCP_header.dst_port)
    print("SEQ: ", TCP_header.seq_num)
    print("ACK: ", TCP_header.ack_num)
    print("DATA OFFSET: ", TCP_header.data_offset)
    print("WINDOW SIZE: ", TCP_header.window_size)
    print("FLAGS: ", TCP_header.flags)

    packet.IP_header = IPV4_header
    packet.TCP_header = TCP_header

    return packet


def load_global_header(globalHeaderBits):
    global_header = structs.pcap_header()
    global_header.set_magic_number(globalHeaderBits[0:4])
    global_header.set_version_major(globalHeaderBits[4:6])
    global_header.set_version_minor(globalHeaderBits[6:8])
    global_header.set_this_zone(globalHeaderBits[8:12])
    global_header.set_sigfigs(globalHeaderBits[12:16])
    global_header.set_snaplen(globalHeaderBits[16:20])
    global_header.set_network(globalHeaderBits[20:24])
    return global_header



if __name__ == '__main__':
    main()
