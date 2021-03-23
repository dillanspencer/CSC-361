# CSC 361 Programming Assignment 2
# Dillan Spencer
# V00914254

import sys
import utils
import connection
import struct


def main():
    # Read CAP file
    file_name = sys.argv[1]
    file = open(file_name, "rb")

    # Lists for packets and connections
    packets = []
    connections = {}

    # Read General Header
    data = file.read(24)
    gen_header = load_general_header(data)

    # Read first packet header
    data = file.read(16)
    orig_time = data[0:4]
    orig_micro = data[4:8]
    packet_num = 0
    packets.append(load_packet_header(packet_num, data, orig_time, orig_micro))

    # Read first packet data
    data = file.read(packets[packet_num].incl_len)
    packets[packet_num].Ethernet_header = load_ethernet_header(data)
    packets[packet_num].IP_header = load_ipv4_header(data)
    packets[packet_num].TCP_header = load_tcp_header(data)
    check_connection(packets[packet_num], connections)

    while True:
        try:
            data = file.read(16)
            packet_num += 1
            packets.append(load_packet_header(packet_num, data, orig_time, orig_micro))

            data = file.read(packets[packet_num].incl_len)
            packets[packet_num].Ethernet_header = load_ethernet_header(data)
            packets[packet_num].IP_header = load_ipv4_header(data)
            packets[packet_num].TCP_header = load_tcp_header(data)
            check_connection(packets[packet_num], connections)
        except struct.error:
            break

    # Output deliverables
    connection_details(connections)


# Takes a packet and checks what connection it belongs to
# If no connection is found, a new connection is created
# and packet is added to connection.
def check_connection(packet, connections):
    src_ip = packet.IP_header.src_ip
    dst_ip = packet.IP_header.dst_ip
    src_port = packet.TCP_header.src_port
    dst_port = packet.TCP_header.dst_port
    buffer = (src_ip, src_port, dst_ip, dst_port)
    ID = utils.pack_id(buffer)

    if ID not in connections:
        c = connection.Connection(src_ip, src_port, dst_ip, dst_port)
        c.add_packet(packet)
        connections[ID] = c
    else:
        connections[ID].add_packet(packet)


# Loads data into general header object
# Returns general header
def load_general_header(data):
    gen_header = utils.General_Header()
    gen_header.set_magic_number(data[0:4])
    gen_header.set_version_major(data[4:6])
    gen_header.set_version_minor(data[6:8])
    gen_header.set_zone(data[8:12])
    gen_header.set_sigfigs(data[12:16])
    gen_header.set_snaplen(data[16:20])
    gen_header.set_network(data[20:24])
    return gen_header


# Loads data into packet header object
# Returns packet header
def load_packet_header(packet_num, data, time, micro):
    packet = utils.packet()
    buff1 = data[0:4]
    buff2 = data[4:8]
    incl_len = data[8:12]
    orig_len = data[12:16]

    packet.packet_No_set(packet_num)
    packet.timestamp_set(buff1, buff2, time, micro)
    packet.packet_incl_len_set(incl_len)
    packet.packet_size_set(orig_len)
    packet.buffer = data

    return packet


# Loads data into ethernet header object
# Returns ethernet header
def load_ethernet_header(data):
    header = utils.Ethernet_Header()
    header.set_dest_addr(data[0:6])
    header.set_src_addr(data[6:12])
    header.set_type(data[12:14])
    return header


# Loads data into IPV4 header object
# Returns IPV4 header
def load_ipv4_header(data):
    header = utils.IP_Header()
    src = data[26:30]
    dest = data[30:34]
    total_len = data[16:18]
    header_len = data[14:15]

    header.get_IP(src, dest)
    header.get_total_len(total_len)
    header.get_header_len(header_len)
    return header


# Loads data into TCP header object
# Returns TCP header
def load_tcp_header(data):
    header = utils.TCP_Header()
    src_port = data[34:36]
    dest_port = data[36:38]
    seq_num = data[38:42]
    ack_num = data[42:46]
    data_offset = data[46:47]
    flags = data[47:48]
    w1 = data[48:49]
    w2 = data[49:50]

    header.get_src_port(src_port)
    header.get_dst_port(dest_port)
    header.get_seq_num(seq_num)
    header.get_ack_num(ack_num)
    header.get_data_offset(data_offset)
    header.get_window_size(w1, w2)
    header.get_flags(flags)

    return header


# Outputs deliverables of connections
def connection_details(connections):
    inc = 1
    complete_connections = 0
    reset_connections = 0
    open_connections = 0
    total_packets = 0
    min_time = float('inf')
    mean_time = 0
    max_time = float('-inf')
    min_packets = float('inf')
    mean_packets = 0
    max_packets = float('-inf')
    min_rtt = float('inf')
    mean_rtt = 0
    max_rtt = float('-inf')
    total_rtt = 0
    min_window = float('inf')
    mean_window = 0
    max_window = float('-inf')

    # Output -----------------------
    print("Output For Assignment 2: \n")
    print("A) Total Number of connections: ", len(connections))
    print("------------------------")
    print("B) Connection Details:")
    for conn in connections.values():
        # STATISTICS
        start_time, end_time, total_time = conn.get_connection_time()
        if conn.is_complete():
            complete_connections += 1
            total_packets += conn.get_num_packets()
            # TIME
            min_time = min(total_time, min_time)
            mean_time += total_time
            max_time = max(total_time, max_time)
            # PACKETS
            min_packets = min(conn.get_num_packets(), min_packets)
            mean_packets += conn.get_num_packets()
            max_packets = max(conn.get_num_packets(), max_packets)
            # RTT
            rtt = conn.calculate_rtt()
            min_rtt = min(min(rtt), min_rtt)
            mean_rtt += sum(rtt)
            max_rtt = max(max(rtt), max_rtt)
            total_rtt += conn.get_num_rtt_pairs()
            # WINDOW SIZE
            min_window = min(conn.min_window, min_window)
            mean_window += conn.total_window
            max_window = max(conn.max_window, max_window)
        if conn.is_reset():
            reset_connections += 1
        if conn.is_open():
            open_connections += 1

        # CONNECTION DETAILS OUTPUT
        print("Connection: ", inc)
        print("Source Address: ", conn.address[0])
        print("Source Port: ", conn.address[1])
        print("Destination Address: ", conn.address[2])
        print("Destination Port: ", conn.address[3])
        print("Status: ", conn.check_connection_state())
        if conn.is_complete():
            print("Start Time: ", start_time)
            print("End Time: ", end_time)
            print("Duration: ", round(total_time, 6))
            print("Number of packets sent from Source to Destination: ", conn.get_src_packet_total())
            print("Number of packets sent from Destination to Source: ", conn.get_dst_packet_total())
            print("Total number of packets: ", conn.get_num_packets())
            print("Number of data bytes sent from Source to Destination: ", conn.get_src_bytes_total())
            print("Number of data bytes sent from Destination to Source: ", conn.get_dst_bytes_total())
            print("Total number of bytes sent: ", conn.get_num_bytes())
        print("-------------------------")
        inc += 1

    print("C) GENERAL\n")
    print("Total number of complete TCP connections: ", complete_connections)
    print("Number of reset TCP connections: ", reset_connections)
    print("Number of TCP connections that were still open when the trace capture ended: ", open_connections)
    print("-------------------------")
    print("D) Complete TCP connections:\n")
    print("Minimum time duration: %2f" % min_time)
    print("Mean time duration: %2f" % float(mean_time / complete_connections))
    print("Maximum time duration: %2f" % max_time)
    print("")
    print("Minimum RTT value: ", min_rtt)
    print("Mean RTT value: ", round(mean_rtt / total_rtt, 6))
    print("Maximum RTT value: ", max_rtt)
    print("")
    print("Minimum number of packets sent/received: ", min_packets)
    print("Mean number of packets sent/received: ", float(mean_packets / complete_connections))
    print("Maximum number of packets sent/received: ", max_packets)
    print("")
    print("Minimum receive window size including sent/received: ", str(min_window) + " bytes")
    print("Mean receive window size including sent/received: %2f " % float(mean_window / total_packets), "bytes")
    print("Maximum receive window size including sent/received: ", str(max_window) + " bytes")


if __name__ == '__main__':
    main()
