/*************************************************************************
	> File Name: receive.c
	> Author: 
	> Mail: 
	> Created Time: Sat 28 Jul 2018 04:12:11 PM CST
 ************************************************************************/

#include "receive.h"

void* packets_receive(void* argv) {
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t* receive_nic;

    fprintf(stdout, "EELC-Receive: Thread is running...\n");

    receive_nic = pcap_open_live(
        RECEIVE_NIC, PKT_MAX_SIZE, RECEIVE_PROMISC, TO_MS, err_buf
    );
    if (receive_nic == NULL) {
        fprintf(stderr, "Error: EELC-Receive: pcap_open_live(): %s\n", err_buf);
        pthread_exit(NULL);
    }

    pcap_loop(receive_nic, PACKET_NUM, get_packet, (u_char*)argv);

    fprintf(
        stdout, 
        "EELC-Receive: Last packet is received. Ready to exit thread.\n"
    );

    pcap_close(receive_nic);

    return NULL;
}

void get_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // struct timeval* end_time_record = (struct timeval*)arg;
    struct timespec* end_time_record = (struct timespec*)arg;
    struct ether_header* eth_header;
    u_char local_mac[6];

    eth_header = (struct ether_header*)packet;
    sscanf(
        LOCAL_MAC, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        local_mac + 5, local_mac + 4, local_mac + 3,
        local_mac + 2, local_mac + 1, local_mac + 0
    );
    for (int i = 0; i < 6; i++) {
        if (eth_header->ether_dhost[i] != local_mac[i]) {
            return;
        }
    }
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        const u_char* ip_header;
        u_char protocol;
        uint16_t packet_count;
        ip_header = packet + ETHER_HEADER_LENGTH;
        protocol = *(ip_header + 9);
        if (protocol == IPPROTO_TCP) {
            const u_char* tcp_header;
            unsigned int ip_header_length;
            ip_header_length = (*ip_header) & 0x0F;
            ip_header_length = ip_header_length * 4;
            tcp_header = ip_header + ip_header_length;
            packet_count = ntohs(*((uint16_t*)(tcp_header + 18)));
            // gettimeofday(&end_time_record[packet_count], NULL);
            clock_gettime(CLOCK_REALTIME, &end_time_record[packet_count]);
            if (packet_count % 1000 == 999) {
                fprintf(
                    stdout, 
                    "EELC-Receive: %d packets(used for "
                    "latency computing) has been received\n", 
                    packet_count + 1
                );
            }
            if (packet_count == TIME_RECORD_SIZE - 1) {
                fprintf(
                    stdout, 
                    "EELC-Receive: Last packet is received."
                    " Ready to exit thread.\n"
                );
                pthread_exit(NULL);
            }
        }
    }
    return;
}
