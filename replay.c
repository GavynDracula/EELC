/*************************************************************************
	> File Name: replay.c
	> Author: 
	> Mail: 
	> Created Time: Sat 28 Jul 2018 11:20:20 AM CST
 ************************************************************************/

#include "replay.h"

void* pcap_replay(void* argv) {

    const u_char *packet;
    struct pcap_pkthdr pkthdr;
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t* replay_nic;
    pcap_t* pcap_file;
    uint16_t packet_count = 0;
    // struct replay_arg* args = (struct replay_arg*)argv;
    struct timeval* start_time_record = (struct timeval*)argv;

    replay_nic = pcap_open_live(REPLAY_NIC, PKT_MAX_SIZE, REPLAY_PROMISC, TO_MS, err_buf);
    if (replay_nic == NULL) {
        fprintf(stderr, "Error: EELC-Replay: pcap_open_live(): %s\n", err_buf);
    }

    pcap_file = pcap_open_offline(PCAP_FILE, err_buf);
    if (pcap_file == NULL) {
        fprintf(stderr, "Error: EELC-Replay: pcap_open_offline(): %s\n", err_buf);
    }

    packet = pcap_next(pcap_file, &pkthdr);
    while (packet != NULL && packet_count < TIME_RECORD_SIZE) {
        struct ether_header* eth_header;
        eth_header = (struct ether_header*)packet;
        sscanf(
                LOCAL_MAC, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                eth_header->ether_shost, 
                eth_header->ether_shost + 1, 
                eth_header->ether_shost + 2, 
                eth_header->ether_shost + 3, 
                eth_header->ether_shost + 4, 
                eth_header->ether_shost + 5
              );
        sscanf(
                TARGET_MAC, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                eth_header->ether_dhost, 
                eth_header->ether_dhost + 1, 
                eth_header->ether_dhost + 2, 
                eth_header->ether_dhost + 3, 
                eth_header->ether_dhost + 4, 
                eth_header->ether_dhost + 5
              );
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            const u_char* ip_header;
            u_char protocol;
            ip_header = packet + ETHER_HEADER_LENGTH;
            protocol = *(ip_header + 9);
            if (protocol == IPPROTO_TCP) {
                const u_char* tcp_header;
                unsigned int ip_header_length;
                ip_header_length = (*ip_header) & 0x0F;
                ip_header_length = ip_header_length * 4;
                tcp_header = ip_header + ip_header_length;
                *((uint16_t*)(tcp_header + 18)) = htons(packet_count);
                gettimeofday(&start_time_record[packet_count], NULL);
                packet_count += 1;
            }
        }
        usleep(SEND_DELAY_US);
        if (pcap_sendpacket(replay_nic, packet, pkthdr.caplen) != 0) {
            fprintf(
                stderr, 
                "Error: EELC-Replay: pcap_sendpacket(): send packet error\n"
            );
        }
        packet = pcap_next(pcap_file, &pkthdr);
    }

    pcap_close(replay_nic);
    pcap_close(pcap_file);

    return NULL;
}

