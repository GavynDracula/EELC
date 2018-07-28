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

    fprintf(stdout, "EELC-Replay: Thread is running...\n");

    replay_nic = pcap_open_live(REPLAY_NIC, PKT_MAX_SIZE, REPLAY_PROMISC, TO_MS, err_buf);
    if (replay_nic == NULL) {
        fprintf(stderr, "Error: EELC-Replay: pcap_open_live(): %s\n", err_buf);
        pthread_exit(NULL);
    }

    pcap_file = pcap_open_offline(PCAP_FILE, err_buf);
    if (pcap_file == NULL) {
        fprintf(stderr, "Error: EELC-Replay: pcap_open_offline(): %s\n", err_buf);
        pthread_exit(NULL);
    }

    packet = pcap_next(pcap_file, &pkthdr);
    fprintf(stdout, "EELC-Replay: Begin to replay packets\n");
    while (packet != NULL && packet_count < TIME_RECORD_SIZE) {
        struct ether_header* eth_header;
        eth_header = (struct ether_header*)packet;
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
                /* Modify Ethernet Address */
                *((uint16_t*)(ip_header + 10)) = 0;
                sscanf(
                    LOCAL_MAC, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                    eth_header->ether_shost, 
                    eth_header->ether_shost + 1, 
                    eth_header->ether_shost + 2, 
                    eth_header->ether_shost + 3, 
                    eth_header->ether_shost + 4, 
                    eth_header->ether_shost + 5
                );
                fprintf(
                    stdout, 
                    "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx\n", 
                    eth_header->ether_shost[0], 
                    eth_header->ether_shost[1], 
                    eth_header->ether_shost[2], 
                    eth_header->ether_shost[3], 
                    eth_header->ether_shost[4], 
                    eth_header->ether_shost[5]
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
                *((uint16_t*)(ip_header + 10)) = 
                    htons(ip_checksum((void*)ip_header, ip_header_length));
                gettimeofday(&start_time_record[packet_count], NULL);
                packet_count += 1;
                if (packet_count % 1000 == 0) {
                    fprintf(
                        stdout, 
                        "EELC-Replay: %d packets(used for "
                        "latency computing) has been sent\n", 
                        packet_count
                    );
                }
            }
        }
        if (pcap_sendpacket(replay_nic, packet, pkthdr.caplen) != 0) {
            fprintf(
                stderr, 
                "Error: EELC-Replay: pcap_sendpacket(): send packet error\n"
            );
        }
        usleep(SEND_DELAY_US);
        packet = pcap_next(pcap_file, &pkthdr);
    }

    fprintf(stdout, "EELC-Replay: Packets sent over. Ready to exit thread.\n");

    pcap_close(replay_nic);
    pcap_close(pcap_file);

    return NULL;
}

uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}
