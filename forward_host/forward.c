/*************************************************************************
	> File Name: receive.c
	> Author: 
	> Mail: 
	> Created Time: Sat 28 Jul 2018 04:12:11 PM CST
 ************************************************************************/

#include "forward.h"

void* packets_forward(void* argv) {
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t* receive_nic;
    pcap_t* send_nic;
    char (*nic_group)[16] = argv;

    fprintf(stdout, "EELC-Forward: Thread is running...\n");

    // receive_nic = pcap_open_live(
        // RECEIVE_NIC, PKT_MAX_SIZE, RECEIVE_PROMISC, TO_MS, err_buf
    // );
    // if (receive_nic == NULL) {
        // fprintf(stderr, "Error: EELC-Receive: pcap_open_live(): %s\n", err_buf);
        // pthread_exit(NULL);
    // }

    receive_nic = pcap_create(nic_group[0], err_buf);
    if (receive_nic == NULL) {
        fprintf(stderr, "Error: EELC-Forward: pcap_create(): %s\n", err_buf);
        pthread_exit(NULL);
    }
    if (pcap_set_promisc(receive_nic, FORWARD_PROMISC) != 0) {
        fprintf(stderr, "Error: EELC-Forward: pcap_set_promisc() fails\n");
        pthread_exit(NULL);
    }
    if (pcap_set_snaplen(receive_nic, FORWARD_SNAPLEN) != 0) {
        fprintf(stderr, "Error: EELC-Forward: pcap_set_snaplen() fails\n");
        pthread_exit(NULL);
    }
    if (pcap_set_timeout(receive_nic, FORWARD_TO_MS) != 0) {
        fprintf(stderr, "Error: EELC-Forward: pcap_set_timeout() fails\n");
        pthread_exit(NULL);
    }
    if (pcap_set_immediate_mode(receive_nic, FORWARD_IMMEDIATE) != 0) {
        fprintf(
            stderr, "Error: EELC-Forward: pcap_set_immediate_mode() fails\n"
        );
        pthread_exit(NULL);
    }
    if (pcap_activate(receive_nic) != 0) {
        fprintf(stderr,"Error: EELC-Forward: pcap_activate() fails\n");
        pthread_exit(NULL);
    }

    send_nic = pcap_create(nic_group[1], err_buf);
    if (send_nic == NULL) {
        fprintf(stderr, "Error: EELC-Forward: pcap_create(): %s\n", err_buf);
        pthread_exit(NULL);
    }
    if (pcap_set_promisc(send_nic, FORWARD_PROMISC) != 0) {
        fprintf(stderr, "Error: EELC-Forward: pcap_set_promisc() fails\n");
        pthread_exit(NULL);
    }
    if (pcap_set_snaplen(send_nic, FORWARD_SNAPLEN) != 0) {
        fprintf(stderr, "Error: EELC-Forward: pcap_set_snaplen() fails\n");
        pthread_exit(NULL);
    }
    if (pcap_set_timeout(send_nic, FORWARD_TO_MS) != 0) {
        fprintf(stderr, "Error: EELC-Forward: pcap_set_timeout() fails\n");
        pthread_exit(NULL);
    }
    if (pcap_set_immediate_mode(send_nic, FORWARD_IMMEDIATE) != 0) {
        fprintf(
            stderr, "Error: EELC-Forward: pcap_set_immediate_mode() fails\n"
        );
        pthread_exit(NULL);
    }
    if (pcap_activate(send_nic) != 0) {
        fprintf(stderr,"Error: EELC-Forward: pcap_activate() fails\n");
        pthread_exit(NULL);
    }

    pcap_loop(receive_nic, PACKET_NUM, get_packet, (u_char*)send_nic);

    fprintf(stdout, "EELC-Forward: Ready to exit thread.\n");

    pcap_close(receive_nic);
    pcap_close(send_nic);

    return NULL;
}

void get_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    pcap_t* send_nic = (pcap_t*)arg;
    struct ether_header* eth_header;
    u_char target_mac_1[6];
    u_char target_mac_2[6];
    int i;

    eth_header = (struct ether_header*)packet;
    sscanf(
        TARGET_MAC_1, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        target_mac_1 + 5, target_mac_1 + 4, target_mac_1 + 3,
        target_mac_1 + 2, target_mac_1 + 1, target_mac_1 + 0
    );
    sscanf(
        TARGET_MAC_2, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        target_mac_2 + 5, target_mac_2 + 4, target_mac_2 + 3,
        target_mac_2 + 2, target_mac_2 + 1, target_mac_2 + 0
    );
    for (i = 0; i < 6; i++) {
        if (eth_header->ether_dhost[i] != target_mac_1[i] && 
            eth_header->ether_dhost[i] != target_mac_2[i]) {
            return;
        }
    }
    if (pcap_inject(send_nic, packet, pkthdr->caplen) == -1) {
        fprintf(
            stderr, 
            "Error: EELC-Receive: pcap_inject(): send packet error\n"
        );
    }
    return;
}
