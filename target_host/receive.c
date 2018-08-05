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

    // receive_nic = pcap_open_live(
        // RECEIVE_NIC, PKT_MAX_SIZE, RECEIVE_PROMISC, TO_MS, err_buf
    // );
    // if (receive_nic == NULL) {
        // fprintf(stderr, "Error: EELC-Receive: pcap_open_live(): %s\n", err_buf);
        // pthread_exit(NULL);
    // }

    receive_nic = pcap_create(RECEIVE_NIC, err_buf);
    if (receive_nic == NULL) {
        fprintf(stderr, "Error: EELC-Receive: pcap_create(): %s\n", err_buf);
        pthread_exit(NULL);
    }
    if (pcap_set_promisc(receive_nic, RECEIVE_PROMISC) != 0) {
        fprintf(stderr, "Error: EELC-Receive: pcap_set_promisc() fails\n");
        pthread_exit(NULL);
    }
    if (pcap_set_snaplen(receive_nic, RECEIVE_SNAPLEN) != 0) {
        fprintf(stderr, "Error: EELC-Receive: pcap_set_snaplen() fails\n");
        pthread_exit(NULL);
    }
    if (pcap_set_timeout(receive_nic, RECEIVE_TO_MS) != 0) {
        fprintf(stderr, "Error: EELC-Receive: pcap_set_timeout() fails\n");
        pthread_exit(NULL);
    }
    if (pcap_set_immediate_mode(receive_nic, RECEIVE_IMMEDIATE) != 0) {
        fprintf(
            stderr, "Error: EELC-Receive: pcap_set_immediate_mode() fails\n"
        );
        pthread_exit(NULL);
    }
    if (pcap_activate(receive_nic) != 0) {
        fprintf(stderr,"Error: EELC-Receive: pcap_activate() fails\n");
        pthread_exit(NULL);
    }

    pcap_loop(receive_nic, PACKET_NUM, get_packet, (u_char*)receive_nic);

    fprintf(stdout, "EELC-Receive: Ready to exit thread.\n");

    pcap_close(receive_nic);

    return NULL;
}

void get_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    pcap_t* receive_nic = (pcap_t*)arg;
    struct ether_header* eth_header;
    u_char target_mac[6];
    int i;

    eth_header = (struct ether_header*)packet;
    sscanf(
        TARGET_MAC, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        target_mac + 5, target_mac + 4, target_mac + 3,
        target_mac + 2, target_mac + 1, target_mac + 0
    );
    for (i = 0; i < 6; i++) {
        if (eth_header->ether_dhost[i] != target_mac[i]) {
            return;
        }
    }
    for (i = 0; i < 6; i++) {
        eth_header->ether_dhost[i] = eth_header->ether_shost[i];
        eth_header->ether_shost[i] = target_mac[i];
    }
    if (pcap_inject(receive_nic, packet, pkthdr->caplen) == -1) {
        fprintf(
            stderr, 
            "Error: EELC-Receive: pcap_inject(): send packet error\n"
        );
    }
    return;
}
