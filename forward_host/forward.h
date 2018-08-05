/*************************************************************************
	> File Name: receive.h
	> Author: 
	> Mail: 
	> Created Time: Sat 28 Jul 2018 04:12:14 PM CST
 ************************************************************************/

#ifndef _RECEIVE_H
#define _RECEIVE_H

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <pthread.h>
#include <sys/time.h>

#define FORWARD_NIC_1 "enp2s0f0"
#define FORWARD_NIC_2 "enp2s0f1"

#define ETHER_HEADER_LENGTH 14

#define FORWARD_SNAPLEN 2048
#define FORWARD_PROMISC 1
#define FORWARD_TO_MS 1000
#define FORWARD_IMMEDIATE 1

#define PACKET_NUM -1

#define TARGET_MAC_1 "00:1b:21:93:33:d9"
#define TARGET_MAC_2 "00:1b:21:93:33:d8"

#define TIME_RECORD_SIZE 10000

struct forward_thread_arg {
    char nic_group[2][16];
    char target_mac[20];
};

struct pcap_loop_arg {
    pcap_t* send_nic;
    char* target_mac;
};

void* packets_forward(void* argv);
void get_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif
