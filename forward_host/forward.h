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

#define FORWARD_NIC_1 "enp4s0f0"
#define FORWARD_NIC_2 "enp4s0f1"

#define ETHER_HEADER_LENGTH 14

#define FORWARD_SNAPLEN 2048
#define FORWARD_PROMISC 1
#define FORWARD_TO_MS 1000
#define FORWARD_IMMEDIATE 1

#define PACKET_NUM -1

#define TARGET_MAC_1 "68:91:d0:61:12:3a"
#define TARGET_MAC_2 "68:91:d0:61:12:3b"

#define TIME_RECORD_SIZE 10000

void* packets_forward(void* argv);
void get_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif
