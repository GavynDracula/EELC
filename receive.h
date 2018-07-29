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

#define RECEIVE_NIC "enp4s0f0"

#define ETHER_HEADER_LENGTH 14

#define RECEIVE_SNAPLEN 2048
#define RECEIVE_PROMISC 1
#define RECEIVE_TO_MS 1000
#define RECEIVE_IMMEDIATE 1

#define PACKET_NUM -1

#define LOCAL_MAC "68:91:d0:61:b4:c4"

#define TIME_RECORD_SIZE 10000

void* packets_receive(void* argv);
void get_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif
