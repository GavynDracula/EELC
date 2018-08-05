/*************************************************************************
	> File Name: main.c
	> Author: 
	> Mail: 
	> Created Time: Sat 28 Jul 2018 11:19:43 AM CST
 ************************************************************************/

#include "main.h"

int main(void) {
    int ret;
    void* status;
    char nic_group_1[2][16];
    char nic_group_2[2][16];
    pthread_t forward_thread_1;
    pthread_t forward_thread_2;
    cpu_set_t set;

    sprintf(nic_group_1[0], "%s", FORWARD_NIC_1);
    sprintf(nic_group_1[1], "%s", FORWARD_NIC_2);
    sprintf(nic_group_2[0], "%s", FORWARD_NIC_2);
    sprintf(nic_group_2[1], "%s", FORWARD_NIC_1);

    ret = pthread_create(
        &forward_thread_1, NULL, &packets_forward, nic_group_1
    );
    if (ret != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't create Forward thread 1!");
        exit(1);
    }

    ret = pthread_create(
        &forward_thread_2, NULL, &packets_forward, nic_group_2
    );
    if (ret != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't create Forward thread 2!");
        exit(1);
    }

    CPU_ZERO(&set);
    CPU_SET(4, &set);
    if(pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't set Main's cpu-affinity\n");
        exit(1);
    }
    CPU_ZERO(&set);
    CPU_SET(5, &set);
    if(pthread_setaffinity_np(forward_thread_1, sizeof(set), &set) != 0) {
        fprintf(
            stderr, 
            "Error: EELC-Main: Can't set Forward thread 1's cpu-affinity\n"
        );
        exit(1);
    }
    CPU_ZERO(&set);
    CPU_SET(6, &set);
    if(pthread_setaffinity_np(forward_thread_2, sizeof(set), &set) != 0) {
        fprintf(
            stderr, 
            "Error: EELC-Main: Can't set Forward thread 2's cpu-affinity\n"
        );
        exit(1);
    }

    if (pthread_join(forward_thread_1, &status) != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't end Forward thread 1!");
        exit(2);
    }
    if (pthread_join(forward_thread_2, &status) != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't end Forward thread 2!");
        exit(2);
    }

    fprintf(stdout, "EELC-Main: Receive threads run over\n");

    return 0;
}
