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
    pthread_t receive_thread;
    cpu_set_t set;

    ret = pthread_create(&receive_thread, NULL, &packets_receive, NULL);
    if (ret != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't create Reiceive thread!");
        exit(1);
    }

    CPU_ZERO(&set);
    CPU_SET(6, &set);
    if(pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't set Main's cpu-affinity\n");
        exit(1);
    }
    CPU_ZERO(&set);
    CPU_SET(8, &set);
    if(pthread_setaffinity_np(receive_thread, sizeof(set), &set) != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't set Receive's cpu-affinity\n");
        exit(1);
    }

    if (pthread_join(receive_thread, &status) != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't end Receive thread!");
        exit(2);
    }

    fprintf(stdout, "EELC-Main: Receive threads run over\n");

    return 0;
}
