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
    pthread_t replay_thread;
    pthread_t receive_thread;
    struct timeval start_time;
    struct timeval end_time;

    ret = pthread_create(
        &replay_thread, NULL, &pcap_replay, (void*)start_time_record
    );
    if (ret != 0) {
        fprintf(stderr, "Error: EELC-Main: can't create Replay thread!");
    }

    ret = pthread_create(
        &receive_thread, NULL, &packets_receive, (void*)end_time_record
    );
    if (ret != 0) {
        fprintf(stderr, "Error: EELC-Main: can't create Reiceive thread!");
    }

    if (pthread_join(replay_thread, &status) != 0) {
        fprintf(stderr, "Error: EELC-Main: can't end Replay thread!");
    }
    if (pthread_join(receive_thread, &status) != 0) {
        fprintf(stderr, "Error: EELC-Main: can't end Receive thread!");
    }

    for (int i = 0; i < TIME_RECORD_SIZE; i++) {
        start_time = start_time_record[i];
        end_time = end_time_record[i];
        latency_record[i] = (end_time.tv_sec - start_time.tv_sec) * 1000000;
        latency_record[i] += end_time.tv_usec - start_time.tv_usec;
    }

    return 0;
}
