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
    FILE* fp;

    ret = pthread_create(
        &replay_thread, NULL, &pcap_replay, (void*)start_time_record
    );
    if (ret != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't create Replay thread!");
        exit(1);
    }

    ret = pthread_create(
        &receive_thread, NULL, &packets_receive, (void*)end_time_record
    );
    if (ret != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't create Reiceive thread!");
        exit(1);
    }

    if (pthread_join(replay_thread, &status) != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't end Replay thread!");
        exit(2);
    }
    if (pthread_join(receive_thread, &status) != 0) {
        fprintf(stderr, "Error: EELC-Main: Can't end Receive thread!");
        exit(2);
    }

    fprintf(stdout, "EELC-Main: Replay and Receive threads run over\n");
    fprintf(stdout, "EELC-Main: Ready to compute latency and write to file\n");

    if ((fp = fopen(LATENCY_FILE, "w")) == NULL) {
        fprintf(stderr, "Erro: EELC-Main: Can't open file %s\n", LATENCY_FILE);
        exit(3);
    }

    for (int i = 0; i < TIME_RECORD_SIZE; i++) {
        start_time = start_time_record[i];
        end_time = end_time_record[i];
        latency_record[i] = (end_time.tv_sec - start_time.tv_sec) * 1000000;
        latency_record[i] += end_time.tv_usec - start_time.tv_usec;
        fprintf(fp, "%d %lu\n", i, latency_record[i]);
    }

    fclose(fp);

    return 0;
}
