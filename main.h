/*************************************************************************
	> File Name: main.h
	> Author: 
	> Mail: 
	> Created Time: Sat 28 Jul 2018 11:19:37 AM CST
 ************************************************************************/

#ifndef _MAIN_H
#define _MAIN_H

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

#include "replay.h"
#include "receive.h"

#define TIME_RECORD_SIZE 10000
#define LATENCY_FILE "latency.record"

struct timeval start_time_record[TIME_RECORD_SIZE];
struct timeval end_time_record[TIME_RECORD_SIZE];

uint64_t latency_record[TIME_RECORD_SIZE];

#endif
