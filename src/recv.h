/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_RECV_H
#define XMAP_RECV_H

#include "socket.h"
#include <pthread.h>

int recv_update_stats(void);

// Precision of the timestamps handed to process_packet: 1 if the capture was
// opened with nanosecond precision, 0 for microsecond. Valid after recv_init.
extern int recv_pcap_tstamp_nano;

int recv_run(pthread_mutex_t *recv_ready_mutex, sock_t);

#endif // XMAP_RECV_H
