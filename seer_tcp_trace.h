#ifndef SEER_TCP_TRACE_H_
#define SEER_TCP_TRACE_H_

#include "vmlinux.h"
// Common definitions shared by both bpf program and user space program

#define SEER_PORT_STATUS 19204
#define SEER_PORT_CONTORL 19205

struct SeerTcpCommandRecord {
    int16_t cmd;
};

#endif // SEER_TCP_TRACE_H_
