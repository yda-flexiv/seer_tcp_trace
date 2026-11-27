#ifndef SEER_TCP_TRACE_H_
#define SEER_TCP_TRACE_H_

#include "vmlinux.h"
// Common definitions shared by both bpf program and user space program

#define SEER_PORT_STATUS 19204
#define SEER_PORT_CONTORL 19205

struct SeerTcpCommandRecord {
  int16_t cmd;
};

struct SeerTcpHeader {
  uint8_t m_sync;
  uint8_t m_version;
  uint16_t m_number;
  uint32_t m_length;
  uint16_t m_type;
  uint8_t m_reserved[6];
};

#define SEER_TCP_HEADER_MAGIC_BYTE 0x5A

#endif // SEER_TCP_TRACE_H_
