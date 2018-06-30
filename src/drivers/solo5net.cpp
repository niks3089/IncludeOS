// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "solo5net.hpp"
#include <net/packet.hpp>
#include <hw/pci.hpp>
#include <cstdio>
#include <cstring>

extern "C" {
#include <solo5.h>
}
static const uint32_t NUM_BUFFERS = 1024;
using namespace net;

const char* Solo5Net::driver_name() const { return "Solo5Net"; }

static void tohexs(char *dst, uint8_t *src, size_t size)
{
    while (size--) {
        uint8_t n = *src >> 4;
        *dst++ = (n < 10) ? (n + '0') : (n - 10 + 'a');
        n = *src & 0xf;
        *dst++ = (n < 10) ? (n + '0') : (n - 10 + 'a');
        src++;
    }
    *dst = '\0';
}

Solo5Net::Solo5Net()
  : Link(Link_protocol{{this, &Solo5Net::transmit}, mac()}),
    packets_rx_{Statman::get().create(Stat::UINT64, device_name() + ".packets_rx").get_uint64()},
    packets_tx_{Statman::get().create(Stat::UINT64, device_name() + ".packets_tx").get_uint64()},
    bufstore_{NUM_BUFFERS, 2048u} // don't change this
{
  uint8_t macaddr[6];
  INFO("Solo5Net", "Driver initializing");

  struct solo5_net_info ni;
  solo5_net_info(0, &ni);
  memcpy(macaddr, ni.mac_address, sizeof macaddr);
  char macaddr_s[(sizeof macaddr * 2) + 1];
  tohexs(macaddr_s, macaddr, sizeof macaddr);

  mac_addr = MAC::Addr(macaddr_s);
}

void Solo5Net::transmit(net::Packet_ptr pckt)
{
  net::Packet_ptr tail = std::move(pckt);

  // Transmit all we can directly
  while (tail) {
    // next in line
    auto next = tail->detach_tail();
    // write data to network
    solo5_net_write(0, tail->buf(), tail->size());
    // set tail to next, releasing tail
    tail = std::move(next);
    // Stat increase packets transmitted
    packets_tx_++;
  }

  // Buffer the rest
  if (UNLIKELY(tail)) {
    INFO("solo5net", "Could not send all packets..\n");
  }
}

net::Packet_ptr Solo5Net::create_packet(int link_offset)
{
  auto buffer = bufstore().get_buffer();
  auto* pckt = (net::Packet*) buffer.addr;

  new (pckt) net::Packet(link_offset, 0, packet_len(), buffer.bufstore);
  return net::Packet_ptr(pckt);
}

net::Packet_ptr Solo5Net::recv_packet()
{
  auto buffer = bufstore().get_buffer();
  auto* pckt = (net::Packet*) buffer.addr;
  new (pckt) net::Packet(0, MTU(), packet_len(), buffer.bufstore);
  // Populate the packet buffer with new packet, if any
  int size = packet_len();
  size_t len = 0;
  if (solo5_net_read(0, pckt->buf(), size, &len) == SOLO5_R_OK) {
      // Adjust packet size to match received data
      if (len) {
        //INFO("Solo5Net", "Received pkt of len: %u", len);
        pckt->set_data_end(len);
        return net::Packet_ptr(pckt);
      }
  }
  bufstore().release(buffer.addr);
  return nullptr;
}

void Solo5Net::poll()
{
  auto pckt_ptr = recv_packet();
  while (pckt_ptr != nullptr) {
    Link::receive(std::move(pckt_ptr));
    pckt_ptr = recv_packet();
  }
}

void Solo5Net::deactivate()
{
  INFO("Solo5Net", "deactivate");
}

#include <kernel/solo5_manager.hpp>

struct Autoreg_solo5net {
  Autoreg_solo5net() {
    Solo5_manager::register_net(&Solo5Net::new_instance);
  }
} autoreg_solo5net;
