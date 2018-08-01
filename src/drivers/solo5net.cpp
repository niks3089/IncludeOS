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

Solo5Net::Solo5Net(uint8_t nic_index)
  : nic_index_(nic_index), Link(Link_protocol{{this, &Solo5Net::transmit}, mac()}),
    packets_rx_{Statman::get().create(Stat::UINT64, device_name() + ".packets_rx").get_uint64()},
    packets_tx_{Statman::get().create(Stat::UINT64, device_name() + ".packets_tx").get_uint64()},
    bufstore_{NUM_BUFFERS, 2048u} // don't change this
{
  uint8_t macaddr[6];
  INFO("Solo5Net", "Driver initializing");

  struct solo5_net_info ni;
  solo5_net_info(nic_index, &ni);
  mac_addr = MAC::Addr(ni.mac_address[0], ni.mac_address[1], ni.mac_address[2],
                       ni.mac_address[3], ni.mac_address[4], ni.mac_address[5]);
}

void Solo5Net::transmit(net::Packet_ptr pckt)
{
  net::Packet_ptr tail = std::move(pckt);

  // Transmit all we can directly
  while (tail) {
    // next in line
    auto next = tail->detach_tail();
    // write data to network
    solo5_net_write(nic_index_, tail->buf(), tail->size());
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
  size_t size = packet_len();
  if (solo5_net_read(nic_index_, pckt->buf(), size, &size) == 0) {
    // Adjust packet size to match received data
    if (size) {
      pckt->set_data_end(size);
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
