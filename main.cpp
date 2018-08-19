// Copyright (C) 2018 Jiajie Chen
// 
// This file is part of gretapmac.
// 
// gretapmac is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// gretapmac is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with gretapmac.  If not, see <http://www.gnu.org/licenses/>.
// 

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <cstdio>
#include <cassert>
#include <string>
#include <thread>

struct gre {
    uint8_t checksum : 1;
    uint8_t routing : 1;
    uint8_t key : 1;
    uint8_t seq : 1;
    uint16_t res0 : 9;
    uint8_t version : 3;
    uint16_t ether_type;
};

int gretap_fd, tap_fd;
std::string local_ip, remote_ip, tap_if;
struct in_addr local_ipaddr, remote_ipaddr;
const size_t iphdr_len = 20;
const size_t encap_len = iphdr_len + sizeof(struct gre);
const size_t ether_encap_type = 0x6558;


// reference: https://sock-raw.org/papers/sock_raw

void gre_to_tap() {
    uint8_t buffer[4096];
    struct ip *iphdr = (struct ip*)buffer;
    while(1) {
        ssize_t size = recv(gretap_fd, buffer, sizeof(buffer), 0);
        size_t offset = iphdr->ip_hl * 4;
        size_t hdrlen = iphdr->ip_hl * 4 + sizeof(gre);
        if (size < 0) {
            perror("recv");
        }

        if (iphdr->ip_src.s_addr != remote_ipaddr.s_addr || iphdr->ip_dst.s_addr != local_ipaddr.s_addr) {
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iphdr->ip_src, src, sizeof(src));
            inet_ntop(AF_INET, &iphdr->ip_dst, dst, sizeof(dst));
            printf("GRE packet from %s to %s, ignoring\n", src, dst);
            continue;
        }

        struct gre *hdr = (struct gre*)(buffer + offset);
        assert(hdr->checksum == 0);
        assert(hdr->routing == 0);
        assert(hdr->key == 0);
        assert(hdr->seq == 0);

        uint16_t ether_type = ntohs(hdr->ether_type);
        if (ether_type == ether_encap_type) {
            // GRETAP
            if (write(tap_fd, buffer+hdrlen, size - hdrlen) < 0) {
                perror("write");
            }
        }
    }
}

void tap_to_gre() {
    uint8_t buffer[4096] = {0};

    struct ip *iphdr = (struct ip*)buffer;
    struct gre *grehdr = (struct gre*)(buffer + iphdr_len);
    uint8_t *begin = buffer + encap_len;

    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_id = 0;
    iphdr->ip_off = 0;
    iphdr->ip_ttl = IPDEFTTL;
    iphdr->ip_p = IPPROTO_GRE;

    iphdr->ip_src = local_ipaddr;
    inet_pton(AF_INET, local_ip.c_str(), &iphdr->ip_src);
    struct sockaddr_in daddr;
    daddr.sin_family = AF_INET;
    daddr.sin_port = 0;
    daddr.sin_addr = remote_ipaddr;
    iphdr->ip_dst = remote_ipaddr;

    grehdr->ether_type = htons(ether_encap_type);

    int header_crafted = 1;
    if (setsockopt(gretap_fd, IPPROTO_IP, IP_HDRINCL, &header_crafted, sizeof(header_crafted)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    while(1) {
        ssize_t size = read(tap_fd, begin, sizeof(buffer) - encap_len);
        if (size < 0) {
            perror("recv");
        }
        iphdr->ip_len = size + encap_len; // conversion to network byte order is made by OS
        if (sendto(gretap_fd, buffer, size + encap_len, 0, (struct sockaddr*)&daddr, sizeof(daddr)) < 0) {
            perror("sendto");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: gretapmac [tap_if] [local_ip] [remote_ip]\n");
        printf("\tequivalent to: ip link add [tap_if] type gretap local [local_ip] remote [remote_ip]\n");
        return 1;
    }
    tap_if = argv[1];
    local_ip = argv[2];
    inet_pton(AF_INET, local_ip.c_str(), &local_ipaddr);
    remote_ip = argv[3];
    inet_pton(AF_INET, remote_ip.c_str(), &remote_ipaddr);

    if ((gretap_fd = socket(PF_INET, SOCK_RAW, IPPROTO_GRE)) < 0) {
        perror("socket");
        return 1;
    }

    std::string device_name = "/dev/";
    device_name += tap_if;
    if ((tap_fd = open(device_name.c_str(), O_RDWR)) < 0) {
        perror("socket");
        return 1;
    }
    // dangerous, I know it
    std::string command = "ifconfig ";
    command += tap_if;
    command += " up";
    system(command.c_str());

    std::thread t1(gre_to_tap);
    std::thread t2(tap_to_gre);
    t1.join();
    t2.join();
    return 0;
}