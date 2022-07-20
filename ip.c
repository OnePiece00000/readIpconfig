#include "ip.h"

#include <endian.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static unsigned long scan(register char *s, register unsigned long *u) {
    register unsigned int pos = 0;
    register unsigned long result = 0;
    register unsigned long c;

    while ((c = (unsigned long)(unsigned char)(s[pos] - '0')) < 10) {
        result = result * 10 + c;
        pos++;
    }
    *u = result;
    return pos;
}

ip_t ip_init() {
    ip_t ip;
    ip.address = 0;
    ip.mask = 0;
    return ip;
}

int parse_ip(ip_t *ip, char *ip_str) {
    uint32_t pos;
    char *s = ip_str;
    unsigned long u;

    // Parse IP
    for (int i = 0; i < 4; i++) {
        pos = scan(s, &u);

        if (!pos) {
            return ERROR_IPV4_INVALID_SYMBOL;
        }

        if (u > UINT8_MAX) {
            return ERROR_IPV4_DATA_OVERFLOW;
        }
        s += pos;

        if (*s != '.' && i != 3) {
            return ERROR_IPV4_INVALID_SYMBOL;
        }

        if (*s != '\0') {
            s++;
        }
#if __BYTE_ORDER == __LITTLE_ENDIAN
        ip->bytes[3 - i] = u;
#elif __BYTE_ORDER == __BIG_ENDIAN
        ip->bytes[i] = u;
#endif
    }

    // Parse Mask
    if (*s == '\0' || *(s - 1) != '/') {
        return ERROR_IPV4_NO_MASK;
    }

    if (!scan(s, &u)) {
        return ERROR_IPV4_INVALID_SYMBOL;
    }

    if (u > 32) {
        return ERROR_IPV4_MASK_OVERFLOW;
    }

    ip->mask = (uint8_t)u;

    return IPV4_SUCCESS;
}

char *convert_to_dot_decimal_heap(ip_t *ip) {
    char *buffer = calloc(IP_MAX_STRING_SIZE, sizeof(char));

    if (convert_to_dot_decimal(ip, buffer, IP_MAX_STRING_SIZE) != IPV4_SUCCESS) {
        return NULL;
    }

    return buffer;
}

int convert_to_dot_decimal(ip_t *ip, char *buffer, int size) {
    int result;

    if (size < IP_MAX_STRING_SIZE) {
        return ERROR_IPV4_NOT_ENOUGH_MEMORY;
    }

#if __BYTE_ORDER == __LITTLE_ENDIAN
    result = snprintf(buffer, size, "%u.%u.%u.%u", ip->bytes[3], ip->bytes[2], ip->bytes[1],
                      ip->bytes[0]);
#elif __BYTE_ORDER == __BIG_ENDIAN
    result = snprintf(buffer, size, "%u.%u.%u.%u", ip->bytes[0], ip->bytes[1], ip->bytes[2],
                      ip->bytes[3]);
#endif

    if (result < 0 || result >= size) {
        return ERROR_IPV4_NOT_ENOUGH_MEMORY;
    }

    return IPV4_SUCCESS;
}

int ipv4_str2prefixlen(const char *ip_str) {
    int ret = 0;
    unsigned int ip_num = 0;
    unsigned char c1, c2, c3, c4;
    int cnt = 0;

    ret = sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu", &c1, &c2, &c3, &c4);
    ip_num = c1 << 24 | c2 << 16 | c3 << 8 | c4;

    // fast...
    if (ip_num == 0xffffffff) return 32;
    if (ip_num == 0xffffff00) return 24;
    if (ip_num == 0xffff0000) return 16;
    if (ip_num == 0xff000000) return 8;
    // just in case
    for (int i = 0; i < 32; i++) {
        // unsigned int tmp = (ip_num<<i);
        if ((ip_num << i) & 0x80000000)
            cnt++;
        else
            break;
    }
    return cnt;
}

/**
 *   获取mac地址，成功返回0，失败返回-1
 * **/
int get_mac(char *mac) {
    int sockfd;
    struct ifreq tmp;
    char mac_addr[30];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("create socket fail\n");
        return -1;
    }
    memset(&tmp, 0, sizeof(struct ifreq));
    strncpy(tmp.ifr_name, "eth0", sizeof(tmp.ifr_name) - 1);
    if ((ioctl(sockfd, SIOCGIFHWADDR, &tmp)) < 0) {
        printf("mac ioctl error\n");
        return -1;
    }

    sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)tmp.ifr_hwaddr.sa_data[0],
            (unsigned char)tmp.ifr_hwaddr.sa_data[1], (unsigned char)tmp.ifr_hwaddr.sa_data[2],
            (unsigned char)tmp.ifr_hwaddr.sa_data[3], (unsigned char)tmp.ifr_hwaddr.sa_data[4],
            (unsigned char)tmp.ifr_hwaddr.sa_data[5]);
    close(sockfd);
    memcpy(mac, mac_addr, strlen(mac_addr));
    return 0;
}
