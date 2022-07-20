#include <stdint.h>
#include <utils/Log.h>

#ifndef IPCALC_IP
#define IPCALC_IP

#ifndef IP_MAX_STRING_SIZE
    #define IP_MAX_STRING_SIZE 40
#endif

#define IPV4_SUCCESS 0

#define ERROR_IPV4_DATA_OVERFLOW -1
#define ERROR_IPV4_INVALID_SYMBOL -2
#define ERROR_IPV4_NO_MASK -3
#define ERROR_IPV4_NOT_ENOUGH_MEMORY -4
#define ERROR_IPV4_MASK_OVERFLOW -5

#define INFO(...)            \
    do {                     \
        printf(__VA_ARGS__); \
        printf("\n");        \
        ALOGD(__VA_ARGS__);  \
    } while (0)

typedef struct ip {
    union {
        uint8_t bytes[4];
        uint32_t address;
    };
    uint8_t mask;
} ip_t;

ip_t ip_init();

int parse_ip(ip_t* ip, char* ip_str);
char* convert_to_dot_decimal_heap(ip_t* ip);
int convert_to_dot_decimal(ip_t* ip, char* buffer, int size);
int ipv4_str2prefixlen(const char* ip_str);
int get_mac(char* mac);
#endif
