#ifndef IPCONFIG_H
#define IPCONFIG_H

#include <stdbool.h>
#include <inttypes.h>

enum IPConfigAttributeType
{
	InvalidIPConfigAttributeType = -1,
	TerminalIPConfigAttributeType = 0,
	IntegerIPConfigAttributeType = 1,
	StringIPConfigAttributeType = 2,
	LinkIPConfigAttributeType = 3,
	RouteIPConfigAttributeType = 4
};

struct IPConfigAttributeKey
{
	char *key;
	enum IPConfigAttributeType type;
};

struct IPConfigLink
{
	char *address;
	uint32_t prefix;
};

struct IPConfigRoute
{
	struct IPConfigLink destination;
	char *nextHop;
};

union IPConfigValue
{
	uint32_t integer;
	char *string;
	struct IPConfigLink link;
	struct IPConfigRoute route;
};

struct IPConfigAttribute
{
	enum IPConfigAttributeType type;
	char *key;
	union IPConfigValue value;
	struct IPConfigAttribute *next;
};

struct IPConfig
{
	uint32_t version;
	struct IPConfigAttribute *attributes;
};

extern struct IPConfig config;

// extern char static_cfg[4][100] = {
//         "",   //ip mask
//         "",   //gateway
//         "",   //dns1
//         ""    //dns2
// };

extern char static_cfg[6][100];

bool readPackedIPConfig(FILE *stream, struct IPConfig *config);
bool readUnpackedIPConfig(FILE *stream, struct IPConfig *config);
bool writePackedIPConfig(struct IPConfig *config, FILE *stream);
bool writeUnpackedIPConfig(struct IPConfig *config, FILE *stream);

void deinitializeIPConfig(struct IPConfig *config);

int writeipconfig(int argc, char *argv[]);
void printConfig(struct IPConfig *config);
bool genPackedIPConfig(struct IPConfig *config, char *linkAddress, char *gw, char *dns1, char *dns2);
bool genPackedDHCPIPConfig(struct IPConfig *config);

int ipv4_prefixlen2str(int prefixlen, char* ip_str);
int ipv4_str2prefixlen(const char* ip_str);


#endif
