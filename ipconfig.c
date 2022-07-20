#define _DEFAULT_SOURCE

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include "data.h"
#include "ipconfig.h"
#include "error.h"

#define calculateElementCount(array) (sizeof array / sizeof *array)

static const uint32_t IPConfigFileMinimumVersion = 1;
static const uint32_t IPConfigFileMaximumVersion = 3;

static char *IPConfigTerminatorKey = "eos";

static struct IPConfigAttributeKey IPConfigVersion1AttributeKeys[] =
{
	{"id", IntegerIPConfigAttributeType},
	{"ipAssignment", StringIPConfigAttributeType},
	{"linkAddress", LinkIPConfigAttributeType},
	{"gateway", StringIPConfigAttributeType},
	{"dns", StringIPConfigAttributeType},
	{"proxySettings", StringIPConfigAttributeType},
	{"proxyHost", StringIPConfigAttributeType},
	{"proxyPort", IntegerIPConfigAttributeType},
	{"proxyPac", StringIPConfigAttributeType},
	{"exclusionList", StringIPConfigAttributeType},
	{"eos", TerminalIPConfigAttributeType}
};

static size_t IPConfigVersion1AttributeKeyCount = 
	calculateElementCount(IPConfigVersion1AttributeKeys);

static struct IPConfigAttributeKey IPConfigVersion2AttributeKeys[] =
{
	{"id", IntegerIPConfigAttributeType},
	{"ipAssignment", StringIPConfigAttributeType},
	{"linkAddress", LinkIPConfigAttributeType},
	{"gateway", RouteIPConfigAttributeType},
	{"dns", StringIPConfigAttributeType},
	{"proxySettings", StringIPConfigAttributeType},
	{"proxyHost", StringIPConfigAttributeType},
	{"proxyPort", IntegerIPConfigAttributeType},
	{"proxyPac", StringIPConfigAttributeType},
	{"exclusionList", StringIPConfigAttributeType},
	{"eos", TerminalIPConfigAttributeType}
};

static size_t IPConfigVersion2AttributeKeyCount = 
	calculateElementCount(IPConfigVersion2AttributeKeys);

static struct IPConfigAttributeKey IPConfigVersion3AttributeKeys[] =
{
	{"id", StringIPConfigAttributeType},
	{"ipAssignment", StringIPConfigAttributeType},
	{"linkAddress", LinkIPConfigAttributeType},
	{"gateway", RouteIPConfigAttributeType},
	{"dns", StringIPConfigAttributeType},
	{"proxySettings", StringIPConfigAttributeType},
	{"proxyHost", StringIPConfigAttributeType},
	{"proxyPort", IntegerIPConfigAttributeType},
	{"proxyPac", StringIPConfigAttributeType},
	{"exclusionList", StringIPConfigAttributeType},
	{"eos", TerminalIPConfigAttributeType}
};

static size_t IPConfigVersion3AttributeKeyCount = 
	calculateElementCount(IPConfigVersion3AttributeKeys);

static enum IPConfigAttributeType getAttributeType(uint32_t version, char *key)
{
	size_t keyLength = strlen(key);

	struct IPConfigAttributeKey *keys = NULL;
	size_t count = 0;

	switch (version)
	{
		case 1:
			keys = IPConfigVersion1AttributeKeys;
			count = IPConfigVersion1AttributeKeyCount;
			break;

		case 2:
			keys = IPConfigVersion2AttributeKeys;
			count = IPConfigVersion2AttributeKeyCount;
			break;

		case 3:
			keys = IPConfigVersion3AttributeKeys;
			count = IPConfigVersion3AttributeKeyCount;
			break;

		default:
			break;
	};

	for (size_t index = 0; index < count; index++)
	{
		char *candidate = keys[index].key;
		size_t maximumLength = strlen(candidate);

		if (keyLength > maximumLength)
		{
			maximumLength = keyLength;
		}

		if (!strncmp(candidate, key, maximumLength))
		{
			return keys[index].type;
		}
	}

	return InvalidIPConfigAttributeType;
}

static void appendAttribute(struct IPConfigAttribute *attribute,
                            struct IPConfig *config)
{
	if (!config->attributes)
	{
		config->attributes = attribute;
	}

	else
	{
		struct IPConfigAttribute *previous = config->attributes;

		while (previous->next)
		{
			previous = previous->next;
		}

		previous->next = attribute;
	}
}

bool readPackedIPConfig(FILE *stream, struct IPConfig *config)
{

	if (!readPackedUInt32(stream, &config->version))
	{
		printError("failed to read file version");
		return NULL;
	}
	
	if (config->version < IPConfigFileMinimumVersion ||
	    config->version > IPConfigFileMaximumVersion)
	{
		printError("unrecognized file version");
		return NULL;
	}

	while (!feof(stream))
	{
		struct IPConfigAttribute *attribute = NULL;
		attribute = calloc(1, sizeof(struct IPConfigAttribute));

		if (!attribute)
		{
			printLibraryError("calloc");
			deinitializeIPConfig(config);
			return NULL;
		}

		appendAttribute(attribute, config);

		if (!readPackedString(stream, &attribute->key))
		{
			printError("failed to read attribute key");
			deinitializeIPConfig(config);
			return NULL;
		}

		attribute->type = getAttributeType(config->version,
		                                   attribute->key);

		if (attribute->type == InvalidIPConfigAttributeType)
		{
			printError("unrecognized attribute key");
			deinitializeIPConfig(config);
			return NULL;
		}

		else if (attribute->type == TerminalIPConfigAttributeType)
		{
			break;
		}

		else if (attribute->type == IntegerIPConfigAttributeType)
		{
			uint32_t *integer = &attribute->value.integer;

			if (!readPackedUInt32(stream, integer))
			{
				printError("failed to read integer");
				deinitializeIPConfig(config);
				return NULL;
			}
		}

		else if (attribute->type == StringIPConfigAttributeType)
		{
			char **string = &attribute->value.string;

			if (!readPackedString(stream, string))
			{
				printError("failed to read string");
				deinitializeIPConfig(config);
				return NULL;
			}
		}

		else if (attribute->type == LinkIPConfigAttributeType)
		{
			if (!readPackedLink(stream, &attribute->value.link))
			{
				printError("failed to read link");
				deinitializeIPConfig(config);
				return NULL;
			}
		}

		else if (attribute->type == RouteIPConfigAttributeType)
		{
			if (!readPackedRoute(stream, &attribute->value.route))
			{
				printError("failed to read route");
				deinitializeIPConfig(config);
				return NULL;
			}
		}
	}

	return config;
}

void deinitializeIPConfig(struct IPConfig *config)
{
	struct IPConfigAttribute *next = NULL;
	struct IPConfigAttribute *attribute = config->attributes;

	while (attribute)
	{
		union IPConfigValue *value = &attribute->value;

		if (attribute->type == StringIPConfigAttributeType)
		{
			free(value->string);
		}

		else if (attribute->type == LinkIPConfigAttributeType)
		{
			free(value->link.address);
		}

		else if (attribute->type == RouteIPConfigAttributeType)
		{
			if (value->route.destination.address)
			{
				free(value->route.destination.address);
			}

			if (value->route.nextHop)
			{
				free(value->route.nextHop);
			}
		}

		next = attribute->next;	
		free(attribute->key);
		free(attribute);
		attribute = next;
	}
}

bool writePackedIPConfig(struct IPConfig *config, FILE *stream)
{
	bool terminated = false;
	struct IPConfigAttribute *attribute = config->attributes;

	if (!writePackedUInt32(config->version, stream))
	{
		printError("failed to write file version");
		return false;
	}

	while (attribute)
	{
		union IPConfigValue *value = &attribute->value;

		if (!writePackedString(attribute->key, stream))
		{
			printError("failed to write key");
			return false;
		}

		if (attribute->type == TerminalIPConfigAttributeType)
		{
			terminated = true;
			break;
		}

		else if (attribute->type == IntegerIPConfigAttributeType)
		{
			if (!writePackedUInt32(value->integer, stream))
			{
				printError("failed to write integer");
				return false;
			}
		}

		else if (attribute->type == StringIPConfigAttributeType)
		{
			if (!writePackedString(value->string, stream))
			{
				printError("failed to write string");
				return false;
			}
		}

		else if (attribute->type == LinkIPConfigAttributeType)
		{
			if (!writePackedLink(&value->link, stream))
			{
				printError("failed to write link");
				return false;
			}
		}

		else if (attribute->type == RouteIPConfigAttributeType)
		{
			if (!writePackedRoute(&value->route, stream))
			{
				printError("failed to write route");
				return false;
			}
		}

		attribute = attribute->next;
	}

	if (!terminated)
	{
		if (!writePackedString(IPConfigTerminatorKey, stream))
		{
			printError("failed to write terminator");
			return false;
		}
	}

	return true;
}

bool writeUnpackedIPConfig(struct IPConfig *config, FILE *stream)
{
	struct IPConfigAttribute *attribute = config->attributes;

	while (attribute)
	{
		if (attribute->type == IntegerIPConfigAttributeType)
		{
			fprintf(stream, "%s: %" PRIu32 "\n",
			                attribute->key,
			                attribute->value.integer);
		}

		else if (attribute->type == StringIPConfigAttributeType)
		{
			fprintf(stream, "%s: %s\n",
			                attribute->key,
			                attribute->value.string);
		}

		else if (attribute->type == LinkIPConfigAttributeType)
		{
			struct IPConfigLink *link = &attribute->value.link;

			fprintf(stream, "%s: %s/%" PRIu32 "\n",
			                attribute->key,
			                link->address,
			                link->prefix);
		}

		else if (attribute->type == RouteIPConfigAttributeType)
		{
			struct IPConfigRoute *route = &attribute->value.route;
			struct IPConfigLink *destination = &route->destination;

			if (destination->address && destination->prefix)
			{
				fprintf(stream, "%s: %s/%" PRIu32 " %s\n",
			                        attribute->key,
			                        destination->address,
			                        destination->prefix,
			                        route->nextHop);
			}

			else
			{
				fprintf(stream, "%s: %s\n",
			                        attribute->key,
			                        route->nextHop);
			}
		}

		attribute = attribute->next;
	}

	return true;
}

bool readUnpackedIPConfig(FILE *stream, struct IPConfig *config)
{
	if (config->version < IPConfigFileMinimumVersion ||
	    config->version > IPConfigFileMaximumVersion)
	{
		printError("unrecognized file version");
		return false;
	}

	while (!feof(stream))
	{
		char *line = NULL;
		char *value = NULL;

		struct IPConfigAttribute *attribute = NULL;
		attribute = calloc(1, sizeof(struct IPConfigAttribute));

		if (!attribute)
		{
			printLibraryError("calloc");
			deinitializeIPConfig(config);
			return false;
		}

		appendAttribute(attribute, config);

		if (!readUnpackedLine(stream, &line))
		{
			printError("failed to read line");
			deinitializeIPConfig(config);
			return false;
		}
	
		if (strlen(line) == 0)
		{
			free(line);

			if (feof(stream))
			{
				attribute->key = strdup(IPConfigTerminatorKey);
				break;
			}

			continue;
		}

		if (!parseUnpackedPair(line, &attribute->key, &value))
		{
			printError("failed to read pair");
			deinitializeIPConfig(config);
			free(line);
			return false;
		}

		free(line);
		attribute->type = getAttributeType(config->version,
		                                   attribute->key);

		if (!attribute->type)
		{
			printError("unrecognized attribute type");
			deinitializeIPConfig(config);
			free(value);
			return false;
		}

		else if (attribute->type == IntegerIPConfigAttributeType)
		{
			uint32_t *integer = &attribute->value.integer;

			if (!parseUnpackedUInt32(value, integer))
			{
				printError("failed to read integer");
				deinitializeIPConfig(config);
				free(value);
				return false;
			}

			free(value);
		}

		else if (attribute->type == StringIPConfigAttributeType)
		{
			attribute->value.string = value;
		}

		else if (attribute->type == LinkIPConfigAttributeType)
		{
			if (!parseUnpackedLink(value, &attribute->value.link))
			{
				printError("failed to read link");
				deinitializeIPConfig(config);
				free(value);
				return false;
			}

			free(value);
		}

		else if (attribute->type == RouteIPConfigAttributeType)
		{
			struct IPConfigRoute *route = &attribute->value.route;

			if (!parseUnpackedRoute(value, route))
			{
				printError("failed to read route");
				deinitializeIPConfig(config);
				free(value);
				return false;
			}

			free(value);
		}
	}

	return true;
}

void printConfig(struct IPConfig *config) {
    struct IPConfigAttribute *attribute = config->attributes;
    while (attribute)
    {
		if (attribute->type == RouteIPConfigAttributeType) {
        struct IPConfigRoute *route = &attribute->value.route;
		struct IPConfigLink *destination = &route->destination;
        if (destination->address && destination->prefix) {
            printf("%s: %s/%" PRIu32 " %s\n",attribute->key,destination->address,destination->prefix,route->nextHop);
	       }
        if (strcmp(attribute->key,"gateway") == 0) {
           strcpy(static_cfg[2],route->nextHop);
		   }
		}
	    if (strcmp(attribute->key,"linkAddress") == 0) {
		    struct IPConfigLink *link = &attribute->value.link;
            strcpy(static_cfg[0],attribute->value.string);
		    ipv4_prefixlen2str(link->prefix,static_cfg[1]);
			strcpy(static_cfg[5],static_cfg[0]);
			char str[25];
			sprintf(str,"/%d",link->prefix);
			strcat(static_cfg[5],str);
		} else if (strcmp(attribute->key,"dns") == 0) {
		    if (strlen(static_cfg[3]) != 0) {
            strcpy(static_cfg[4],attribute->value.string);
		} else {
            strcpy(static_cfg[3],attribute->value.string);
		}
	}
        //printf("%d,%s:%s --> ", attribute->type, attribute->key, attribute->value.string);
        attribute = attribute->next;
    }
    //printf("\n");
}

bool genPackedDHCPIPConfig(struct IPConfig *config) {
    if (config->version < IPConfigFileMinimumVersion ||
        config->version > IPConfigFileMaximumVersion)
    {
        printError("unrecognized file version");
        return false;
    }

    char static_cfg[3][40] = {
            "ipAssignment: DHCP",
            "proxySettings: NONE",
            "id: eth0"
    };

    for (int i = 0; i < 3; i++ ) {
//        printf("%s\n", static_cfg[i]);
//        char *line = NULL;
        char *value = NULL;

        struct IPConfigAttribute *attribute = NULL;
        attribute = calloc(1, sizeof(struct IPConfigAttribute));

        if (!attribute)
        {
            printLibraryError("calloc");
            deinitializeIPConfig(config);
            return false;
        }

        appendAttribute(attribute, config);

        if (!parseUnpackedPair(static_cfg[i], &attribute->key, &value))
        {
            printError("failed to read pair");
            deinitializeIPConfig(config);
            free(static_cfg[i]);
            return false;
        }

        attribute->type = getAttributeType(config->version,
                                           attribute->key);

        if (!attribute->type)
        {
            printError("unrecognized attribute type");
            deinitializeIPConfig(config);
            free(value);
            return false;
        }

        else if (attribute->type == IntegerIPConfigAttributeType)
        {
            uint32_t *integer = &attribute->value.integer;

            if (!parseUnpackedUInt32(value, integer))
            {
                printError("failed to read integer");
                deinitializeIPConfig(config);
                free(value);
                return false;
            }

            free(value);
        }

        else if (attribute->type == StringIPConfigAttributeType)
        {
            attribute->value.string = value;
        }

        else if (attribute->type == LinkIPConfigAttributeType)
        {
            if (!parseUnpackedLink(value, &attribute->value.link))
            {
                printError("failed to read link");
                deinitializeIPConfig(config);
                free(value);
                return false;
            }

            free(value);
        }

        else if (attribute->type == RouteIPConfigAttributeType)
        {
            struct IPConfigRoute *route = &attribute->value.route;

            if (!parseUnpackedRoute(value, route))
            {
                printError("failed to read route");
                deinitializeIPConfig(config);
                free(value);
                return false;
            }

            free(value);
        }
    }
    return true;
}

bool genPackedIPConfig(struct IPConfig *config, char *linkAddress, char *gw, char *dns1, char *dns2)
{
    if (config->version < IPConfigFileMinimumVersion ||
        config->version > IPConfigFileMaximumVersion)
    {
        printError("unrecognized file version");
        return false;
    }

    char static_cfg[7][100] = {
            "ipAssignment: STATIC",
            "linkAddress: ",
            "gateway: ",
            "dns: ",
            "dns: ",
            "proxySettings: NONE",
            "id: eth0"
    };
    strcat(static_cfg[1], linkAddress);
    strcat(static_cfg[2], gw);
    strcat(static_cfg[3], dns1);
    strcat(static_cfg[4], dns2);

    for (int i = 0; i < 7; i++ ) {
//        printf("%s\n", static_cfg[i]);
//        char *line = NULL;
        char *value = NULL;

        struct IPConfigAttribute *attribute = NULL;
        attribute = calloc(1, sizeof(struct IPConfigAttribute));

        if (!attribute)
        {
            printLibraryError("calloc");
            deinitializeIPConfig(config);
            return false;
        }

        appendAttribute(attribute, config);

        if (!parseUnpackedPair(static_cfg[i], &attribute->key, &value))
        {
            printError("failed to read pair");
            deinitializeIPConfig(config);
            free(static_cfg[i]);
            return false;
        }

        attribute->type = getAttributeType(config->version,
                                           attribute->key);

        if (!attribute->type)
        {
            printError("unrecognized attribute type");
            deinitializeIPConfig(config);
            free(value);
            return false;
        }

        else if (attribute->type == IntegerIPConfigAttributeType)
        {
            uint32_t *integer = &attribute->value.integer;

            if (!parseUnpackedUInt32(value, integer))
            {
                printError("failed to read integer");
                deinitializeIPConfig(config);
                free(value);
                return false;
            }

            free(value);
        }

        else if (attribute->type == StringIPConfigAttributeType)
        {
            attribute->value.string = value;
        }

        else if (attribute->type == LinkIPConfigAttributeType)
        {

            if (!parseUnpackedLink(value, &attribute->value.link))
            {
                printError("failed to read link");
                deinitializeIPConfig(config);
                free(value);
                return false;
            }

            free(value);
        }

        else if (attribute->type == RouteIPConfigAttributeType)
        {
            struct IPConfigRoute *route = &attribute->value.route;

            if (!parseUnpackedRoute(value, route))
            {
                printError("failed to read route");
                deinitializeIPConfig(config);
                free(value);
                return false;
            }

            free(value);
        }
    }
    return true;
}

int ipv4_prefixlen2str(int prefixlen, char* ip_str)
{
    //char tmp[16] = {0};
    //char* p = tmp;
    unsigned int ip_num = 0;
 
    if (ip_str == NULL) return -1;
    if (prefixlen > 32) return -1;
 
    // fast...
    if (prefixlen == 8) strcpy(ip_str, "255.0.0.0");
    if (prefixlen == 16) strcpy(ip_str, "255.255.0.0");
    if (prefixlen == 24) strcpy(ip_str, "255.255.255.0");
    if (prefixlen == 32) strcpy(ip_str, "255.255.255.255");
 
    // just in case
    for (int i = prefixlen, j = 31; i > 0; i--, j--)
    {
        //unsigned int tmp = (1<<j);
        //printf("%d tmp: %08x\n", i, tmp);
        ip_num += (1<<j);
    }
    //printf("ip_num: %08x\n", ip_num);
    sprintf(ip_str, "%u.%u.%u.%u", (ip_num>>24)&0xff, (ip_num>>16)&0xff, (ip_num>>8)&0xff, ip_num&0xff);
    return 0;
}

/*
int ipv4_str2prefixlen(const char* ip_str)
{
    int ret = 0;
    unsigned int ip_num = 0;
    unsigned char c1,c2,c3,c4;
    int cnt = 0;

    ret = sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu", &c1, &c2, &c3, &c4);
    ip_num = c1<<24 | c2<<16 | c3<<8 | c4;

    // fast...
    if (ip_num == 0xffffffff) return 32;
    if (ip_num == 0xffffff00) return 24;
    if (ip_num == 0xffff0000) return 16;
    if (ip_num == 0xff000000) return 6;
    // just in case
    for (int i = 0; i < 32; i++)
    {
        //unsigned int tmp = (ip_num<<i);
        //printf("%d tmp: %x\n", i+1, tmp);
        if ((ip_num<<i) & 0x80000000)
            cnt++;
        else
            break;
    }
    //printf("cnt: %d\n", cnt);
    return cnt;
}
*/



