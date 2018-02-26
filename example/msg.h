#ifndef _MSG_H_
#define _MSG_H_

#include <time.h>
#include <stdint.h>
#include "list.h"
#define MAX_DOMAIN_LENGTH 1024

#define IP_LENGTH 16
#define MAC_LENGTH 18

typedef struct {
	char mac[MAC_LENGTH];
	char host[IP_LENGTH];
	uint16_t port;
	uint8_t proto;
	uint64_t stamp;
} tuple_t;

typedef struct {
	char mac[MAC_LENGTH];
	char domain[MAX_DOMAIN_LENGTH];
	char ip[MAX_DOMAIN_LENGTH*4];
	uint64_t stamp;
} dns_t;


//Time list
typedef struct stamp_list {
	struct list_head list;
	uint64_t stamp;
} stamplist;

//tuple list
typedef struct tuple_list {
	struct list_head list;
	char host[IP_LENGTH];
	uint16_t port;
	uint8_t proto;
	uint64_t hashval;
	//stamplist sl;
	uint32_t times;
} tuplelist;

typedef struct dns_list {
	struct list_head list;
	char domain[MAX_DOMAIN_LENGTH];
	char ip[MAX_DOMAIN_LENGTH*4];
	//stamplist sl;
	uint32_t times;
} dnslist;

//mac list
typedef struct mac_list {
	struct list_head list;
	tuplelist tuple;
	dnslist dns;
	char mac[MAC_LENGTH];
	//statistics total element length
	uint16_t datalen;
	
} maclist;

void init_struct_store();
void dump_maclist_to_disk();
int generate_from_dump_json(char *host, int port, char* url, char *filename);
void add_dns_to_maclist(char *data);
void add_tuple_to_maclist(char *data);
void json_log_write(char *prefix, char *str, int close_file);

void dump_maclist_to_disk_debug();
//receive from udp
//parse to structure
// -- put to xxxx
// -- dump to file
#endif
