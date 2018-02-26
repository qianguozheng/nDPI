#include "msg.h"

#include "log.h"

#include <stdio.h>
#include <string.h>
#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#include <pthread.h>

//Parse receive data to element, add to list

maclist store, store_backup;
pthread_mutex_t s_mutex, sb_mutex;

//parse_tulpe_string_all()
//dns_log_write("dns.list", msg_node->msg.data);
//mac,domain,time
void parse_dns_string_all(const char *buff, dns_t *dns){
	char *buf= (char *)buff;
	char *outer_ptr = NULL;
	char *p = NULL;
	
	if (!buff) return;
	
	p = strtok_r(buf, "|", &outer_ptr);
	if (p){
		sprintf(dns->mac, "%s", p);
		p = strtok_r(NULL, "|", &outer_ptr);
		if (p) sprintf(dns->domain, "%s", p);
		p = strtok_r(NULL, "|", &outer_ptr);
		if (p) dns->stamp = atoll(p);
		p = strtok_r(NULL, "|", &outer_ptr);
		if (p) sprintf(dns->ip, "%s", p);
		//LOG("mac=%s,domain=%s,time=%lld\n",
		//	dns->mac, dns->domain, dns->stamp);
	}
}
//mac,host,dport,proto,time
void parse_tulpe_string_all(const char *buff, tuple_t *tuple){
	char *buf= (char *)buff;
	char *outer_ptr = NULL, *inner_ptr = NULL;
	char *p = NULL;
	
	if (!buff) return;
	
	p = strtok_r(buf, "|", &outer_ptr);
	if (p){
		sprintf(tuple->mac, "%s", p);
		p = strtok_r(NULL, "|", &outer_ptr);
		if (p) sprintf(tuple->host, "%s", p);
		p = strtok_r(NULL, "|", &outer_ptr);
		if (p) tuple->port = atol(p);
		p = strtok_r(NULL, "|", &outer_ptr);
		if (p) tuple->proto = atoi(p);
		p = strtok_r(NULL, "|", &outer_ptr);
		if (p) tuple->stamp = atoll(p);
		//LOG("mac=%s,host=%s,port=%d,proto=%d,time=%lld\n", 
		//	tuple->mac, tuple->host, tuple->port, tuple->proto, tuple->stamp);
	}
}

#if 1

void init_struct_store() {
	memset(&store, 0, sizeof(maclist));
	INIT_LIST_HEAD(&store.list);
	
	INIT_LIST_HEAD(&store.tuple.list);
	INIT_LIST_HEAD(&store.dns.list);
	
	//INIT_LIST_HEAD(&store.dns.sl.list);
	//INIT_LIST_HEAD(&store.tuple.sl.list);
	
	memset(&store_backup, 0, sizeof(store_backup));
	INIT_LIST_HEAD(&store_backup.list);
	
	INIT_LIST_HEAD(&store_backup.tuple.list);
	INIT_LIST_HEAD(&store_backup.dns.list);
	
	//INIT_LIST_HEAD(&store_backup.dns.sl.list);
	//INIT_LIST_HEAD(&store_backup.tuple.sl.list);
}

#if 0
void add_timestamp_to_stamplist(tuplelist *tuple, int64_t stamp) {
	struct list_head *pos;
	stamplist *p;
	
	stamplist *node = malloc(sizeof(stamplist));
	memset(node, 0, sizeof(stamplist));
	
	node->stamp = stamp/1000;
	list_add_tail(&node->list, &tuple->sl.list);
}

void add_timestamp_to_dnsstamplist(dnslist *dns, int64_t stamp) {
	struct list_head *pos;
	stamplist *p;
	
	stamplist *node = malloc(sizeof(stamplist));
	memset(node, 0, sizeof(stamplist));
	
	node->stamp = stamp/1000;
	list_add_tail(&node->list, &dns->sl.list);
}
#endif

void add_dns_to_dnslist(maclist *mac, dns_t dns){
	struct list_head *pos;
	dnslist *p;
	int found = 0;
	
	list_for_each(pos, &mac->dns.list) {
		p = list_entry(pos, dnslist, list);
		if (0 == strcasecmp(p->domain, dns.domain)){
			//add timestamp to this list.
			//add_timestamp_to_dnsstamplist(p, dns.stamp);
			p->times++;
			mac->datalen += 13;
			found = 1;
		}
	}
	
	if (!found) {
		dnslist *node = malloc(sizeof(dnslist));
		memset(node, 0, sizeof(dnslist));
		sprintf(node->domain, "%s", dns.domain);
		sprintf(node->ip, "%s", dns.ip);
		node->times++;
		
		//INIT_LIST_HEAD(&node->sl.list);
		//node->sl.stamp = dns.stamp;
		
		mac->datalen += strlen(dns.domain) + 10;
		
		list_add_tail(&node->list, &mac->dns.list);
		
		//add_timestamp_to_dnsstamplist(node, dns.stamp);
	}
}

void add_tuple_to_tuplelist(maclist *mac, tuple_t tuple) {
	struct list_head *pos;
	tuplelist *p;
	int found = 0;
	
	///LOG("1 mac=%s\n", mac->mac);
	list_for_each(pos, &mac->tuple.list) {
		p = list_entry(pos, tuplelist, list);
		if (0 == strcasecmp(p->host, tuple.host) &&
			p->port == tuple.port &&
			p->proto == tuple.proto){
			//add timestamp to this list;
			//add_timestamp_to_stamplist(p, tuple.stamp);
			p->times++;
			
			mac->datalen += 14;
			
			found = 1;
		}
	}
	///LOG("2 mac=%s\n", mac->mac);
	//Add new node to tuplelist
	if (!found) {
		tuplelist *node = malloc(sizeof(tuplelist));
		memset(node, 0, sizeof(tuplelist));
		sprintf(node->host, "%s", tuple.host);
		node->port = tuple.port;
		node->proto = tuple.proto;
		node->times++;
		
		//INIT_LIST_HEAD(&node->sl.list);
		//node->sl.stamp = tuple.stamp;
		
		mac->datalen += strlen(tuple.host) + 18;
		
		list_add_tail(&node->list, &mac->tuple.list);
		
		//add_timestamp_to_stamplist(node, tuple.stamp);
	}
}

#define DUMP_BY_COUNT 1
#define MAX_COUNT 512*1024
int g_count = 0;
int dump_to_disk = 0;

time_t last_time = 0;
int schedule_by_time(uint16_t duration){
	time_t cur = time(NULL);
	if (cur > last_time + duration) {
		last_time = cur;
		LOG("g_count=%d, dump_to_disk=%d\n", g_count, dump_to_disk);
		dump_to_disk = dump_to_disk == 1 ? 1 : 0;
	}
}

int lan_ip_check(char *ip) {
	if (!ip) return 0;
	if (0 == strncmp("192.168.", ip, strlen("192.168."))
	 || 0 == strncmp("127.0.0.1", ip, strlen("127.0.0.1"))
	 || 0 == strncmp("10.", ip, strlen("10.")))
		return 1;
	return 0;
}

void add_tuple_to_maclist(char *data){
	
	tuple_t tuple;
	memset(&tuple, 0, sizeof(tuple_t));
	parse_tulpe_string_all(data, &tuple);
	
	int found = 0;
	//walk mac list
	struct list_head *pos;
	maclist *p, *mlist;
	
	if(lan_ip_check(tuple.host)) {
		//LOG("dest ip %s proto=%d, port=%d is local\n", tuple.host, 
		//	tuple.proto, tuple.port);
		return;
	}
	
#ifdef DUMP_BY_COUNT
	if (++g_count >= MAX_COUNT)
	{
		LOG("g_count=%d, dump_to_disk=%d\n", g_count, dump_to_disk);
		dump_to_disk = dump_to_disk == 0 ? 1 : 0;
		g_count = 0;
	}
#else
	//duration seconds.
	schedule_by_time(600);
#endif
	
	if (dump_to_disk)
	{
		pthread_mutex_lock(&s_mutex);
		mlist = &store;
		pthread_mutex_unlock(&s_mutex);
	} else {
		pthread_mutex_lock(&sb_mutex);
		mlist = &store_backup;
		pthread_mutex_unlock(&sb_mutex);
	}
	
	//LOG("g_count=%d, dump_to_disk=%d\n", g_count, dump_to_disk);
	list_for_each(pos, &mlist->list){
		///LOG("in list\n");
		p = list_entry(pos, maclist, list);
		///LOG("in list=%p\n", p);
		///if(p) LOG("xxxxxx\n");
		///else LOG("p is NULL\n");
		if (0 == strcasecmp(p->mac, tuple.mac)){
			//add tuple to this mac list;
			///LOG("=======\n");
			add_tuple_to_tuplelist(p, tuple);
			///LOG("=======!!!!\n");
			found = 1;
		}
		///LOG("end list\n");
	}
	///LOG("after walk list\n");
	
	//Add new node to maclist
	if (!found) {
		maclist *node = malloc(sizeof(maclist));
		memset(node, 0, sizeof(maclist));
		
		///LOG("init node\n");
		
		INIT_LIST_HEAD(&node->tuple.list);
		//INIT_LIST_HEAD(&node->tuple.sl.list);
		INIT_LIST_HEAD(&node->dns.list);
		//INIT_LIST_HEAD(&node->dns.sl.list);
		sprintf(node->mac, "%s", tuple.mac);
		
		///LOG("mac=%s\n", node->mac);
		sprintf(node->tuple.host, "%s", tuple.host);
		node->tuple.port = tuple.port;
		node->tuple.proto = tuple.proto;
		///LOG("next is stamp=%lld\n", tuple.stamp);
		//node->tuple.sl.stamp = tuple.stamp;
		///LOG("End of stamp\n");
		//statistic total data length, 10 timestamp, 5 port, 3 proto
		node->datalen += strlen(tuple.mac) + strlen(tuple.host)+ 10 + 5 + 3;
		
		list_add_tail(&node->list, &mlist->list);
		
		add_tuple_to_tuplelist(node, tuple);
	}
}

int find_str(char *str, char *domain){
	char *p = domain;
	if (!p) return 0;
	
	p = strstr(p, str);
	
	if (p && strlen(p) == strlen(str)) {
		return 1;
	} else {
		return 0;
	}
}
#define MAX_LEN_FAKE 2
int filter_fake_dns(char *domain) {
	//LOG("filter fake dns [%s]\n", domain);
    char p[MAX_LEN_FAKE][128] = {
                ".lan",
                ".in-addr.arpa"
            };
    
    int i = MAX_LEN_FAKE;
    for (i = 0; i < MAX_LEN_FAKE; i++) {
		if (find_str(p[i], domain))
			return 1;
	}
	return 0;

}

void add_dns_to_maclist(char *data) {
	dns_t dns;
	memset(&dns, 0, sizeof(dns_t));
	parse_dns_string_all(data, &dns);
	
	int found = 0;
	//walk mac list
	struct list_head *pos;
	maclist *p, *mlist;
	
	if (filter_fake_dns(dns.domain)) {
		//LOG("Domain is %s filtered\n", dns.domain);
		return;
	}
	
	if (++g_count >= MAX_COUNT)
	{
		LOG("g_count=%d, dump_to_disk=%d\n", g_count, dump_to_disk);
		dump_to_disk = dump_to_disk == 0 ? 1 : 0;
		g_count = 0;
	}
	
	if (dump_to_disk)
	{
		mlist = &store;
	} else {
		mlist = &store_backup;
	}
	
	//LOG("g_count=%d, dump_to_disk=%d\n", g_count, dump_to_disk);
	list_for_each(pos, &mlist->list){
		p = list_entry(pos, maclist, list);
		if (0 == strcasecmp(p->mac, dns.mac)) {
			//add dns to maclist
			add_dns_to_dnslist(p, dns);
			found = 1;
		}
		///LOG("mac=%s, datalen=%d\n", p->mac, p->datalen);
	}
	
	//Add new node to maclist
	if (!found) {
		maclist *node = malloc(sizeof(maclist));
		memset(node, 0, sizeof(node));
		
		INIT_LIST_HEAD(&node->tuple.list);
		//INIT_LIST_HEAD(&node->tuple.sl.list);
		INIT_LIST_HEAD(&node->dns.list);
		//INIT_LIST_HEAD(&node->dns.sl.list);
		
		sprintf(node->mac, "%s", dns.mac);

		sprintf(node->dns.domain, "%s", dns.domain);
		
		//node->dns.sl.stamp = dns.stamp;
		
		node->datalen += strlen(dns.mac) + strlen(dns.domain) + 10;
		list_add_tail(&node->list, &mlist->list);
		
		add_dns_to_dnslist(node, dns);
	}
}


////Dump data to disk
int dump_count = 0;
#define DIVIDE_INTO_PART 1

json_object *format_dns_to_json(dnslist *dns, int *full_read, int already_read) {
	json_object *jso;
	json_object *stamparr;
	struct list_head *n, *pos;
	stamplist *p;
	int stamplen = 0;
	int have_stamp = 0;
	//char *pstr = NULL;
	*full_read = 0;
	
	jso = json_object_new_object();
	
	json_object_object_add(jso, "domain", json_object_new_string(dns->domain));
	json_object_object_add(jso, "ip", json_object_new_string(dns->ip));
	
#if 1
	json_object_object_add(jso, "times", json_object_new_int(dns->times));
#else
	stamparr = json_object_new_array();
	
	list_for_each_safe(pos, n, &dns->sl.list) {
		p = list_entry(pos, stamplist, list);
		
		stamplen += 14;
		
		if ((stamplen + already_read > 2000) && have_stamp) {
			json_object_object_add(jso, "time", stamparr);
			return jso;
		}
		
		json_object_array_add(stamparr, json_object_new_int64(p->stamp));
		
		have_stamp++;
		list_del(pos);
		free(p);
		usleep(5);
		dump_count++;
	}
	
	//LOG("dns stamplen=%d\n", stamplen);
	if (stamplen > 0) {
		json_object_object_add(jso, "time", stamparr);
	}
	else {
		json_object_put(stamparr);
		LOG("dns stamp length is 0, release it\n");
	}
#endif
	*full_read = 1;
	return jso;
	//pstr = strdup(json_object_to_json_string(jso));
	//json_object_put(jso);
	
	//LOG("ptr=[%s]\n", pstr);
	//return pstr;
}

json_object *format_tuple_to_json(tuplelist *tuple, int *full_read, int already_read) {
	json_object *jso;
	json_object *stamparr;
	int stamplen = 0;
	int have_stamp = 0;
	
	*full_read = 0;

	jso = json_object_new_object();
	
	json_object_object_add(jso, "ip", json_object_new_string(tuple->host));
	
	if (6 == tuple->proto)
		json_object_object_add(jso, "proto", json_object_new_string("tcp"));
	else if (17 == tuple->proto)
		json_object_object_add(jso, "proto", json_object_new_string("udp"));
	
	json_object_object_add(jso, "port", json_object_new_int(tuple->port));
	
	struct list_head *n, *pos;
	stamplist *p;
	
#if 1
	json_object_object_add(jso, "times", json_object_new_int(tuple->times));
#else
	stamparr = json_object_new_array();
	
	list_for_each_safe(pos, n, &tuple->sl.list) {
		
		p = list_entry(pos, stamplist, list);
		stamplen += 14;
		
		if ((stamplen + already_read > 2000) && have_stamp) {
			json_object_object_add(jso, "time",stamparr);
			return jso;
		}
		
		json_object_array_add(stamparr, json_object_new_int64(p->stamp));
		have_stamp++;
		list_del(pos);
		free(p);
		dump_count++;
		
		
		usleep(5);
		
	}
	
	if (stamplen > 0){
		json_object_object_add(jso, "time",stamparr);
	} else {
		json_object_put(stamparr);
		LOG("tuple stamp length is 0, release it\n");
	}
#endif

	*full_read = 1;
	return jso;
}

void dump_tuplelist_dnslist_to_disk(maclist *mac) {
	struct list_head *n, *pos;
	tuplelist *p;
	dnslist *pdns;
	json_object *jso;
	json_object *ips, *dns, *json, *jsondns;
	char *dump_json = NULL;
	int ipslen, dnslen;
	int dump_part, full_read;
WALK_TUPLE:
	full_read = 0;
	dnslen = 0;
	ipslen = 0;
	dump_part = 0;
	jso = json_object_new_object();
	ips = json_object_new_array();
	
	json_object_object_add(jso, "mac", json_object_new_string(mac->mac));

	//LOG("dump tuple/dns enter mac=[%s]\n", mac->mac);
	//walk tuplelist
	list_for_each_safe(pos, n, &mac->tuple.list) {
		
		p = list_entry(pos, tuplelist, list);
		json = format_tuple_to_json(p, &full_read, ipslen);
		ipslen += strlen(json_object_to_json_string_ext(json, JSON_C_TO_STRING_PLAIN));
		json_object_array_add(ips, json);
		
		//stamp length > 2000, need divide it
		if (0 == full_read) {
			//LOG("dump part, timestamp too long, ipslen=%d\n", ipslen);
			dump_part = 1;
			goto DUMP_TUPLE_PART;
		}
		
		list_del(pos);
		free(p);
		//dump_count++;
		
		if (ipslen > 2048){
			//LOG("dump part ipslen=%d\n", ipslen);
			dump_part = 1;
			goto DUMP_TUPLE_PART;
		}
		usleep(5);
	}
	//LOG("dump tuple end\n");
	
DUMP_TUPLE_PART:
	if (ipslen > 0) {
		json_object_object_add(jso, "ips", ips);
	}
	else if (!dump_part) {
		//LOG("No tuple object, release it\n");
		json_object_put(ips);
	}
	
	if (dump_part) {
		dump_json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PLAIN));
		json_object_put(jso);
		
		if (dump_json) json_log_write("tuple.list", dump_json, 0);
		free(dump_json);
		
		//LOG("dump tuple part done\n");
		goto WALK_TUPLE;
	}
	
WALK_DNS:
	//walk dnslist
	dump_part = 0;
	dnslen = 0;
	full_read = 0;
	dns = json_object_new_array();
	
	list_for_each_safe(pos, n, &mac->dns.list) {
		
		pdns = list_entry(pos, dnslist, list);
		jsondns = format_dns_to_json(pdns, &full_read, dnslen+ipslen);
		dnslen += strlen(json_object_to_json_string_ext(jsondns, JSON_C_TO_STRING_PLAIN));
		json_object_array_add(dns, jsondns);
	
		if (0 == full_read) {
			//LOG("dump part, timestamp too long, dnslen=%d\n", dnslen);
			dump_part = 2;
			goto DUMP_DNS_PART;
		}
		
		list_del(pos);
		free(pdns);
		//dump_count++;
		
		if (dnslen+ipslen > 2048) {
			//LOG("dump part dnslen=%d, ipslen=%d\n", dnslen, ipslen);
			dump_part = 2;
			goto DUMP_DNS_PART;
		}
		usleep(5);
	}
DUMP_DNS_PART:
	if (dnslen > 0) {
		json_object_object_add(jso, "domains", dns);
	}
	else if (2 !=dump_part) {
		//LOG("No dns object, release it\n");
		json_object_put(dns);
	}
	
	if (2 == dump_part) {
		dump_json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PLAIN));
		json_object_put(jso);
		ipslen = 0;
		
		//save to file
		if (dump_json) json_log_write("tuple.list", dump_json, 0);
		free(dump_json);
		
		jso = json_object_new_object();
		json_object_object_add(jso, "mac", json_object_new_string(mac->mac));
		
		//LOG("dump dns part done!\n");
		goto WALK_DNS;
	}
	
	dump_json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PLAIN));
	//LOG("dump_json=[%s]\n", dump_json);
	
	//save to file
	if (dump_json && (dnslen || ipslen)) {
		json_log_write("tuple.list", dump_json, 0);
	}
	else {
		LOG("BUG: dnslen=%d, ipslen=%d, dump_json=[%s]\n", dnslen, ipslen, dump_json);
	}
	
	json_object_put(jso);
	free(dump_json);
}

void dump_maclist_to_disk(){
	struct list_head *n, *pos;
	maclist *p;
	maclist *mac;
	int curflag = dump_to_disk;
	
	pthread_mutex_init(&s_mutex, NULL);
	pthread_mutex_init(&sb_mutex, NULL);
	while (1) { 

		if (curflag == dump_to_disk) {
			sleep(1);
			dump_count = 0;
			continue;
		}
		
		curflag = dump_to_disk;

		if (dump_to_disk)
		{
			pthread_mutex_lock(&s_mutex);
			mac = &store_backup;
		} else {
			pthread_mutex_lock(&sb_mutex);
			mac = &store;
		}
		
		LOG("Dump mac=[%s]\n", mac->mac);
		list_for_each_safe(pos, n, &mac->list) {
			p = list_entry(pos, maclist, list);
			//dump tuple to disk
			//dump dns to disk
			dump_tuplelist_dnslist_to_disk(p);
			list_del(pos);
			free(p);
			usleep(50);
			//dump_count++;
		}
		json_log_write("tuple.list", NULL, 1);
		LOG("Dump end %d, max=%d\n", dump_count, MAX_COUNT);
		
		if (dump_to_disk)
			pthread_mutex_unlock(&s_mutex);
		else 
			pthread_mutex_unlock(&sb_mutex);
	};
}

///// Debug memory leak problem ////////////////////////////////////////

#if 0
int ggcount = 0;
void dump_dns_stamp_debug(dnslist *dns) {
	struct list_head *n, *pos;
	stamplist *p;
	
	list_for_each_safe(pos, n, &dns->sl.list) {
		p = list_entry(pos, stamplist, list);
		list_del(pos);
		free(p);
		usleep(5);
		ggcount++;
	}
}
void dump_tuple_stamp_debug(tuplelist *tuple){
	struct list_head *n, *pos;
	stamplist *p;
	
	list_for_each_safe(pos, n, &tuple->sl.list) {
		p = list_entry(pos, stamplist, list);
		list_del(pos);
		free(p);
		usleep(5);
		ggcount++;
	}	
}
void dump_dns_tuple_to_disk_debug(maclist *mac){
	struct list_head *n, *pos;
	tuplelist *p;
	dnslist *pdns;
	
	list_for_each_safe(pos, n, &mac->tuple.list) {
		p = list_entry(pos, tuplelist, list);
		//json = format_tuple_to_json(p);
		//ipslen += strlen(json_object_to_json_string(json));
		//json_object_array_add(ips, json);
		dump_tuple_stamp_debug(p);
		
		list_del(pos);
		//json_object_put(json);
		free(p);
		ggcount++;
	}
	
	list_for_each_safe(pos, n, &mac->dns.list) {
		pdns = list_entry(pos, dnslist, list);
		
		dump_dns_stamp_debug(pdns);
		//json_object_put(json);
		list_del(pos);
		free(pdns);
		usleep(5);
		ggcount++;
	}
}
void dump_maclist_to_disk_debug(){
	struct list_head *n, *pos;
	maclist *p;
	maclist *mac;
	int curflag = dump_to_disk;
	
	
	pthread_mutex_init(&s_mutex, NULL);
	pthread_mutex_init(&sb_mutex, NULL);
	while (1) { 

		if (curflag == dump_to_disk) {
			sleep(1);
			ggcount = 0;
			continue;
		}
		
		curflag = dump_to_disk;

		if (dump_to_disk)
		{
			pthread_mutex_lock(&s_mutex);
			mac = &store_backup;
		} else {
			pthread_mutex_lock(&sb_mutex);
			mac = &store;
		}
		
		LOG("Dump mac=[%s]\n", mac->mac);
		list_for_each_safe(pos, n, &mac->list) {
			p = list_entry(pos, maclist, list);
			//dump tuple to disk
			//dump dns to disk
			//dump_tuplelist_dnslist_to_disk(p);
			dump_dns_tuple_to_disk_debug(p);
			list_del(pos);
			free(p);
			usleep(50);
			ggcount++;
		}
		
		//json_log_write("tuple.list", NULL, 1);
		LOG("Dump end, ggount=%d, max=%d\n", ggcount, MAX_COUNT);
		
		if (dump_to_disk)
			pthread_mutex_unlock(&s_mutex);
		else 
			pthread_mutex_unlock(&sb_mutex);
	};
}
#endif // end of memory debug
#endif
#if 0
//Read json from tuple.list.timestamp file.
unsigned long int post_id = 5;
int generate_from_dump_json(char *host, int port, char* url, char *filename){
	FILE *fp = NULL;
	char buff[4096];
	json_object *mac, *jso, *terms;
	int readlen, ret, reinit;
	char *report_json;
	
	ret = reinit = 0;
	LOG("post file %s\n", filename);
	fp = fopen(filename, "r");
	if (!fp) {
		ret = -1;
		LOG("open file %s failed\n", filename);
		goto ERROR;
	}
	memset(buff, 0, sizeof(buff));
	
	while(fp && fgets(buff, sizeof(buff), fp)){
		if (strlen(buff) <= 20) continue;
		readlen += strlen(buff);
		mac = json_tokener_parse(buff);
		if (NULL == mac) {
			LOG("invalid json format [%s]\n", buff);
			continue;
		}
		if (0 == reinit) {
			jso = json_object_new_object();
			json_object_object_add(jso, "mac", json_object_new_string(ap_mac));
			json_object_object_add(jso, "seqId", json_object_new_int64(post_id++));
			terms = json_object_new_array();
		}
		
		json_object_array_add(terms, mac);

		if (readlen < 512 && !feof(fp)) {
			reinit ++;
			continue;
		} else {
			reinit = readlen = 0;
			
			json_object_object_add(jso, "terminals", terms);
			report_json = strdup(json_object_to_json_string(jso));
			json_object_put(jso);
			//send to server
			if (NULL == report_json) {
				ret = -2;
				goto ERROR;
			}
			LOG("report_json=%s\n", report_json);
			send_request(host, port, url, report_json);
			if (report_json) free(report_json);
		}
	}
ERROR:

	if (fp) fclose(fp);
	

	return ret;
}
#endif

////new format json data to file
//each line is an json object
char jsonfilename[256];
FILE *fpjson = NULL;
void json_log_write(char *prefix, char *str, int close_file) {
	static int flag = 0;
	//struct stat st;
	if (0 == flag || close_file) {
		flag = 1;
		if (fpjson) {
			fflush(fpjson);
			fclose(fpjson);
			fpjson = NULL;
		}
		
		memset(jsonfilename, 0, sizeof(jsonfilename));
		snprintf(jsonfilename, 256, "/tmp/%s.%lu", prefix, time(NULL));
		fpjson = fopen(jsonfilename, "a+");
		
		if (close_file) return;
	}
	
	if (fpjson) {
		char buf[4096];
		int writelen = 0;
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "%s\n", str);
		writelen = fwrite(buf, strlen(buf), 1, fpjson);
		//LOG("writelen=%d\n", writelen);
		fflush(fpjson);
		//stat(jsonfilename, &st);
		//if (st.st_size > MAX_FILESIZE) {
		//	flag = 0;
		//}
	}
}
////End of 2018-1-6




