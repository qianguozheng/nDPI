#ifndef _DNS_H_
#define _DNS_H_
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#define NAMESERVER_PORT 53
#define TFTP_PORT       69

#define IN6ADDRSZ       16
#define INADDRSZ        4

#define PACKETSZ	512		/* maximum packet size */
#define MAXDNAME	1025		/* maximum presentation domain name */
#define RRFIXEDSZ	10		/* #/bytes of fixed data in r record */
#define MAXLABEL        63              /* maximum length of domain label */

#define NOERROR		0		/* no error */
#define FORMERR		1		/* format error */
#define SERVFAIL	2		/* server failure */
#define NXDOMAIN	3		/* non existent domain */
#define NOTIMP		4		/* not implemented */
#define REFUSED		5		/* query refused */

#define QUERY           0               /* opcode */

#define C_IN            1               /* the arpa internet */
#define C_CHAOS         3               /* for chaos net (MIT) */
#define C_HESIOD        4               /* hesiod */
#define C_ANY           255             /* wildcard match */

#define T_A		1
#define T_NS            2
#define T_MD            3
#define T_MF            4             
#define T_CNAME		5
#define T_SOA		6
#define T_MB            7
#define T_MG            8
#define T_MR            9
#define T_PTR		12
#define T_MINFO         14
#define T_MX		15
#define T_TXT		16
#define T_RP            17
#define T_AFSDB         18
#define T_RT            21
#define T_SIG		24
#define T_PX            26
#define T_AAAA		28
#define T_NXT           30
#define T_SRV		33
#define T_NAPTR		35
#define T_KX            36
#define T_DNAME         39
#define T_OPT		41
#define T_DS            43
#define T_RRSIG         46
#define T_NSEC          47
#define T_DNSKEY        48
#define T_NSEC3         50
#define	T_TKEY		249		
#define	T_TSIG		250
#define T_AXFR          252
#define T_MAILB		253	
#define T_ANY		255

#define EDNS0_OPTION_MAC            65001 /* dyndns.org temporary assignment */
#define EDNS0_OPTION_CLIENT_SUBNET  8     /* IANA */


///New Add
#define CNAME_CHAIN 10 /* chains longer than this atr dropped for loop protection */

#define F_IMMORTAL  (1u<<0)
#define F_NAMEP     (1u<<1)
#define F_REVERSE   (1u<<2)
#define F_FORWARD   (1u<<3)
#define F_DHCP      (1u<<4)
#define F_NEG       (1u<<5)       
#define F_HOSTS     (1u<<6)
#define F_IPV4      (1u<<7)
#define F_IPV6      (1u<<8)
#define F_BIGNAME   (1u<<9)
#define F_NXDOMAIN  (1u<<10)
#define F_CNAME     (1u<<11)
#define F_DNSKEY    (1u<<12)
#define F_CONFIG    (1u<<13)
#define F_DS        (1u<<14)
#define F_DNSSECOK  (1u<<15)

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;


struct dns_header {
  u16 id;
  u8  hb3,hb4;
  u16 qdcount,ancount,nscount,arcount;
};

#define HB3_QR       0x80 /* Query */
#define HB3_OPCODE   0x78
#define HB3_AA       0x04 /* Authoritative Answer */
#define HB3_TC       0x02 /* TrunCated */
#define HB3_RD       0x01 /* Recursion Desired */

#define HB4_RA       0x80 /* Recursion Available */
#define HB4_AD       0x20 /* Authenticated Data */
#define HB4_CD       0x10 /* Checking Disabled */
#define HB4_RCODE    0x0f

#define OPCODE(x)          (((x)->hb3 & HB3_OPCODE) >> 3)
#define SET_OPCODE(x, code) (x)->hb3 = ((x)->hb3 & ~HB3_OPCODE) | code

#define RCODE(x)           ((x)->hb4 & HB4_RCODE)
#define SET_RCODE(x, code) (x)->hb4 = ((x)->hb4 & ~HB4_RCODE) | code
  
#define GETSHORT(s, cp) { \
	unsigned char *t_cp = (unsigned char *)(cp); \
	(s) = ((u16)t_cp[0] << 8) \
	    | ((u16)t_cp[1]) \
	    ; \
	(cp) += 2; \
}

#define GETLONG(l, cp) { \
	unsigned char *t_cp = (unsigned char *)(cp); \
	(l) = ((u32)t_cp[0] << 24) \
	    | ((u32)t_cp[1] << 16) \
	    | ((u32)t_cp[2] << 8) \
	    | ((u32)t_cp[3]) \
	    ; \
	(cp) += 4; \
}

#define PUTSHORT(s, cp) { \
	u16 t_s = (u16)(s); \
	unsigned char *t_cp = (unsigned char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += 2; \
}

#define PUTLONG(l, cp) { \
	u32 t_l = (u32)(l); \
	unsigned char *t_cp = (unsigned char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += 4; \
}

#define CHECK_LEN(header, pp, plen, len) \
    ((size_t)((pp) - (unsigned char *)(header) + (len)) <= (plen))

#define ADD_RDLEN(header, pp, plen, len) \
  (!CHECK_LEN(header, pp, plen, len) ? 0 : (((pp) += (len)), 1))

/* Escape character in our presentation format for names.
   Cannot be '.' or /000 and must be !isprint().
   Note that escaped chars are stored as
   <NAME_ESCAPE> <orig-char+1>
   to ensure that the escaped form of /000 doesn't include /000
*/


//======================================================================
struct all_addr {
  union {
    struct in_addr addr4;
#ifdef HAVE_IPV6
    struct in6_addr addr6;
#endif
    /* for log_query */
    unsigned int keytag;
    /* for cache_insert if RRSIG, DNSKEY, DS */
    struct {
      unsigned short class, type;
    } dnssec;      
  } addr;
};

/* is addr in the non-globally-routed IP space? */ 
void dissectDNS(u_int8_t *payload, u_int16_t payload_len, int l4_proto, char *mac, uint64_t time);

#endif
