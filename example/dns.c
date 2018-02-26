#include "dns.h"
#include "log.h"
#include <limits.h>
#include "ndpi_main.h"
#include "ndpi_util.h"

#define CHECK_LEN(header, pp, plen, len) \
    ((size_t)((pp) - (unsigned char *)(header) + (len)) <= (plen))

#define ADD_RDLEN(header, pp, plen, len) \
  (!CHECK_LEN(header, pp, plen, len) ? 0 : (((pp) += (len)), 1))
#define MAXDNAME	1025		/* maximum presentation domain name */
#define QUERY           0               /* opcode */
#define HB3_OPCODE   0x78
#define OPCODE(x)          (((x)->hb3 & HB3_OPCODE) >> 3)
/*
struct dns_header {
  u_int16_t id;
  u_int8_t  hb3,hb4;
  u_int16_t qdcount,ancount,nscount,arcount;
};*/

/* don't use strcasecmp and friends here - they may be messed up by LOCALE */
int hostname_isequal(const char *a, const char *b)
{
  unsigned int c1, c2;
  
  do {
    c1 = (unsigned char) *a++;
    c2 = (unsigned char) *b++;
    
    if (c1 >= 'A' && c1 <= 'Z')
      c1 += 'a' - 'A';
    if (c2 >= 'A' && c2 <= 'Z')
      c2 += 'a' - 'A';
    
    if (c1 != c2)
      return 0;
  } while (c1);
  
  return 1;
}

/* Max size of input string (for IPv6) is 75 chars.) */
#define MAXARPANAME 75
int in_arpa_name_2_addr(char *namein, struct all_addr *addrp)
{
  int j;
  char name[MAXARPANAME+1], *cp1;
  unsigned char *addr = (unsigned char *)addrp;
  char *lastchunk = NULL, *penchunk = NULL;
  
  if (strlen(namein) > MAXARPANAME)
    return 0;

  memset(addrp, 0, sizeof(struct all_addr));

  /* turn name into a series of asciiz strings */
  /* j counts no of labels */
  for(j = 1,cp1 = name; *namein; cp1++, namein++)
    if (*namein == '.')
      {
	penchunk = lastchunk;
        lastchunk = cp1 + 1;
	*cp1 = 0;
	j++;
      }
    else
      *cp1 = *namein;
  
  *cp1 = 0;

  if (j<3)
    return 0;

  if (hostname_isequal(lastchunk, "arpa") && hostname_isequal(penchunk, "in-addr"))
    {
      /* IP v4 */
      /* address arives as a name of the form
	 www.xxx.yyy.zzz.in-addr.arpa
	 some of the low order address octets might be missing
	 and should be set to zero. */
      for (cp1 = name; cp1 != penchunk; cp1 += strlen(cp1)+1)
	{
	  /* check for digits only (weeds out things like
	     50.0/24.67.28.64.in-addr.arpa which are used 
	     as CNAME targets according to RFC 2317 */
	  char *cp;
	  for (cp = cp1; *cp; cp++)
	    if (!isdigit((unsigned char)*cp))
	      return 0;
	  
	  addr[3] = addr[2];
	  addr[2] = addr[1];
	  addr[1] = addr[0];
	  addr[0] = atoi(cp1);
	}

      return F_IPV4;
    }
#ifdef HAVE_IPV6
  else if (hostname_isequal(penchunk, "ip6") && 
	   (hostname_isequal(lastchunk, "int") || hostname_isequal(lastchunk, "arpa")))
    {
      /* IP v6:
         Address arrives as 0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.ip6.[int|arpa]
    	 or \[xfedcba9876543210fedcba9876543210/128].ip6.[int|arpa]
      
	 Note that most of these the various reprentations are obsolete and 
	 left-over from the many DNS-for-IPv6 wars. We support all the formats
	 that we can since there is no reason not to.
      */

      if (*name == '\\' && *(name+1) == '[' && 
	  (*(name+2) == 'x' || *(name+2) == 'X'))
	{	  
	  for (j = 0, cp1 = name+3; *cp1 && isxdigit((unsigned char) *cp1) && j < 32; cp1++, j++)
	    {
	      char xdig[2];
	      xdig[0] = *cp1;
	      xdig[1] = 0;
	      if (j%2)
		addr[j/2] |= strtol(xdig, NULL, 16);
	      else
		addr[j/2] = strtol(xdig, NULL, 16) << 4;
	    }
	  
	  if (*cp1 == '/' && j == 32)
	    return F_IPV6;
	}
      else
	{
	  for (cp1 = name; cp1 != penchunk; cp1 += strlen(cp1)+1)
	    {
	      if (*(cp1+1) || !isxdigit((unsigned char)*cp1))
		return 0;
	      
	      for (j = sizeof(struct all_addr)-1; j>0; j--)
		addr[j] = (addr[j] >> 4) | (addr[j-1] << 4);
	      addr[0] = (addr[0] >> 4) | (strtol(cp1, NULL, 16) << 4);
	    }
	  
	  return F_IPV6;
	}
    }
#endif
  
  return 0;
}

unsigned char *skip_name(unsigned char *ansp, struct dns_header *header, size_t plen, int extrabytes)
{
  while(1)
    {
      unsigned int label_type;
      
      if (!CHECK_LEN(header, ansp, plen, 1))
	return NULL;
      
      label_type = (*ansp) & 0xc0;

      if (label_type == 0xc0)
	{
	  /* pointer for compression. */
	  ansp += 2;	
	  break;
	}
      else if (label_type == 0x80)
	return NULL; /* reserved */
      else if (label_type == 0x40)
	{
	  /* Extended label type */
	  unsigned int count;
	  
	  if (!CHECK_LEN(header, ansp, plen, 2))
	    return NULL;
	  
	  if (((*ansp++) & 0x3f) != 1)
	    return NULL; /* we only understand bitstrings */
	  
	  count = *(ansp++); /* Bits in bitstring */
	  
	  if (count == 0) /* count == 0 means 256 bits */
	    ansp += 32;
	  else
	    ansp += ((count-1)>>3)+1;
	}
      else
	{ /* label type == 0 Bottom six bits is length */
	  unsigned int len = (*ansp++) & 0x3f;
	  
	  if (!ADD_RDLEN(header, ansp, plen, len))
	    return NULL;

	  if (len == 0)
	    break; /* zero length label marks the end. */
	}
    }

  if (!CHECK_LEN(header, ansp, plen, extrabytes))
    return NULL;
  
  return ansp;
}

unsigned char *skip_questions(struct dns_header *header, size_t plen)
{
  int q;
  unsigned char *ansp = (unsigned char *)(header+1);

  for (q = ntohs(header->qdcount); q != 0; q--)
    {
      if (!(ansp = skip_name(ansp, header, plen, 4)))
	return NULL;
      ansp += 4; /* class and type */
    }
  
  return ansp;
}


int private_net(struct in_addr addr, int ban_localhost) 
{
  in_addr_t ip_addr = ntohl(addr.s_addr);

  return
    (((ip_addr & 0xFF000000) == 0x7F000000) && ban_localhost)  /* 127.0.0.0/8    (loopback) */ || 
    ((ip_addr & 0xFFFF0000) == 0xC0A80000)  /* 192.168.0.0/16 (private)  */ ||
    ((ip_addr & 0xFF000000) == 0x0A000000)  /* 10.0.0.0/8     (private)  */ ||
    ((ip_addr & 0xFFF00000) == 0xAC100000)  /* 172.16.0.0/12  (private)  */ ||
    ((ip_addr & 0xFFFF0000) == 0xA9FE0000)  /* 169.254.0.0/16 (zeroconf) */ ;
}

int extract_name(struct dns_header *header, size_t plen, unsigned char **pp, 
		 char *name, int isExtract, int extrabytes)
{
  unsigned char *cp = (unsigned char *)name, *p = *pp, *p1 = NULL;
  unsigned int j, l, hops = 0;
  int retvalue = 1;
  
  if (isExtract)
    *cp = 0;

	while (1)
    {
		unsigned int label_type;

		if (!CHECK_LEN(header, p, plen, 1))
			return 0;
		  
		if ((l = *p++) == 0) 
		/* end marker */
		{
		  /* check that there are the correct no of bytes after the name */
			if (!CHECK_LEN(header, p, plen, extrabytes))
				return 0;
		  
			if (isExtract)
			{
				if (cp != (unsigned char *)name)
					cp--;
				*cp = 0; /* terminate: lose final period */
			}
			else if (*cp != 0)
				retvalue = 2;
		  
			if (p1) /* we jumped via compression */
				*pp = p1;
			else
				*pp = p;
		  
			return retvalue;
		}

		label_type = l & 0xc0;
		  
		if (label_type == 0xc0) /* pointer */
		{ 
			if (!CHECK_LEN(header, p, plen, 1))
				return 0;
			  
			/* get offset */
			l = (l&0x3f) << 8;
			l |= *p++;
		  
			if (!p1) /* first jump, save location to go back to */
				p1 = p;
			  
			hops++; /* break malicious infinite loops */
			if (hops > 255)
				return 0;
		  
		  p = l + (unsigned char *)header;
		}
		else if (label_type == 0x80)
			return 0; /* reserved */
		else if (label_type == 0x40)
		{ /* ELT */
			unsigned int count, digs;
		  
			if ((l & 0x3f) != 1)
				return 0; /* we only understand bitstrings */

			if (!isExtract)
				return 0; /* Cannot compare bitsrings */
		  
			count = *p++;
			if (count == 0)
				count = 256;
			digs = ((count-1)>>2)+1;
		  
			/* output is \[x<hex>/siz]. which is digs+9 chars */
			if (cp - (unsigned char *)name + digs + 9 >= MAXDNAME)
				return 0;
			if (!CHECK_LEN(header, p, plen, (count-1)>>3))
				return 0;

			*cp++ = '\\';
			*cp++ = '[';
			*cp++ = 'x';
			for (j=0; j<digs; j++)
			{
				unsigned int dig;
				if (j%2 == 0)
					dig = *p >> 4;
				else
					dig = *p++ & 0x0f;
			
				*cp++ = dig < 10 ? dig + '0' : dig + 'A' - 10;
			} 
			cp += sprintf((char *)cp, "/%d]", count);
			/* do this here to overwrite the zero char from sprintf */
			*cp++ = '.';
		}
		else 
		{ /* label_type = 0 -> label. */
		  if (cp - (unsigned char *)name + l + 1 >= MAXDNAME)
			return 0;
		  if (!CHECK_LEN(header, p, plen, l))
			return 0;
		  
		  for(j=0; j<l; j++, p++)
			if (isExtract)
			{
				unsigned char c = *p;
				if (isascii(c) && !iscntrl(c) && c != '.')
				  *cp++ = *p;
				else
				  return 0;
			}
			else 
			{
				unsigned char c1 = *cp, c2 = *p;
				
				if (c1 == 0)
				  retvalue = 2;
				else 
				  {
					cp++;
					if (c1 >= 'A' && c1 <= 'Z')
					  c1 += 'a' - 'A';
					if (c2 >= 'A' && c2 <= 'Z')
					  c2 += 'a' - 'A';
					
					if (c1 != c2)
					  retvalue =  2;
				  }
			}
		  
		  if (isExtract)
			*cp++ = '.';
		  else if (*cp != 0 && *cp++ != '.')
			retvalue = 2;
		}
    }
}

int extract_addresses(struct dns_header *header, size_t qlen, char *name, time_t now, 
		      char **ipsets, int is_sign, int check_rebind, int no_cache_dnssec, char *domain, char *resolv_ip)
{
	unsigned char *p, *p1, *endrr, *namep;
	int i, j, qtype, qclass, aqtype, aqclass, ardlen, res, searched_soa = 0;
	unsigned long ttl = 0;
	struct all_addr addr;
#ifdef HAVE_IPSET
	char **ipsets_cur;
#else
	(void)ipsets; /* unused */
#endif
	int ip_len = 0;
	int got_name = 0;
	char ips[4096];
	
	memset(ips, 0, sizeof(ips));
	//cache_start_insert();
#if 0
	/* find_soa is needed for dns_doctor and logging side-effects, so don't call it lazily if there are any. */
	if (daemon->doctors || option_bool(OPT_LOG) || option_bool(OPT_DNSSEC_VALID))
	{
		searched_soa = 1;
		ttl = find_soa(header, qlen, name, doctored);
#ifdef HAVE_DNSSEC
		if (*doctored && secure)
			return 0;
#endif
	}
#endif

	/* go through the questions. */
	p = (unsigned char *)(header+1);
  
	for (i = ntohs(header->qdcount); i != 0; i--)
	{
		int found = 0, cname_count = CNAME_CHAIN;
		//struct crec *cpp = NULL;
		int flags = RCODE(header) == NXDOMAIN ? F_NXDOMAIN : 0;
		int secflag = 0 ?  F_DNSSECOK : 0;
		unsigned long cttl = ULONG_MAX, attl;

		namep = p;
		if (!extract_name(header, qlen, &p, name, 1, 4))
			return 0; /* bad packet */
           
		GETSHORT(qtype, p); 
		GETSHORT(qclass, p);
      
		if (qclass != C_IN)
			continue;

		/* PTRs: we chase CNAMEs here, since we have no way to 
			represent them in the cache. */
		if (qtype == T_PTR)
		{ 
			int name_encoding = in_arpa_name_2_addr(name, &addr);
		  
			if (!name_encoding)
				continue;

			if (!(flags & F_NXDOMAIN))
			{
			cname_loop:
				if (!(p1 = skip_questions(header, qlen)))
					return 0;
			
				for (j = ntohs(header->ancount); j != 0; j--) 
				{
					unsigned char *tmp = namep;
					/* the loop body overwrites the original name, so get it back here. */
					if (!extract_name(header, qlen, &tmp, name, 1, 0) ||
						!(res = extract_name(header, qlen, &p1, name, 0, 10)))
						return 0; /* bad packet */
					GETSHORT(aqtype, p1); 
					GETSHORT(aqclass, p1);
					GETLONG(attl, p1);
				#if 0
					if ((daemon->max_ttl != 0) && (attl > daemon->max_ttl) && !is_sign)
					{
						(p1) -= 4;
						PUTLONG(daemon->max_ttl, p1);
					}
				#endif
					GETSHORT(ardlen, p1);
					endrr = p1+ardlen;
					
					/* TTL of record is minimum of CNAMES and PTR */
					if (attl < cttl)
						cttl = attl;

					if (aqclass == C_IN && res != 2 && (aqtype == T_CNAME || aqtype == T_PTR))
					{
						if (!extract_name(header, qlen, &p1, name, 1, 0))
							return 0;
					  
						if (aqtype == T_CNAME)
						{
							if (!cname_count--)
								return 0; /* looped CNAMES, or DNSSEC, which we can't cache. */
							goto cname_loop;
						}
						
						
						if (flags & F_IPV4){
							//LOG("ipv4 flag ip_len=%d\n", ip_len);
							
							
							char *ip = inet_ntoa(addr.addr.addr4);
						#if 0
							if (ip_len > 0)
								sprintf(ips+ip_len, ",%s", ip);
							else {
								sprintf(ips+ip_len, "%s", ip);
							}
							
							ip_len = strlen(ips);
						#endif
							LOG("PTR = inet_ntoa ip=%s, %d\n", ip, ip_len);
							
						} else {
						#ifdef HAVE_IPV6
							printf("%s(%d):inet_ntoa ip=%s\n", __FUNCTION__, __LINE__, inet_ntoa(addr.addr.addr6));
						#endif
						}
						
						//cache_insert(name, &addr, now, cttl, name_encoding | secflag | F_REVERSE);
						found = 1; 
					}
				  
					p1 = endrr;
					if (!CHECK_LEN(header, p1, qlen, 0))
						return 0; /* bad packet */
				}
			}
		#if 0
			if (!found && !option_bool(OPT_NO_NEG))
			{
				if (!searched_soa)
				{
					searched_soa = 1;
					ttl = find_soa(header, qlen, NULL, doctored);
				}
				if (ttl)
					cache_insert(NULL, &addr, now, ttl, name_encoding | F_REVERSE | F_NEG | flags | secflag);	
			}
		#endif
		}
		else
		{
			/* everything other than PTR */
			//struct crec *newc;
			int addrlen;

			if (qtype == T_A)
			{
				addrlen = INADDRSZ;
				flags |= F_IPV4;
			}
	#ifdef HAVE_IPV6
			else if (qtype == T_AAAA)
			{
				addrlen = IN6ADDRSZ;
				flags |= F_IPV6;
			}
	#endif
			else 
				continue;
			
		cname_loop1:
			if (!(p1 = skip_questions(header, qlen)))
				return 0;
		  
			for (j = ntohs(header->ancount); j != 0; j--) 
			{
				//Extract name:
				if (!(res = extract_name(header, qlen, &p1, name, 0, 10)))
					return 0; /* bad packet */
				//LOG("cname_loop1 query_name=%s\n", name);
				if (!got_name) {
					got_name++;
					sprintf(domain, "%s", name);
					//LOG("domain=%s\n", domain);
				}
				
				GETSHORT(aqtype, p1); 
				GETSHORT(aqclass, p1);
				GETLONG(attl, p1);
			#if 0
				if ((daemon->max_ttl != 0) && (attl > daemon->max_ttl) && !is_sign)
				{
					(p1) -= 4;
					PUTLONG(daemon->max_ttl, p1);
				}
			#endif
				GETSHORT(ardlen, p1);
				endrr = p1+ardlen;
				
				if (aqclass == C_IN && res != 2 && (aqtype == T_CNAME || aqtype == qtype))
				{
					if (aqtype == T_CNAME)
					{
						//printf("cname_count=%d\n", cname_count);
						if (!cname_count--)
							return 0; /* looped CNAMES */
					#if 0
						newc = cache_insert(name, NULL, now, attl, F_CNAME | F_FORWARD | secflag);
						if (newc)
						{
							newc->addr.cname.target.cache = NULL;
							/* anything other than zero, to avoid being mistaken for CNAME to interface-name */ 
							newc->addr.cname.uid = 1; 
							if (cpp)
							{
								cpp->addr.cname.target.cache = newc;
								cpp->addr.cname.uid = newc->uid;
							}
						}
					  
						cpp = newc;
						if (attl < cttl)
							cttl = attl;
					#endif
					
						if (!extract_name(header, qlen, &p1, name, 1, 0))
							return 0;
						//LOG("C_IN, T_CNAME, name=%s\n", name);
						goto cname_loop1;
					}
					else if (!(flags & F_NXDOMAIN)) 
					{
						found = 1;
					  
						/* copy address into aligned storage */
						if (!CHECK_LEN(header, p1, qlen, addrlen))
							return 0; /* bad packet */
						memcpy(&addr, p1, addrlen);
					  
						/* check for returned address in private space */
						if (check_rebind)
						{
							if ((flags & F_IPV4) &&
								private_net(addr.addr.addr4, 1))
								return 1;
					  
		#ifdef HAVE_IPV6
							if ((flags & F_IPV6) &&
							  IN6_IS_ADDR_V4MAPPED(&addr.addr.addr6))
							{
								struct in_addr v4;
								v4.s_addr = ((const uint32_t *) (&addr.addr.addr6))[3];
								if (private_net(v4, 1))
								return 1;
							}
		#endif
						}
					  
		#ifdef HAVE_IPSET
						if (ipsets && (flags & (F_IPV4 | F_IPV6)))
						{
						  ipsets_cur = ipsets;
						  while (*ipsets_cur)
							{
							  log_query((flags & (F_IPV4 | F_IPV6)) | F_IPSET, name, &addr, *ipsets_cur);
							  add_to_ipset(*ipsets_cur++, &addr, flags, 0);
							}
						}
		#endif
					
						if (flags & F_IPV4){
							//LOG("ipv4 flag ip_len=%d\n", ip_len);
							char *ip = inet_ntoa(addr.addr.addr4);
							if (ip_len > 0) {
								char *p = strstr(ips, ip);
								//End of string
								if (p && (*(p+strlen(ip)) == '\0' || *(p+strlen(ip)) == ',')) { 
									//Start of string
									if(strncmp(ips, ip, strlen(ip)) == 0 || *(p-1) == ',') {
										LOG("Same ip exist ip=[%s],ips=[%s]\n", ip, ips);
									} else {
										LOG("Possible Same ip exist ip=[%s],ips=[%s]\n", ip, ips);
										sprintf(ips+ip_len, ",%s", ip);
										ip_len = strlen(ips);
									}
								} else {
									sprintf(ips+ip_len, ",%s", ip);
									ip_len = strlen(ips);
								}
							}
							else {
								sprintf(ips+ip_len, "%s", ip);
								ip_len = strlen(ips);
							}
							
							//LOG("Non-PTR inet_ntoa ip=%s, ips=[%s], %d\n", ip, ips, ip_len);
						}
						else {
						#ifdef HAVE_IPV6
							//printf("%s(%d):inet_ntoa ip=%s\n", __FUNCTION__, __LINE__, inet_ntoa(addr.addr.addr6));
						#endif
						}
					#if 0
						newc = cache_insert(name, &addr, now, attl, flags | F_FORWARD | secflag);
						if (newc && cpp)
						{
						  cpp->addr.cname.target.cache = newc;
						  cpp->addr.cname.uid = newc->uid;
						}
						  cpp = NULL;
					#endif
					
					}
				}
				  
				p1 = endrr;
				if (!CHECK_LEN(header, p1, qlen, 0))
					return 0; /* bad packet */
			}
		#if 0
			if (!found && !option_bool(OPT_NO_NEG))
			{
				if (!searched_soa)
				{
					searched_soa = 1;
					ttl = find_soa(header, qlen, NULL, doctored);
				}
				  /* If there's no SOA to get the TTL from, but there is a CNAME 
				 pointing at this, inherit its TTL */
				if (ttl || cpp)
				{
					newc = cache_insert(name, NULL, now, ttl ? ttl : cttl, F_FORWARD | F_NEG | flags | secflag);	
					if (newc && cpp)
					{
						cpp->addr.cname.target.cache = newc;
						cpp->addr.cname.uid = newc->uid;
					}
				}
			}
		#endif
		}
	}
  
  /* Don't put stuff from a truncated packet into the cache.
     Don't cache replies from non-recursive nameservers, since we may get a 
     reply containing a CNAME but not its target, even though the target 
     does exist. */
  //if (!(header->hb3 & HB3_TC) && 
  //    !(header->hb4 & HB4_CD) &&
  //    (header->hb4 & HB4_RA) &&
  //    !no_cache_dnssec)
    //cache_end_insert();

	sprintf(resolv_ip, "%s", ips);
	//LOG("resolv_ip=[%s]\n", resolv_ip);
  return 0;
}

void dissectDNS(u_int8_t *payload, u_int16_t payload_len, int l4_proto, char *mac, uint64_t time){
	/*
	  DNS-over-TCP has a 2-bytes field with DNS payload length
	  at the beginning. See RFC1035 section 4.2.2. TCP usage.
	*/
	u_int8_t dns_offset = l4_proto == IPPROTO_TCP && payload_len > 1 ? 2 : 0;
	struct ndpi_dns_packet_header *header = (struct ndpi_dns_packet_header*)(payload + dns_offset);
	u_int16_t dns_flags = ntohs(header->flags);
	int is_query = ((dns_flags & 0x8000) == 0x8000) ? 0 : 1;

	if(is_query && payload_len > 12) {
		//LOG("dns enter\n");
		/* Richard Search Query */
		unsigned char *p = (unsigned char *)(header+1);
		if (ntohs(((struct dns_header *)header)->qdcount) != 1 || OPCODE((struct dns_header *)header) != QUERY)//
		{

		} else {
			char domain[MAXDNAME];
			memset(domain, 0, sizeof(domain));
			extract_name((struct dns_header *)header, payload_len-dns_offset, &p, domain, 1, 4);
			dns_log_write("dns.list", domain, mac, time, "");
		}
	} else if (payload_len > 12) {
		char domain[MAXDNAME], ips[MAXDNAME*4], name[MAXDNAME];
		memset(domain, 0, sizeof(domain));
		memset(name, 0, sizeof(name));
		memset(ips, 0, sizeof(ips));
		
		extract_addresses((struct dns_header *)header,payload_len-dns_offset, name, time, NULL, 0, 1, 1, domain, ips);
		//LOG("domain=[%s], ips=[%s]\n", domain, ips);
		if (strlen(ips) > 0 && strlen(domain) > 0) {
			dns_log_write("dns.list", domain, mac, time, ips);
		}
		//dns_log_write("dns.list", domain, mac, time);
	}
}
