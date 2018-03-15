#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_ROYAL_WAR

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ROYAL_WAR

#include "ndpi_api.h"
#include <linux/types.h>

#define ROYAL_WAR_ENSRUED1_MAX 3
#define ROYAL_WAR_ENSRUED2_MAX 2
#define ROYAL_WAR_UNSRUED1_MAX 24
#define ROYAL_WAR_UNSRUED2_MAX 4

/**
 *  匹配规则： udp/tcp 端口9339
 *  
 * 
 */


static void ndpi_search_royalwar_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	__be32 plen = 0;
	uint32_t ulen = 0;
	__be16 pslen = 0;
	uint16_t uslen = 0;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	
	if (packet->payload_packet_len < 8 ) return;

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_ROYAL_WAR) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_ROYAL_WAR)) {
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->tcp) {
			printk(KERN_INFO"ndpi: detect ROYAL_WAR PVP 04 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
		}
	#endif
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ROYAL_WAR, NDPI_PROTOCOL_UNKNOWN);
		return;
	}	
	
	if (buff[0] == 0x33 && buff[1] == 0x66 && buff[2] == 0x00 && buff[3] == 0x09) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts >= ROYAL_WAR_ENSRUED1_MAX) {
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->tcp) {
				printk(KERN_INFO"ndpi: detect ROYAL_WAR PVP 01 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
			}
		#endif
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ROYAL_WAR, NDPI_PROTOCOL_UNKNOWN);
		}
		
		return;
	}

	if (buff[0] == 0x01 && buff[1] == 0x00 && buff[2] == 0x00) {
		memcpy((void *)&pslen, &buff[3], 2);
		uslen = ntohs(pslen);  // application pkt length
		if (uslen == packet->payload_packet_len) {
			flow->common.ensured_pkts ++;
			if (flow->common.ensured_pkts < ROYAL_WAR_ENSRUED2_MAX)  return;
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->tcp) {
				printk(KERN_INFO"ndpi: detect ROYAL_WAR PVP 02 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
			}
		#endif
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ROYAL_WAR, NDPI_PROTOCOL_UNKNOWN);
		}
		return ;
	}

	memcpy((void *)&plen, buff, 4);
	ulen = ntohl(plen);
	ulen += 4;  // application pkt length 
	//if (ulen == packet->payload_packet_len && ulen >= 8) {
	if (ulen < 3000 && ulen >= 8) {
		if (buff[4] == 0x78 && buff[5] == 0x01) {
			flow->common.ensured_pkts ++;
			if (flow->common.ensured_pkts < ROYAL_WAR_ENSRUED2_MAX)  return;
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->tcp) {
				printk(KERN_INFO"ndpi: detect ROYAL_WAR PVP 03 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
			}
		#endif
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ROYAL_WAR, NDPI_PROTOCOL_UNKNOWN);
		}
		return ;
	}

	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < ROYAL_WAR_UNSRUED2_MAX) return;
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ROYAL_WAR);
}

static void ndpi_search_royal_war_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	if (packet->payload_packet_len < 8 ) return;

	//教学
	if (buff[0] == 0x0f && buff[1] == 0xd7 && buff[2] == 0x8f && buff[3] == 0x83 &&
		buff[4] == 0xd8 && buff[5] == 0xc9 && buff[6] == 0xf7 && buff[7] == 0xc4) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts < ROYAL_WAR_ENSRUED1_MAX)  return;
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ROYAL_WAR, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	//对战
	if (buff[0] == 0xf6 && buff[1] == 0xf5 && buff[2] == 0xce && buff[3] == 0x23 &&
		buff[4] == 0x4b && buff[5] == 0x55 && buff[6] == 0x97 && buff[7] == 0x01) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts < ROYAL_WAR_ENSRUED1_MAX)  return;
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ROYAL_WAR, NDPI_PROTOCOL_UNKNOWN);
		return;
	}

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_ROYAL_WAR) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_ROYAL_WAR)) {
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->udp) {
			printk(KERN_INFO"ndpi: detect ROYAL_WAR UDP 02 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->udp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->udp->dest));
		}
	#endif
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ROYAL_WAR, NDPI_PROTOCOL_UNKNOWN);
		return;
	}

	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < ROYAL_WAR_UNSRUED1_MAX) return;
	// If more than 24 packets have not recognized the application protocol, then ignore it
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_ROYAL_WAR);
}

static void ndpi_search_royal_war(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->udp != NULL) {
		ndpi_search_royal_war_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		//ndpi_search_royal_war_tcp(ndpi_struct, flow);
	}
}


void init_royal_war_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("RoyalWar", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_ROYAL_WAR,
				      ndpi_search_royal_war,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
