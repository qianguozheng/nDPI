#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_WZRY

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WZRY

#include "ndpi_api.h"
#include <linux/types.h>

#define WZRY_ENSRUED1_MAX 3
#define WZRY_ENSRUED2_MAX 2
#define WZRY_UNSRUED1_MAX 24
#define WZRY_UNSRUED2_MAX 4



static void ndpi_search_wzry_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
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

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_WZRY) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_WZRY)) {
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->tcp) {
			printk(KERN_INFO"ndpi: detect WZRY PVP 04 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
		}
	#endif
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WZRY, NDPI_PROTOCOL_UNKNOWN);
		return;
	}	
	
	if (buff[0] == 0x33 && buff[1] == 0x66 && buff[2] == 0x00 && buff[3] == 0x09) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts >= WZRY_ENSRUED1_MAX) {
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->tcp) {
				printk(KERN_INFO"ndpi: detect WZRY PVP 01 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
			}
		#endif
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WZRY, NDPI_PROTOCOL_UNKNOWN);
		}
		
		return;
	}

	if (buff[0] == 0x01 && buff[1] == 0x00 && buff[2] == 0x00) {
		memcpy((void *)&pslen, &buff[3], 2);
		uslen = ntohs(pslen);  // application pkt length
		if (uslen == packet->payload_packet_len) {
			flow->common.ensured_pkts ++;
			if (flow->common.ensured_pkts < WZRY_ENSRUED2_MAX)  return;
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->tcp) {
				printk(KERN_INFO"ndpi: detect WZRY PVP 02 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
			}
		#endif
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WZRY, NDPI_PROTOCOL_UNKNOWN);
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
			if (flow->common.ensured_pkts < WZRY_ENSRUED2_MAX)  return;
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->tcp) {
				printk(KERN_INFO"ndpi: detect WZRY PVP 03 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
			}
		#endif
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WZRY, NDPI_PROTOCOL_UNKNOWN);
		}
		return ;
	}

	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < WZRY_UNSRUED2_MAX) return;
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_WZRY);
}

static void ndpi_search_wzry_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	if (packet->payload_packet_len < 8 ) return;

	if (buff[0] == 0x01 && buff[1] == 0x02 && buff[2] == 0x00 && buff[3] == 0x00 &&
		buff[4] == 0x9a && buff[5] == 0xbc && buff[6] == 0xde && buff[7] == 0xf0) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts < WZRY_ENSRUED1_MAX)  return;
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WZRY, NDPI_PROTOCOL_UNKNOWN);
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->udp) {
			printk(KERN_INFO"ndpi: detect WZRY UDP 01 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->udp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->udp->dest));
		}
	#endif
		return;
	}

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_WZRY) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_WZRY)) {
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->udp) {
			printk(KERN_INFO"ndpi: detect WZRY UDP 02 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->udp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->udp->dest));
		}
	#endif
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WZRY, NDPI_PROTOCOL_UNKNOWN);
		return;
	}

	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < WZRY_UNSRUED1_MAX) return;
	// If more than 24 packets have not recognized the application protocol, then ignore it
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_WZRY);
}

static void ndpi_search_wzry(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->udp != NULL) {
		ndpi_search_wzry_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		ndpi_search_wzry_tcp(ndpi_struct, flow);
	}
}


void init_wzry_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("WZRY", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_WZRY,
				      ndpi_search_wzry,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif