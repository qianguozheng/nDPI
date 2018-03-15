#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_YINYANG
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_YINYANG

#include "ndpi_api.h"
#include <linux/types.h>

#define WZRY_ENSRUED1_MAX 3
#define WZRY_ENSRUED2_MAX 2
#define WZRY_UNSRUED1_MAX 24
#define WZRY_UNSRUED2_MAX 4

/**
 * 
 *  匹配TCP相关内容
 *  0x02 0x00 0x00 0x00 0x00 0x00
 * 
 * 
 **/

static void ndpi_search_yinyang_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	__be32 plen = 0;
	uint32_t ulen = 0;
	__be16 pslen = 0;
	uint16_t uslen = 0;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	
	if (packet->payload_packet_len < 6 ) return;

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_YINYANG) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_YINYANG)) {
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->tcp) {
			printk(KERN_INFO"ndpi: detect WZRY PVP 04 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
		}
	#endif
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YINYANG, NDPI_PROTOCOL_UNKNOWN);
		return;
	}	
	#if 0 // This is XiaoMi protocol
	if (buff[0] == 0xc2 && buff[1] == 0xfe && buff[2] == 0x00 && buff[3] == 0x05) {
		printf("===========22\n");
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts >= WZRY_ENSRUED1_MAX) {
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YINYANG, NDPI_PROTOCOL_UNKNOWN);
		}
		
		return;
	}
	#endif
	
	if (packet->payload_packet_len == 6 
	 && buff[0] == 0x02 && buff[1] == 0x00 && buff[2] == 0x00 && buff[3] == 0x00
	 && buff[4] == 0x00 && buff[5] == 0x00) {
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YINYANG, NDPI_PROTOCOL_UNKNOWN);
		return;
	}


	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < WZRY_UNSRUED2_MAX) return;
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_YINYANG);
}


static void ndpi_search_yinyang(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->udp != NULL) {
		//ndpi_search_yinyang_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		ndpi_search_yinyang_tcp(ndpi_struct, flow);
	}
}


void init_yinyang_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("YinYang", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_YINYANG,
				      ndpi_search_yinyang,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
