#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_DREAM_XIYOU
/*
 *  波克捕鱼
 *  匹配前几个字节 6 个字节 一次， 后续可以继续看看协议的变化
 *  0x0e 0x00 0xfe 0xff 0x02 0x01
 * 
 * 
 */
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DREAM_XIYOU

#include "ndpi_api.h"
#include <linux/types.h>

#define WZRY_ENSRUED1_MAX 3
#define WZRY_ENSRUED2_MAX 2
#define WZRY_UNSRUED1_MAX 24
#define WZRY_UNSRUED2_MAX 4



static void ndpi_search_dream_xiyou_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
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

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_DREAM_XIYOU) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_DREAM_XIYOU)) {
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DREAM_XIYOU, NDPI_PROTOCOL_UNKNOWN);
		return;
	}

	
	if (buff[0] == 0x0e && buff[1] == 0x00 && buff[2] == 0xfe
	 && buff[3] == 0xff && buff[4] == 0x02 && buff[5] == 0x01) {
		//flow->common.ensured_pkts ++;
		//printf("flow->common.ensured_pkts=%d\n", flow->common.ensured_pkts);
		//if (flow->common.ensured_pkts >= WZRY_ENSRUED1_MAX) {
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DREAM_XIYOU, NDPI_PROTOCOL_UNKNOWN);
		//}
		return;
	}


	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < WZRY_UNSRUED2_MAX) return;
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DREAM_XIYOU);
}

static void ndpi_search_dream_xiyou(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	//printf("counter=%d\n", flow->packet_counter);
	if (packet->udp != NULL) {
		//ndpi_search_sgz_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		ndpi_search_dream_xiyou_tcp(ndpi_struct, flow);
	}
}


void init_dream_xiyou_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("DreamXiYou", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DREAM_XIYOU,
				      ndpi_search_dream_xiyou,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
