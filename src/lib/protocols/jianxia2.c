#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_JIANXIA
/*
 *  剑侠2
 *  匹配： 第2-8共有7个字节，两个包
 *  规律： 发现client-> server和server->client的第一个请求和响应的这7个字节相同
 *  
 * 
 * 
 */
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_JIANXIA

#include "ndpi_api.h"
#include <linux/types.h>

#define WZRY_ENSRUED1_MAX 3
#define WZRY_ENSRUED2_MAX 2
#define WZRY_UNSRUED1_MAX 24
#define WZRY_UNSRUED2_MAX 4



static void ndpi_search_jianxia_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	__be32 plen = 0;
	uint32_t ulen = 0;
	__be16 pslen = 0;
	uint16_t uslen = 0;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	
	//printf("[%x %x %x]\n", buff[0], buff[1], buff[2]);
	if (packet->payload_packet_len < 6 ) return;

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_JIANXIA) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_JIANXIA)) {
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JIANXIA, NDPI_PROTOCOL_UNKNOWN);
		return;
	}

	
	if (buff[1] == 0x0e && buff[2] == 0x0e && buff[3] == 0xe && buff[4] == 0x6d && buff[5] == 0xf && buff[6] == 0xe && buff[7] == 0x36) {
		flow->common.ensured_pkts ++;
		//printf("flow->common.ensured_pkts=%d\n", flow->common.ensured_pkts);
		if (flow->common.ensured_pkts >= WZRY_ENSRUED2_MAX) {
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JIANXIA, NDPI_PROTOCOL_UNKNOWN);
		}
		return;
	}


	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < WZRY_UNSRUED2_MAX) return;
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_JIANXIA);
}

static void ndpi_search_jianxia(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	//printf("counter=%d\n", flow->packet_counter);
	if (packet->udp != NULL) {
		//ndpi_search_sgz_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		ndpi_search_jianxia_tcp(ndpi_struct, flow);
	}
}


void init_jianxia2_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("JianXia2", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_JIANXIA,
				      ndpi_search_jianxia,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
