#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_QQ_CAR

/*
 * 
 * QQ飞车
 * 匹配： udp 的5～8的4个字节
 * 规律：发现客户端的好几个请求都含有这几个字节
 * 
 */
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_QQ_CAR

#include "ndpi_api.h"
#include <linux/types.h>

#define WZRY_ENSRUED1_MAX 3
#define WZRY_ENSRUED2_MAX 2
#define WZRY_UNSRUED1_MAX 24
#define WZRY_UNSRUED2_MAX 4



static void ndpi_search_qq_car_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

}

static void ndpi_search_qq_car_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	if (packet->payload_packet_len < 8 ) return;

	if (buff[4] == 0x00 && buff[5] == 0x00 && buff[6] == 0x03 && buff[7] == 0x64) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts < WZRY_ENSRUED1_MAX)  return;
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QQ_CAR, NDPI_PROTOCOL_UNKNOWN);
		return;
	}

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_QQ_CAR) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_QQ_CAR)) {
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QQ_CAR, NDPI_PROTOCOL_UNKNOWN);
		return;
	}

	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < WZRY_UNSRUED1_MAX) return;
	// If more than 24 packets have not recognized the application protocol, then ignore it
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QQ_CAR);
}

static void ndpi_search_qq_car(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->udp != NULL) {
		ndpi_search_qq_car_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		//ndpi_search_qq_car_tcp(ndpi_struct, flow);
	}
}


void init_qq_car_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("QQ_Car", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_QQ_CAR,
				      ndpi_search_qq_car,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
