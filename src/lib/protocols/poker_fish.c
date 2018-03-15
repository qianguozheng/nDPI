#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_BOKE_FISH
/*
 *  波克捕鱼
 *  MSSQL-TDS 匹配到了这个协议
 * 
 *  匹配前几个字节 0x03 0x00 0x00 匹配到3次
 *  
 * 
 * 
 */
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_BOKE_FISH

#include "ndpi_api.h"
#include <linux/types.h>

#define WZRY_ENSRUED1_MAX 3
#define WZRY_ENSRUED2_MAX 2
#define WZRY_UNSRUED1_MAX 24
#define WZRY_UNSRUED2_MAX 4



static void ndpi_search_boke_fish_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	__be32 plen = 0;
	uint32_t ulen = 0;
	__be16 pslen = 0;
	uint16_t uslen = 0;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	
	printf("[%x %x %x]\n", buff[0], buff[1], buff[2]);
	if (packet->payload_packet_len < 6 ) return;

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_BOKE_FISH) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_BOKE_FISH)) {
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BOKE_FISH, NDPI_PROTOCOL_UNKNOWN);
		return;
	}

	
	if (buff[0] == 0x3 && buff[1] == 0x00 && buff[2] == 0x00) {
		flow->common.ensured_pkts ++;
		//printf("flow->common.ensured_pkts=%d\n", flow->common.ensured_pkts);
		if (flow->common.ensured_pkts >= WZRY_ENSRUED1_MAX) {
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_BOKE_FISH, NDPI_PROTOCOL_UNKNOWN);
		}
		return;
	}


	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < WZRY_UNSRUED2_MAX) return;
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_BOKE_FISH);
}

static void ndpi_search_boke_fish(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
	//printf("counter=%d\n", flow->packet_counter);
	if (packet->udp != NULL) {
		//ndpi_search_sgz_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		ndpi_search_boke_fish_tcp(ndpi_struct, flow);
	}
}


void init_boke_fish_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("PokerFish", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_BOKE_FISH,
				      ndpi_search_boke_fish,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
