#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_TERMINATOR

/*
 * 
 *  匹配udp 的前5个字节，和17-24的8个字节， udp包要>=24, 
 *  规律： 好几个udp的开头都是符合以上的规则
 * 
 * 
 */
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TERMINATOR

#include "ndpi_api.h"

#define TERMINATOR_UNSRUED2_MAX 16
#define TERMINATOR_ENSRUED1_MAX 2

#define TERMINATOR_UNSRUED1_MAX 24

static void ndpi_search_terminator_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	if (packet->payload_packet_len < 24 ) return;
	
	if (buff[0] == 0x1 && buff[1] == 0 && buff[2] == 0 && buff[3] == 0xb && buff[4] == 0 &&
	    buff[16] == 0 && buff[17] == 0 && buff[18] == 0 && buff[19] == 0x14 && buff[20] == 0 &&
	    buff[21] == 0 && buff[22] == 0x2 && buff[23] == 0 ) {
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TERMINATOR, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	
#if 0
	if (flow->common.session_stage < 4) {
		if ((flow->common.session_stage + 1) == buff[0]) {
			flow->common.session_stage ++;
			return;
		}
	} else {
		// run this, the fifth package
		if (packet->payload_packet_len > 5 && buff[0] == 0x00 && buff[1] == 0x00 
			&& buff[2] == 0x00 && buff[3] == 0x00 && (buff[4]&0xf0) == 0x50) {
			flow->common.ensured_pkts ++;
			if (flow->common.ensured_pkts < TERMINATOR_ENSRUED1_MAX)  return;
			
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TERMINATOR, NDPI_PROTOCOL_UNKNOWN);
			return;
		}

		if ((flow->common.session_stage + 1) == buff[0]) {
			flow->common.session_stage ++;
			
			if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_TERMINATOR) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_TERMINATOR)) {
				ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TERMINATOR, NDPI_PROTOCOL_UNKNOWN);
			}
			return;
		}
	}
#endif

	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < TERMINATOR_UNSRUED1_MAX) return;
	// If more than 16 packets have not recognized the application protocol, then ignore it
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TERMINATOR);
}

static void ndpi_search_terminator_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	uint16_t uslen = 0;
	const u_int8_t *buff = packet->payload;
	
	if (packet->payload_packet_len > 6 ) {
		uslen = (buff[0]&0xff) + (buff[1]<<8);
		if (uslen == packet->payload_packet_len) {
			if (buff[2] == 0x00 && buff[3] == 0x00 && buff[5] == 0x80) {
				// buff[4] is 0x0c OR 0x0d, 0x10, 0x11, ...
				flow->common.ensured_pkts ++;
				if (flow->common.ensured_pkts < TERMINATOR_ENSRUED1_MAX)  return;
				ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TERMINATOR, NDPI_PROTOCOL_UNKNOWN);
				return;
			}
		}
	}
	
	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < TERMINATOR_UNSRUED2_MAX) return;
	// If more than 16 packets have not recognized the application protocol, then ignore it
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TERMINATOR);
}


static void ndpi_search_terminator(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->udp != NULL) {
		ndpi_search_terminator_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		ndpi_search_terminator_tcp(ndpi_struct, flow);
	}
}

void init_terminator_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("terminator", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TERMINATOR,
				      ndpi_search_terminator,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
