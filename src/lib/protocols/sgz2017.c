#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_SANGUO
/*
 *  三国志 2017 
 *  匹配TCP端口 7642
 * 
 * 
 * 
 */
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SANGUO

#include "ndpi_api.h"
#include <linux/types.h>

static void ndpi_search_sgz(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->udp != NULL) {
		//ndpi_search_sgz_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		//ndpi_search_sgz_tcp(ndpi_struct, flow);
	}
}


void init_sgz_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("SanGuoZhi", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SANGUO,
				      ndpi_search_sgz,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
