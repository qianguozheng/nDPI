#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_QQ_HUANLE

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_QQ_HUANLE

#include "ndpi_api.h"


static void ndpi_int_qq_huanle_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QQ_HUANLE, NDPI_PROTOCOL_UNKNOWN);
}

	
#if !defined(WIN32)
static inline
#elif defined(MINGW_GCC)
__mingw_forceinline static
#else
__forceinline static
#endif
u_int8_t search_client_request(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  u_int16_t a;

  if (packet->payload_packet_len < 3) {
    return 0;
  }
  //前6个字节的内容，不知道下一个版本对不对，下次再测试看看
  if (!(packet->payload[0] == 0x00
	&& packet->payload[1] == 0x00 && packet->payload[2] == 0x00 && packet->payload[3] == 0x18
	&& packet->payload[4] == 0x78 && packet->payload[5] == 0x01)) {
    return 0;
  }

  return 1;
}

/* this detection also works asymmetrically */
void ndpi_search_qq_huanle_tcp(struct ndpi_detection_module_struct
			    *ndpi_struct, struct ndpi_flow_struct *flow)
{

  NDPI_LOG_DBG(ndpi_struct, "search qq huanle\n");

  if (search_client_request(ndpi_struct, flow) == 1) {

      NDPI_LOG_INFO(ndpi_struct, "found qq huanle\n");
      ndpi_int_qq_huanle_add_connection(ndpi_struct, flow);
      return;
  }

  if ((flow->packet_counter < 12 && flow->l4.tcp.telnet_stage > 0) || flow->packet_counter < 6) {
    return;
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
  return;
}


void init_qq_huanle_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("QQ_HUANLE", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_QQ_HUANLE,
				      ndpi_search_qq_huanle_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
