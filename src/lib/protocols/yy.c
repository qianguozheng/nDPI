#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_YY

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_YY

#include "ndpi_api.h"

/* start from 0: client
 *  6-9: 0x03, 0x00, 0xc8, 0x00
 * start from 0: server
 *  6-9: 0x01, 0x00, 0xc8, 0x00
 */
static void ndpi_int_yy_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_YY, NDPI_PROTOCOL_UNKNOWN);
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
  //6-9, 4个字节的内容，不知道下一个版本对不对，下次再测试看看
  if (!((packet->payload[6] == 0x03 || packet->payload[6] == 0x01)
	&& packet->payload[7] == 0x00 
	&& packet->payload[8] == 0xc8 
	&& packet->payload[9] == 0x00)) {
    return 0;
  }

  return 1;
}

/* this detection also works asymmetrically */
void ndpi_search_yy_udp(struct ndpi_detection_module_struct
			    *ndpi_struct, struct ndpi_flow_struct *flow)
{

  NDPI_LOG_DBG(ndpi_struct, "search yy udp\n");

  if (search_client_request(ndpi_struct, flow) == 1) {

      NDPI_LOG_INFO(ndpi_struct, "found yy\n");
      ndpi_int_yy_add_connection(ndpi_struct, flow);
      return;
  }

  if (flow->packet_counter < 6) {
    return;
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
  return;
}


void init_yy_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("YY", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_YY,
				      ndpi_search_yy_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
