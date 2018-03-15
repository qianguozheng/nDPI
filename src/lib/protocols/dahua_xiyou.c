#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_DAHUA_XIYOU
/*
 *  坦克前线 OL
 *  可以匹配--- TCP端口 31013 暂时没有这么处理
 *  匹配client TCP请求的前几个字节
 * 
 * 
 */
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DAHUA_XIYOU

#include "ndpi_api.h"
#include <linux/types.h>

#define WZRY_ENSRUED1_MAX 3
#define WZRY_ENSRUED2_MAX 2
#define WZRY_UNSRUED1_MAX 24
#define WZRY_UNSRUED2_MAX 4





static void ndpi_search_dahua_xiyou(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

}


void init_dahua_xiyou_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("DaHuaXiYou", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DAHUA_XIYOU,
				      ndpi_search_dahua_xiyou,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
