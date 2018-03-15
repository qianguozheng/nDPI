#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_JDQS_GZ
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_JDQS_GZ

#include "ndpi_api.h"
#include <linux/types.h>

/*
 *  主要是UDP协议， 但是内容不定，但是4-6个数据包的长度是一样的。 主要通信数据流
 *  另外，还有一些tcp的协议，可能是商店的相关信息。
 */
#define WZRY_ENSRUED1_MAX 3
#define WZRY_ENSRUED2_MAX 2
#define WZRY_UNSRUED1_MAX 24
#define WZRY_UNSRUED2_MAX 4

#define PAYLOAD_LEN 25

static void ndpi_search_jdqs_gz_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	__be32 plen = 0;
	uint32_t ulen = 0;
	__be16 pslen = 0;
	uint16_t uslen = 0;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	
	if (packet->payload_packet_len < 8 ) return;

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_JDQS_GZ) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_JDQS_GZ)) {
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->tcp) {
			printk(KERN_INFO"ndpi: detect WZRY PVP 04 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
		}
	#endif
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		return;
	}	
	
	if (buff[0] == 0x33 && buff[1] == 0x66 && buff[2] == 0x00 && buff[3] == 0x0a && buff[4] == 0x00 && buff[5] == 0x0a) {
		flow->common.ensured_pkts ++;
		//printf("33 66 00 0a 00 0a\n");
		if (flow->common.ensured_pkts >= WZRY_ENSRUED1_MAX) {
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->tcp) {
				printk(KERN_INFO"ndpi: detect WZRY PVP 01 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
			}
		#endif
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		}
		
		return;
	}
	//match first packet
	if (buff[0] == 0x50 && buff[1] == 0x0a && buff[2] == 0x00 && buff[3] == 0x00 && buff[4] == 0x00 && buff[5] == 0x01 && buff[9] == 0x91) {
		//printf("0x50 0x0a 00 00 00 01\n");
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	
	if ((buff[0] == 0x43 && buff[1] == 0x66 && buff[2] == 0xaa && buff[3] == 0x00 && buff[4] == 0x00 && buff[5] == 0x00 && buff[7] == 0x15) //client
	|| (buff[0] == 0xaa && buff[1] == 0x00 && buff[2] == 0x00 && buff[3] == 0x00 && buff[5] == 0x15 && buff[6] == 0x00 && buff[7] == 0x00)) { //server
		//printf("ensured pkts %d\n", flow->common.ensured_pkts);
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts >= WZRY_ENSRUED1_MAX) {
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->tcp) {
				printk(KERN_INFO"ndpi: detect WZRY PVP 01 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
			}
		#endif
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		}
		
		return;
	}
	
	
	if (buff[0] == 0x01 && buff[1] == 0x00 && buff[2] == 0x00  /*&& buff[10] == 0xaa && buff[11] == 0x62 && buff[12] == 0x80*/) {
		//printf("0x01 00 00 \n");
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	
	#if 0 //jdqs.pcap jdqs1.pcap 没有类似的包
	if (buff[0] == 0xc2 && buff[1] == 0xfe && buff[2] == 0x00 && buff[3] == 0x05 && buff[4] == 0x00 && buff[5] == 0x00 && buff[8] == 0xfa) {
		//printf("ensure pkts %d, port=%d\n", flow->common.ensured_pkts, ntohs(packet->tcp->dest));
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts >= WZRY_ENSRUED1_MAX) {
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->tcp) {
				printk(KERN_INFO"ndpi: detect WZRY PVP 01 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
			}
		#endif
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		}
		
		return;
	}
	#endif
	
	/////For 天美工作室
	if (buff[0] == 0x01 && buff[1] == 0x00 && buff[2] == 0x00  && 
		buff[10] == 0x9c && buff[11] == 0x8d && buff[12] == 0x4c && buff[13] == 0x42) {
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	

	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < WZRY_UNSRUED2_MAX) return;
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_JDQS_GZ);
}

static void ndpi_search_jdqs_gz_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	if (packet->payload_packet_len < 10 ) return;
	
	//One udp session
	if (buff[0] == 0x28 && buff[1] == 0x28 && buff[3] == 0x00 
	 && buff[5] == 0x08 && buff[8] == 0x01 && buff[9] == 0x18) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts < WZRY_ENSRUED1_MAX)  return;
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->udp) {
			printk(KERN_INFO"ndpi: detect JDQS_GZ UDP 01 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->udp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->udp->dest));
		}
	#endif
		return;
	}
	
	if (25 == packet->payload_packet_len) {
		flow->common.session_stage ++; // 连续 4 个25字节的包
	} else if (23 == packet->payload_packet_len &&  flow->common.session_stage >= 4) {
		flow->common.session_stage ++; //连续2个23字节的包
	//} else if (6 == packet->payload_packet_len && flow->common.session_stage == 6) {
	//	flow->common.session_stage ++; //1个 6字节
	} else if (210 == packet->payload_packet_len && flow->common.session_stage == 6){
		flow->common.session_stage ++; //1个 210字节
	} else if (flow->common.session_stage < 0x10){ //下面会用这个变量
		flow->common.session_stage = 0;
	}
	
	if (7 == flow->common.session_stage) {
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	
	/////For 天美工作室
	if (buff[0] == 0x28 && buff[1] == 0x28 && buff[3] == 0x00 
	 && buff[5] == 0x08 && buff[8] == 0x01 && buff[9] == 0x18) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts < WZRY_ENSRUED1_MAX)  return;
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->udp) {
			printk(KERN_INFO"ndpi: detect JDQS_GZ UDP 01 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->udp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->udp->dest));
		}
	#endif
		return;
	}
	
	if (buff[0] == 0x75 && buff[1] == 0x75 && buff[8] == 0x00 && buff[9] == 0xde) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts < WZRY_ENSRUED1_MAX)  return;
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	// only report
	if (buff[0] == 0x13 && buff[1] == 0xce && buff[2] == 0x00 && buff[3] == 0x04) {
		flow->common.ensured_pkts ++;
		if (flow->common.ensured_pkts < WZRY_ENSRUED1_MAX)  return;
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	
#if 1
	if (33 == packet->payload_packet_len) {
		if (buff[0] == 0x01 && buff[1] == 0x00 && buff[2] == 0x00 && buff[3] == 0x00
		 && buff[4] == 0x00 && buff[32] == 0x08) {
			flow->common.session_stage = 0x11;
		} else if (0x11 <= flow->common.session_stage) {
			//总共 4个33长度的数据报文
			flow->common.session_stage ++;
		}
		
		if (0x14 <= flow->common.session_stage) {
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
			return;
		}
	}
#endif

	if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_JDQS_GZ) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_JDQS_GZ)) {
	#ifdef TEST_MT_ENTRY
		if (packet->iph && packet->udp) {
			printk(KERN_INFO"ndpi: detect JDQS UDP 02 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->udp->source), 
				(u8 *)&packet->iph->daddr, ntohs(packet->udp->dest));
		}
	#endif
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_JDQS_GZ, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	
	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < WZRY_UNSRUED1_MAX) return;
	// If more than 24 packets have not recognized the application protocol, then ignore it
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_JDQS_GZ);
}

static void ndpi_search_jdqs_gz(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->udp != NULL) {
		ndpi_search_jdqs_gz_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		ndpi_search_jdqs_gz_tcp(ndpi_struct, flow);
	}
}


void init_jdqs_gz_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("JDQS_GZ", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_JDQS_GZ,
				      ndpi_search_jdqs_gz,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
