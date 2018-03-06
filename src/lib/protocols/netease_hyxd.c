#include "ndpi_protocol_ids.h"

#ifdef NDPI_PROTOCOL_HYXD

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_HYXD

#include "ndpi_api.h"

#define HYXD_UNSRUED2_MAX 16
#define HYXD_ENSRUED1_MAX 2

#define HYXD_UNSRUED1_MAX 24

#if 0
/* flow tracking */
struct osdpi_flow_node_clone {
	struct rb_node node;
	struct kref refcnt;
	struct nf_conn * ct;
	spinlock_t	lock;
	u_int64_t ndpi_timeout;  // detection timeout - detection 30s / connection 180s
	/* mark if done detecting flow proto - no more tries */
	u8 detection_completed;
	/* result only, not used for flow identification */
	ndpi_protocol detected_protocol;
	/* last pointer assigned at run time */
	struct ndpi_flow_struct *ndpi_flow;
};

/* id tracking */
struct osdpi_id_node_clone {
	struct rb_node node;
	struct kref refcnt;
	union nf_inet_addr ip;
	/* last pointer assigned at run time */
	struct ndpi_id_struct *ndpi_id;
};
#endif

static void ndpi_search_hyxd_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	const u_int8_t *buff = packet->payload;
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;
	if (packet->payload_packet_len <= 0 ) return;

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
			if (flow->common.ensured_pkts < HYXD_ENSRUED1_MAX)  return;
			
		#ifdef TEST_MT_ENTRY
			if (packet->iph && packet->udp) {
				printk(KERN_INFO"ndpi: detect HYXD 01 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->udp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->udp->dest));
			}
		#endif			
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HYXD, NDPI_PROTOCOL_UNKNOWN);
			return;
		}

		if ((flow->common.session_stage + 1) == buff[0]) {
			flow->common.session_stage ++;
			
		#if 0
			if (packet->iph && packet->udp) {
				printk(KERN_INFO"ndpi: detect HYXD 03 prev (%pI4:%u -- %pI4:%u),%p,%p, src=0x%08x, dst=0x%08x, flow=%p\n", 
					(u8 *)&packet->iph->saddr, ntohs(packet->udp->source), 
					(u8 *)&packet->iph->daddr, ntohs(packet->udp->dest), src, dst, 
					src?src->detected_protocol_bitmask.fds_bits[6]:0xffffffff, 
					dst?dst->detected_protocol_bitmask.fds_bits[6]:0xffffffff, flow);

				struct osdpi_flow_node_clone *fnode = (struct osdpi_flow_node_clone *)((char*)flow - sizeof(struct osdpi_flow_node_clone));
				struct nf_conn * ct = fnode->ct;
				union nf_inet_addr *ipsrc, *ipdst;
				ipsrc = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
				ipdst = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;
				printk(KERN_INFO"ndpi:HYXD 03 for ct ipsrc=0x%08x%08x%08x%08x, ipdst=0x%08x%08x%08x%08x\n", 
					ipsrc->all[0], ipsrc->all[1], ipsrc->all[2], ipsrc->all[3], 
					ipdst->all[0], ipdst->all[1], ipdst->all[2], ipdst->all[3]);

				struct osdpi_id_node_clone *srcnode, *dstnode;
				srcnode = (struct osdpi_id_node_clone *)((char *)(flow->src) - sizeof(struct osdpi_id_node_clone));
				dstnode = (struct osdpi_id_node_clone *)((char *)(flow->dst) - sizeof(struct osdpi_id_node_clone));
				printk(KERN_INFO"ndpi:HYXD 03 for src dst src=0x%08x%08x%08x%08x, dst=0x%08x%08x%08x%08x\n\n", 
					srcnode->ip.all[0], srcnode->ip.all[1], srcnode->ip.all[2], srcnode->ip.all[3], 
					dstnode->ip.all[0], dstnode->ip.all[1], dstnode->ip.all[2], dstnode->ip.all[3]);
			}
		#endif
			
			if (NDPI_SRC_HAS_PROTOCOL(src, NDPI_PROTOCOL_HYXD) && NDPI_DST_HAS_PROTOCOL(dst, NDPI_PROTOCOL_HYXD)) {
			#ifdef TEST_MT_ENTRY
				if (packet->iph && packet->udp) {
					printk(KERN_INFO"ndpi: detect HYXD 03 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->udp->source), 
						(u8 *)&packet->iph->daddr, ntohs(packet->udp->dest));
				}
			#endif
				ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HYXD, NDPI_PROTOCOL_UNKNOWN);
			}
			return;
		}
	}

	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < HYXD_UNSRUED1_MAX) return;
	// If more than 16 packets have not recognized the application protocol, then ignore it
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HYXD);
}

static void ndpi_search_hyxd_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
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
				if (flow->common.ensured_pkts < HYXD_ENSRUED1_MAX)  return;

			#ifdef TEST_MT_ENTRY
				if (packet->iph && packet->tcp) {
					printk(KERN_INFO"ndpi: detect HYXD 02 (%pI4:%u -- %pI4:%u)\n", (u8 *)&packet->iph->saddr, ntohs(packet->tcp->source), 
						(u8 *)&packet->iph->daddr, ntohs(packet->tcp->dest));
				}
			#endif
				ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HYXD, NDPI_PROTOCOL_UNKNOWN);
			#ifdef TEST_MT_ENTRY
				printk(KERN_INFO"ndpi: HYXD 02 %p,%p, src=0x%08x, dst=0x%08x\n", flow->src, flow->dst, 
					flow->src?flow->src->detected_protocol_bitmask.fds_bits[6]:0xffffffff, 
					flow->dst?flow->dst->detected_protocol_bitmask.fds_bits[6]:0xffffffff);
				struct osdpi_flow_node_clone *fnode = (struct osdpi_flow_node_clone *)((char*)flow - sizeof(struct osdpi_flow_node_clone));
				struct nf_conn * ct = fnode->ct;
				union nf_inet_addr *ipsrc, *ipdst;
				ipsrc = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
				ipdst = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;
				printk(KERN_INFO"ndpi:HYXD 02 for ct ipsrc=0x%08x%08x%08x%08x, ipdst=0x%08x%08x%08x%08x\n", 
					ipsrc->all[0], ipsrc->all[1], ipsrc->all[2], ipsrc->all[3], 
					ipdst->all[0], ipdst->all[1], ipdst->all[2], ipdst->all[3]);

				struct osdpi_id_node_clone *srcnode, *dstnode;
				srcnode = (struct osdpi_id_node_clone *)((char *)(flow->src) - sizeof(struct osdpi_id_node_clone));
				dstnode = (struct osdpi_id_node_clone *)((char *)(flow->dst) - sizeof(struct osdpi_id_node_clone));
				printk(KERN_INFO"ndpi:HYXD 02 for src dst src=0x%08x%08x%08x%08x, dst=0x%08x%08x%08x%08x\n\n", 
					srcnode->ip.all[0], srcnode->ip.all[1], srcnode->ip.all[2], srcnode->ip.all[3], 
					dstnode->ip.all[0], dstnode->ip.all[1], dstnode->ip.all[2], dstnode->ip.all[3]);
			#endif
				return;
			}
		}
	}
	
	flow->common.unsured_pkts ++;
	if (flow->common.unsured_pkts < HYXD_UNSRUED2_MAX) return;
	// If more than 16 packets have not recognized the application protocol, then ignore it
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HYXD);
}


static void ndpi_search_hyxd(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	if (packet->udp != NULL) {
		ndpi_search_hyxd_udp(ndpi_struct, flow);
	} else if (packet->tcp != NULL) {
		ndpi_search_hyxd_tcp(ndpi_struct, flow);
	}
}

void init_hyxd_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("HYXD", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HYXD,
				      ndpi_search_hyxd,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
