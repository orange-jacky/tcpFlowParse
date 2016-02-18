
#include "tcpFlowParse.h"


extern struct logFile mylog;  //定义全局日志变量

/* The DLT_NULL packet header is 4 bytes long. It contains a network
 * order 32 bit integer that specifies the family, e.g. AF_INET.
 * DLT_NULL is used by the localhost interface. */
#define	NULL_HDRLEN 4

//处理回环网卡流量,也就是处理ip为127.0.0.1的流量
void dl_null(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  u_int caplen = h->caplen;
  u_int length = h->len;
  u_int family;

  if (length != caplen) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT,  "warning: only captured %d bytes of %d byte null frame",
	  caplen, length);
  }

  if (caplen < NULL_HDRLEN) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT, "%s", "warning: received incomplete null frame");
    //return;
  }

  /* One of the symptoms of a broken DLT_NULL is that this value is
   * not set correctly, so we don't check for it -- instead, just
   * assume everything is IP.  --JE 20 April 1999*/
#ifdef DLT_NULL_BROKEN
  /* make sure this is AF_INET */
  memcpy((char *)&family, (char *)p, sizeof(family));
  family = ntohl(family);
  if (family != AF_INET) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT,  "warning: received non-AF_INET null frame (type %d)", family);
    //return;
  }
#endif

  process_ip(p + NULL_HDRLEN, caplen - NULL_HDRLEN, h);
}



/* Ethernet datalink handler; used by all 10 and 100 mbit/sec
 * ethernet.  We are given the entire ethernet header so we check to
 * make sure it's marked as being IP. */
//处理以太网网卡协议(Ethernet网卡),能够处理10Mbps, 100Mbps, 1000Mpbs, 或者更大Mbps
//能够处理在tcp/ip 协议中包含vlan协议的数据 
void dl_ethernet(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  u_int caplen = h->caplen;
  u_int length = h->len;
  struct ether_header *eth_header = (struct ether_header *) p;
  unsigned short type;
  u_int len;
  u_char *start;

  //total_bytes += caplen;
  //total_packet++;

  if (length != caplen) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT,  "warning: only captured %d bytes of %d byte ether frame",
	  caplen, length);
  }


  if (caplen < sizeof(struct ether_header)) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT, "%s", "warning: received incomplete ethernet frame");
    //return;
  }

  struct vlan_hdr {
            unsigned short  h_vlan_TCI;
            unsigned short  h_vlan_encapsulated_proto;
   };
    

  /*处理802.1Q vlan*/
  if (ntohs(eth_header->ether_type) == 0x8100) {
      // logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "%s", "_ip_vlan");
	     struct vlan_hdr *vlan_header = (struct vlan_hdr *)(p + sizeof(struct ether_header));

	     if(ntohs(vlan_header->h_vlan_encapsulated_proto) == ETHERTYPE_IP){
		         process_ip(p + sizeof(struct ether_header) + sizeof(struct vlan_hdr),
		   			          caplen - sizeof(struct ether_header) - sizeof(struct vlan_hdr), h);
	     }
  }else if(ntohs(eth_header->ether_type) == ETHERTYPE_IP){
      //  logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "%s", "_ip_only");
	       process_ip(p + sizeof(struct ether_header),
	   			       caplen - sizeof(struct ether_header), h);
  }else{
	  logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT,  "warning: received ethernet type is not ip protocol, the type is %x", ntohs(eth_header->ether_type));
		  //return;
  }
}


/* The DLT_PPP packet header is 4 bytes long.  We just move past it
 * without parsing it.  It is used for PPP on some OSs (DLT_RAW is
 * used by others; see below) */
#define	PPP_HDRLEN 4

void dl_ppp(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  u_int caplen = h->caplen;
  u_int length = h->len;

  if (length != caplen) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT,  "warning: only captured %d bytes of %d byte PPP frame",
	  caplen, length);
  }

  if (caplen < PPP_HDRLEN) {
   logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT,  "%s",  "warning: received incomplete PPP frame");
    //return;
  }

  process_ip(p + PPP_HDRLEN, caplen - PPP_HDRLEN, h);
}


/* DLT_RAW: just a raw IP packet, no encapsulation or link-layer
 * headers.  Used for PPP connections under some OSs including Linux
 * and IRIX. */
//处理原生ip数据包 
void dl_raw(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  u_int caplen = h->caplen;
  u_int length = h->len;

  if (length != caplen) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT,  "warning: only captured %d bytes of %d byte raw frame",
	  caplen, length);
  }

  process_ip(p, caplen, h);
}




//虚构的一种数据链层头
#define SLL_HDR_LEN       16
int i = 0;
void dl_linux_sll(u_char *user, const struct pcap_pkthdr *h, const u_char *p){


  u_int caplen = h->caplen;
  u_int length = h->len;

  if (length != caplen) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT,  "warning: only captured %d bytes of %d byte Linux cooked frame",
	      caplen, length);
  }

  if (caplen < SLL_HDR_LEN) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT, "%s", "warning: received incomplete Linux cooked frame");
    //return;
  }

  process_ip(p + SLL_HDR_LEN, caplen - SLL_HDR_LEN, h);
}


pcap_handler find_handler(int datalink_type, char *device)
{
  int i;
  struct {
    pcap_handler handler;
    int type;
  } handlers[] = {
    { dl_null, DLT_NULL },
#ifdef DLT_RAW /* older versions of libpcap do not have DLT_RAW */
    { dl_raw, DLT_RAW },
#endif
    { dl_ethernet, DLT_EN10MB },
    { dl_ethernet, DLT_IEEE802 },
    { dl_ppp, DLT_PPP },
#ifdef DLT_LINUX_SLL
    { dl_linux_sll, DLT_LINUX_SLL },
#endif
    { NULL, 0 },
  };

  logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "looking for handler for datalink type %d for interface %s",
	datalink_type, device);

  for (i = 0; handlers[i].handler != NULL; i++)
    if (handlers[i].type == datalink_type)
      return handlers[i].handler;

  logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "sorry - unknown datalink type %d on interface %s", datalink_type,
      device);
  /* NOTREACHED */
  return NULL;
}