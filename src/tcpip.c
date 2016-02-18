
#include "tcpFlowParse.h"
#include "cups.h"

extern struct logFile mylog;  //定义全局日志变量
extern long total_packet ;
extern long total_bytes;
extern struct proto protos[MAX_DATAPROTO_NUMBER];
extern struct app apps[MAX_APPS_NUMBER];
extern LinkList list1, list2;
extern struct logFile cupslog;


/* This is called when we receive an IP datagram.  We make sure that
 * it's valid and contains a TCP segment; if so, we pass it to
 * process_tcp() for further processing.
 *
 * Note: we currently don't know how to handle IP fragments. */
void process_ip(const u_char *data, u_int32_t caplen, struct pcap_pkthdr *pkthdr)
{
  const struct ip *ip_header = (struct ip *) data;
  u_int ip_header_len;
  u_int ip_total_len;

  /* make sure that the packet is at least as long as the min IP header */
  if (caplen < sizeof(struct ip)) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT, "%s", "received truncated IP datagram!");
    //return;
  }

  /* for now we're only looking for TCP; throw away everything else */
  if (ip_header->ip_p != IPPROTO_TCP) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT, "got non-TCP frame -- IP proto %d", ip_header->ip_p);
    //return;
  }

  /* check and see if we got everything.  NOTE: we must use
   * ip_total_len after this, because we may have captured bytes
   * beyond the end of the packet (e.g. ethernet padding). */
  ip_total_len = ntohs(ip_header->ip_len);
  if (caplen < ip_total_len) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT, "warning: captured only %ld bytes of %ld-byte IP datagram",
	 (long) caplen, (long) ip_total_len);
  }

  /* XXX - throw away everything but fragment 0; this version doesn't
   * know how to do fragment reassembly. */
  if (ntohs(ip_header->ip_off) & 0x1fff) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT, "%s", "warning: throwing away IP fragment from X to X");
    //return;
  }

  /* figure out where the IP header ends */
  ip_header_len = ip_header->ip_hl * 4;

  /* make sure there's some data */
  if (ip_header_len > ip_total_len) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT, "%s","received truncated IP datagram!");
    //return;
  }

  /* do TCP processing */
  process_tcp(data + ip_header_len, ip_total_len - ip_header_len,
	      ntohl(ip_header->ip_src.s_addr),
	      ntohl(ip_header->ip_dst.s_addr), pkthdr);
}


void process_tcp(const u_char *data, u_int32_t length, u_int32_t src,
		 u_int32_t dst, struct pcap_pkthdr *pkthdr)
{
  struct tcphdr *tcp_header = (struct tcphdr *) data;
  flow_t this_flow;
  u_int tcp_header_len;
  tcp_seq seq, ack;
  u_char  th_flags;

  if (length < sizeof(struct tcphdr)) {
    logFile_write_message(&mylog, LOG_LEVEL_WARN, LOG_FORMAT, "%s","received truncated TCP segment!");
    //return;
  }

  /* calculate the total length of the TCP header including options */
  tcp_header_len = tcp_header->th_off * 4;

  /* return if this packet doesn't have any data (e.g., just an ACK) */

  /*
  if (length <= tcp_header_len) {
    DEBUG(50) ("got TCP segment with no data");
    return;
  }
  */


  /* fill in the flow_t structure with info that identifies this flow */
  this_flow.src = src;
  this_flow.dst = dst;
  this_flow.sport = ntohs(tcp_header->th_sport);
  this_flow.dport = ntohs(tcp_header->th_dport);
  seq = ntohl(tcp_header->th_seq);
  ack = ntohl(tcp_header->th_ack);


  if( flow_app(&this_flow, &apps[0]) == -1 )
      return ;


  total_bytes += pkthdr->caplen;
  total_packet++;

  th_flags = tcp_header->th_flags;
  /* recalculate the beginning of data and its length, moving past the
   * TCP header */
  data += tcp_header_len;
  length -= tcp_header_len;

  /* strip nonprintable characters if necessary */
  //if (strip_nonprint)
  //data = do_strip_nonprint(data, length);

  /* store or print the output */
  //if (console_only) {
  //  print_packet(this_flow, data, length, pkthdr);
  //} else {
    store_packet(this_flow, data, length, seq, ack , pkthdr);
  //}
}


/* convert all non-printable characters to '.' (period).  not
 * thread-safe, obviously, but neither is most of the rest of this. */
u_char *do_strip_nonprint(const u_char *data, u_int32_t length)
{
  static u_char buf[SNAPLEN];
  u_char *write_ptr;

  write_ptr = buf;
  while (length) {
    if (isprint(*data) || (*data == '\n') || (*data == '\r'))
      *write_ptr = *data;
    else
      *write_ptr = '.';
    write_ptr++;
    data++;
    length--;
  }

  return buf;
}


/* print the contents of this packet to the console */
void store_packet(flow_t flow, const u_char *data, u_int32_t length,
      u_int32_t seq, u_int32_t ack, struct pcap_pkthdr *pkthdr)
{
   char buff[128];
   char output[64];
   struct tm *tp;
   flow_filename(flow, output);
   tp = localtime(&pkthdr->ts.tv_sec);
   sprintf(buff, "number[%d] %s: \narrival time is %.04d%.02d%.02d %.02d:%.02d:%.02d.%.06u, caplen=%d, len=%d\n", total_packet,
      output,
		  tp->tm_year+1900, tp->tm_mon+1,
 		  tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec,
 		  pkthdr->ts.tv_usec, pkthdr->caplen, pkthdr->len);

   if (fwrite(buff, strlen(buff), 1, mylog.fp) != 1) {
     /* sigh... this should be a nice, plain DEBUG statement that
      * passes strerrror() as an argument, but SunOS 4.1.3 doesn't seem
      * to have strerror. */
       logFile_write_message(&mylog, LOG_LEVEL_ERROR, LOG_FORMAT,  "write to %s failed(wirte tcp flow header): ", output);
      // perror("");
   }


  if(length >0){

        u_char buff[1024];
        sprintf(buff, "seq=%u, data_len=%u", seq, length);
        logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "%s", buff);


        struct cups mycups;
        parse_cups(&mycups, data + 4, length);//前四个字节表示cups报文长度,这里移动4个字节
        output_cups(&mycups, buff);
        logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "%s", buff);

        LElemType e;
        memcpy(&e.pkthdr, pkthdr, sizeof(struct pcap_pkthdr));
        e.seq = seq;
        e.data_len = length;
        memcpy(&e.flow, &flow, sizeof(flow_t));
        memcpy(&e.cupInfo, &mycups, sizeof(struct cups) );

        char tmp[2] = {0x00, 0x00};
        //判断是请求
        if( memcmp(mycups.masterfields.resCode, tmp, 2)  == 0){

            logFile_write_message(&mylog, LOG_LEVEL_ERROR, LOG_FORMAT,  "插入请求报文");
            if(ListEmpty(list1) == -1){//列表为空
              ListInsert(&list1, &e);
            }else{
              LinkList p = NULL;
              p = list1->next;
              if( p->data.seq + p->data.data_len <= seq){ //认为是不重复的报文
                  ListInsert(&list1, &e);
              }
            }
        }else{//是响应
            LinkList p = NULL;
            p = ListFind(list1, &e);
            if(p == NULL){//没有找到请求
                logFile_write_message(&mylog, LOG_LEVEL_ERROR, LOG_FORMAT,  "是响应报文  没找到请求报文");
            }else{//找到
                char aa[64];
                elsptime(p->data.pkthdr.ts, e.pkthdr.ts, aa);
                //输出响应时间
                logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "响应时间是:%s", aa);
                
                u_char buf[2048];

                memset(buf, 0x00, sizeof(buf));
                if( memcpy(mycups.header.desID, "0001000", 8) == 0){
                  strcat(buf, "|dir:00"); //00:他代本
                }else{
                  strcat(buf, "|dir:ff"); //ff:本代他
                }

                char ip[100];
                sprintf(ip, "|clientIP:%d.%d.%d.%d", (u_int8_t) ((flow.src & 0xff000000) >> 24),
                        (u_int8_t) ((flow.src & 0x00ff0000) >> 16),
                         (u_int8_t) ((flow.src & 0x0000ff00) >> 8),
                          (u_int8_t)  (flow.src & 0x000000ff));

                strcat(buf, ip);

               sprintf(ip, "|serverIP:%d.%d.%d.%d",     (u_int8_t) ((flow.dst & 0xff000000) >> 24),
                    (u_int8_t) ((flow.dst & 0x00ff0000) >> 16),
                    (u_int8_t) ((flow.dst & 0x0000ff00) >> 8),
                    (u_int8_t)  (flow.dst & 0x000000ff));

                strcat(buf, ip);

                char tmp[3];
                memcpy(tmp, mycups.masterfields.processCode, 2);
                tmp[2] = '\0';

               // sprintf(ip, "|transType:%s-%s", tmp, convert_trans_type( atoi(tmp) ) );
                sprintf(ip, "|transType:%s", tmp);

                strcat(buf, ip);


              // sprintf(ip, "|retCode:%.*s-%s", 2, mycups.masterfields.resCode, convert_rescode(mycups.masterfields.resCode) );
               sprintf(ip, "|retCode:%.*s", 2, mycups.masterfields.resCode);
               strcat(buf, ip);

               sprintf(ip, "|respTime:%s", aa);
               strcat(buf, ip);


               sprintf(ip, "|cardNo:%.*s", 21, mycups.masterfields.PAN);
               strcat(buf, ip);


               sprintf(ip, "|tranTime:%.*s", 10, mycups.masterfields.transmissionTime);
               strcat(buf, ip);

               sprintf(ip, "|detail:");
               strcat(buf, ip);

               logFile_write_message(&cupslog, LOG_LEVEL_ALL, LOG_FORMAT,  "%s", buf);

                ListDel(&list1, p);
            }
        }
  }
#if 0
  if ( (length >0) &&fwrite(data, length, 1, mylog.fp) != 1) {
    /* sigh... this should be a nice, plain DEBUG statement that
     * passes strerrror() as an argument, but SunOS 4.1.3 doesn't seem
     * to have strerror. */
      logFile_write_message(&mylog, LOG_LEVEL_ERROR, LOG_FORMAT, "write to %s failed(wirte tcp flow content): ", output);
    }
#endif    
}
