
#ifndef TCPFLOWPARSE_H_
#define TCPFLOWPARSE_H_


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>


#ifdef HAVE_STANDARDS_H
# include <standards.h>
#endif


#ifdef HAVE_TCP_H
#include <tcp.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_SYS_BITYPES_H
# include<sys/bitypes.h>
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#ifndef __USE_BSD
#define __USE_BSD
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif

#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
# include <netinet/if_ether.h>
#endif

/* Linux libc5 systems have different names for certain structures.
 * Patch sent by Johnny Tevessen <j.tevessen@gmx.net> */
#if !defined(HAVE_NETINET_IF_ETHER_H) && defined(HAVE_LINUX_IF_ETHER_H)
# include <linux/if_ether.h>
# define ether_header ethhdr
# define ether_type h_proto
# define ETHERTYPE_IP ETH_P_IP
#endif

//#ifdef HAVE_SIGNAL_H
# include <signal.h>
//#endif


/****************** Ugly System Dependencies ******************************/

/* We always want to refer to RLIMIT_NOFILE, even if what you actually
 * have is RLIMIT_OFILE */
#ifdef RLIMIT_OFILE
# ifndef RLIMIT_NOFILE
#  define RLIMIT_NOFILE RLIMIT_OFILE
# endif
#endif

/* We always want to refer to OPEN_MAX, even if what you actually have
 * is FOPEN_MAX. */
#ifdef FOPEN_MAX
# ifndef OPEN_MAX
#  define OPEN_MAX FOPEN_MAX
# endif
#endif




#include <dirent.h>
#include <sys/param.h>
#include <unistd.h>
#include <sys/stat.h>


#include <libxml/parser.h>
#include <libxml/xpath.h>


#include <pcap.h>


#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "cups.h"


/*********************************************************************/
/*************** **数据协议,应用协议,主配置文件 start*********************/
/*********************************************************************/
#define MAX_FIELD_NUMBER 30
/*支持的最大application数量*/
#define MAX_APPS_NUMBER	100
/*支持的最大数据协议数量*/
#define MAX_DATAPROTO_NUMBER	100

/*定义application 信息的结构*/
typedef struct app{
	u_char *appname;

	u_char *base;
	u_char *ex;
	u_char *dataproPtr;   /*指向数据协议*/

	u_char *transMethod;
	u_char *output_tcp, *output_trans;	

	u_char *ports[MAX_FIELD_NUMBER];
	u_char *servers[MAX_FIELD_NUMBER];
	u_char *clients[MAX_FIELD_NUMBER];
};


/*定义 数据协议 信息的结构*/
typedef struct proto{
	u_char *name;
	u_char *get_fields[MAX_FIELD_NUMBER]; /*保存取哪些字段*/
	u_char *output_name[MAX_FIELD_NUMBER]; /*每个字段的含义*/
};


/*定义 主配置文件tcpFlowParse.xml 信息的结构*/
typedef struct tcpFlowParse{
	u_char *nic;
	u_char *pcap_path, *pcap_filename;
	u_char *filter;
	u_char *pcapstat;
	int timeinterval;
	u_char *loglevel;
	u_char *app_name[MAX_APPS_NUMBER];
};
/*********************************************************************/
/*************** **数据协议,应用协议,主配置文件 end*********************/
/*********************************************************************/



/*********************************************************************/
/************************日志部分start*********************/
/*********************************************************************/

//定义日志级别
#define LOG_LEVEL_ALL	0xff

#define LOG_LEVEL_ERROR	0x80
#define LOG_LEVEL_WARN	0x40
#define LOG_LEVEL_INFO	0x20
#define LOG_LEVEL_DEBUG	0x10


#define LOG_FORMAT  __FILE__,__LINE__,__func__

/*每个日志文件的最大大小为64MB*/
#define MAX_LOGFILE_SIZE	64*1024*1024


typedef struct logFile{
	char *filename;
	FILE *fp;
	long pos; /*保存文件的大小,文件最大为64*/
	int flags;  /*文件是否关闭*/
};


int  logFile_open(struct logFile *logFile , char *filename);
void logFile_write_message(struct logFile *logfile, int loglevel, char *filename, int line, char *func, char *fmt, ...);
void logFile_colse(struct logFile *logfile);


int  file_check_exist(const char *file);


int dir_create(const char *path);
int dir_check_exist(const char *path);
unsigned long get_file_size(const char *path) ; 



/*********************************************************************/
/************************日志部分end *********************/
/*********************************************************************/




/*********************************************************************/
/************************ 解析xml start *********************/
/*********************************************************************/

xmlDocPtr get_doc_from_memory(char *buffer, int size);//解析内存中xml格式的字符串,buffer必须以null结尾才能解析
xmlDocPtr get_doc_from_file (char *docname);//解析xml文件
xmlXPathObjectPtr get_node_set (xmlDocPtr doc, xmlChar *xpath);

int parse_tcpFlowParse(struct tcpFlowParse *maincfgPtr , char *filepath);
int parse_app(struct app *appptr , char *filepath);
int parse_proto(struct proto *protoptr , char *filepath);
void print_tcpFlowParse(struct tcpFlowParse * maincfgptr);
void print_app(struct app  *appptr);
void print_proto(struct proto *protoptr);
void free_tcpFlowParse(struct tcpFlowParse * maincfgptr);
void free_app(struct app *appptr);
void free_proto(struct proto *protoptr);

/*********************************************************************/
/************************ 解析xml end *********************/
/*********************************************************************/



/*********************************************************************/
/************************ 协议类型和协议传输方式 start *********************/
/*********************************************************************/


//transport protocol
typedef enum tcp_base{
	tcp   //transport layer protocol is tcp
};

typedef enum tcp_base tcp_base;

//middleware transport protocol
typedef enum tcp_ex{
	http, //transport transaction data by http protocol
	wmq,  //transport transaction data by middleware wmq of IBM
	wtc   //transport transaction data by middleware wtc of oracle
};

typedef enum tcp_ex tcp_ex;

//data protocol
typedef enum message_proto{
	xml,  //general data format
	cups, //unipay data format
	sop,  //cebbank private data format
	fdi   //cebbank credit card data format
};

typedef enum message_proto message_proto;

//transport method
typedef enum tcp_trans_method{
	asyn_long_single,
	asyn_long_full,
	syn_long,
	syn_short
};

typedef enum tcp_trans_method  tcp_trans_method;

/*********************************************************************/
/************************ 协议类型和协议传输方式 end *********************/
/*********************************************************************/



/*********************************************************************/
/************************ pcap 处理函数相关内容 start *********************/
/*********************************************************************/
#define SNAPLEN             65536 /* largest possible MTU we'll see */


/**************************** Structures **********************************/
typedef struct flow_t{
  u_int32_t src;		/* Source IP address */
  u_int32_t dst;		/* Destination IP address */
  u_int16_t sport;		/* Source port number */
  u_int16_t dport;		/* Destination port number */
} ;

typedef struct flow_t flow_t;


/* datalink.c */
pcap_handler find_handler(int datalink_type, char *device);

/* tcpip.c */
void process_ip(const u_char *data, u_int32_t length, struct pcap_pkthdr *pkthdr);
void process_tcp(const u_char *data, u_int32_t length, u_int32_t src,
		 u_int32_t dst, struct pcap_pkthdr *pkthdr);
void print_packet(flow_t flow, const u_char *data, u_int32_t length, struct pcap_pkthdr *pkthdr);
void store_packet(flow_t flow, const u_char *data, u_int32_t length,
		  u_int32_t seq, u_int32_t ack, struct pcap_pkthdr *pkthdr);

u_char *do_strip_nonprint(const u_char *data, u_int32_t length);
void flow_filename(flow_t flow, char *output);
int flow_app(flow_t *flow, struct app *app);
int flow_find_ip(flow_t *flow, struct app *app);
int flow_find_port(flow_t *flow, struct app *app);
/*********************************************************************/
/************************ pcap 处理函数相关内容 end *********************/
/*********************************************************************/


/*********************************************************************/
/************************ 会话 和交易 统计 start *********************/
/*********************************************************************/


#define MAX_TCP_FLOW_NUMBER	100


//计算针对目标端口
typedef struct tcp_connect_info{
	int active_connect; //活动连接数
	int new_connect;    //新建连接数
	int terminate_connect; //终止连接数
	int reset_connect;   //重置连接数
};


//计算针对tcp flow统计
typedef struct tcp_statistics{

	int rec_packets;
	int send_packets;
	int total_packets;

	long rec_bytes;
	long send_bytes;
	long total_bytes;

	int retrans_number; //重传数

	int avg_network;   //时间单位都是毫秒
	int avg_server;
	int avg_response;
	int max_network;
	int max_server;
	int max_response;
	int min_network;
	int min_server;
	int min_response;
};


//计算针对每一种 交易统计
typedef struct trans_statistics{

	long total_trans;      //总的交易数
	long success_trans;   //成功交易数
	long fail_trans;      //失败交易数 
	long slow_trans;
	double fail_percent; //失败比例

	int avg_response;  //平均响应时间
	int avg_server;     //平均服务时间
	int avg_network;    //平均网络时间

	int max_response;
	int max_server;
	int max_network;

	int min_response;
	int min_server;
	int min_network;

};


typedef struct tcp_statistics tcp_stat;
typedef struct trans_statistics trans_stat;

/* TCP flags */
#define TH_FIN  0x0001
#define TH_SYN  0x0002
#define TH_RST  0x0004
#define TH_PUSH 0x0008
#define TH_ACK  0x0010
#define TH_URG  0x0020
#define TH_ECN  0x0040
#define TH_CWR  0x0080
#define TH_NS   0x0100
#define TH_RES  0x0E00 /* 3 reserved bits */
#define TH_MASK 0x0FFF


//银联交易信息
typedef struct cups_key_info{
	struct pcap_pkthdr pkthdr; //记录包时间
	tcp_seq seq;   //记录seq序列号
	int data_len;  //数据长度
	flow_t flow;   //ip,port
	struct cups cupInfo; //交易信息
};

/*********************************************************************/
/************************ 会话 和交易 统计 end *********************/
/*********************************************************************/

/*********************************************************************/
/************************ 单链表开始 *********************/
/*********************************************************************/

typedef struct cups_key_info LElemType;
typedef int Status;
/* 单链表的链式存储结构 */
typedef struct LNode
{
  LElemType data;
  struct LNode *next;
}LNode,*LinkList;
 

/* 单链表的基本操作(9个) */
int InitList(LinkList *list);
void DestroyList(LinkList *list);
void ClearList(LinkList *list);
Status ListEmpty(LinkList list);
int ListLength(LinkList list);
int ListInsert(LinkList *list,LElemType *e);
Status ListDel(LinkList *list,LinkList p);
void ListTraverse(LinkList list,void(*vi)(LElemType));
LinkList ListFind(LinkList list, LElemType *e);


/*********************************************************************/
/************************ 单链表结束 *********************/
/*********************************************************************/


void *check_malloc(size_t size);
int get_max_fds(void);
void elsptime(struct timeval req, struct timeval resp, char *aa);

typedef  int RETSIGTYPE;
RETSIGTYPE (*portable_signal(int signo, RETSIGTYPE (*func)(int)))(int);

/*********************************************************************/
/************************ 定义常用函数 end *********************/
/*********************************************************************/

#define MAX_FD_GUESS        64
#define PROGRAM_NAME   "tcpFlowParse"

#endif /* TCPFLOWPARSE_H_ */

