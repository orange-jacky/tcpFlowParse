/*
 * cups.h
 *
 *  Created on: 2015年4月17日
 *      Author: fredlee
 */

#ifndef CUPS_H_
#define CUPS_H_

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>

/*判断cups位图的是否置位*/
#define TIBMAP_IS_SET(b,i)  ((b)[((i)/8)] & (0x80 >> ((i)%8)))

//cups2.0, define cups message header
typedef struct cups_header{
	u_char headLen;//1Byte       /*field1 头长度 */        /*8位二进制数 此值必须是0x2e,十进制值是46*/
	u_char headVer;//1Byte       /*field2 头标识和版本号*/  /*8位二进制数*/
	u_char cupsLen[4];//4Byte    /*field3 整个报文长度*/    /*4位定长数字字符,必须大于46,小于等于1846*/
	u_char desID[11];//11Byte    /*field4 目的ID*/         /*11位定长数字字符,不足11为后补空格*/
	u_char srcID[11];//11Byte	 /*field5 源ID*/		 	  /*11位定长数字字符,不足11为后补空格*/
	u_char reserved[3];//3Byte	 /*field6 保留使用*/       /*24位二进制数,入网机构请求,这个值必须为0*/
	u_char batchNum;//1Byte 	 /*field7 批次号*/         /*8位二进制数*/
	u_char transInfor[8];//8Byte /*field8 交易信息*/		  /*8位字母,数字和特殊字符;*/
	u_char userInfor;//1Byte 	 /*field9 用户信息*/       /*8位二进制*/
	u_char rejectCode[5];//5Byte /*field10 拒绝码*/        /*5位定长数字字符*/
};/*共46个字节,所有字段都为必填*/

//cups2.0 define cups message fields1
//from field2 to field64, have no field1
//报文中大域1的 关键信息域--7,11,32,33的组合能够唯一标识一笔交易
//报文中大域1的 关键信息域--39标识交易是否成功
typedef struct cups_masterfields{
	u_char PAN[21];        //21bytes   /*field2 主账号*/
	u_char processCode[6]; //6bytes    /*field3 交易类型*/
	u_char transmissionTime[10];  //10bytes   /*field7 交易传输时间*/
	u_char systemTraceNumber[6]; //6bytes     /*field11 系统跟踪号*/
	u_char acquireInstID[13]; //13bytes       /*field32 受理机构标志码*/
	u_char forwardInstID[13]; //13bytes       /*field33 发送机构标志码*/
	u_char authResID[6]; //6bytes             /*field38 授权标志应答码*/
	u_char resCode[2]; //2bytes               /*field39 应答码*/
	u_char cardID[15]; //15bytes              /*field42 受卡方标志码*/
};

//cups2.0 define cups message fields2
//fro field66 to field128
typedef struct cups_slavefields{
	u_char origData[42]; //42bytes             /*field90 原始数据元*/
};

//cups2.0 define cups message struct
//cups使用的报文以ascii形式编码
typedef struct cups{
		struct cups_header header;//46Bytes       /*cups报文头*/
		u_char type[4]; //4Byte                      /*报文类型,由其决定是什么交易 4位定长数字字符*/
		u_char mastermap[8]; //8Byte				  /*主位图,64位二进制数*/
		/*cups_mastermap的第一位为0,表示没有第二个位图*/
		u_char slavemap[8]; //8Byte                  /*副位图,64位二进制数*/
		struct cups_masterfields masterfields;
		struct cups_slavefields slavefields;
};


u_char *convert_trans_type(int type);
u_char *convert_msg_type(char *type);
u_char *convert_rescode(char *rescode);

int parse_cups(struct cups *cups, u_char *data, u_int32_t len);
int parse_cups_header(struct cups *cups, u_char *data, u_int32_t len);
int parse_cups_masterfields(struct cups *cups, u_char *data, u_int32_t len);
int parse_cups_slavefields(struct cups *cups, u_char *data, u_int32_t len);

void output_cups(struct cups *cups, u_char *output);


#endif /* CUPS_H_ */
