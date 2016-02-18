#include "cups.h"


u_char *convert_msg_type(char *type){

	return type;

}

u_char *convert_rescode(char *rescode){

	u_char *p = NULL;
	u_char tmp[3];
	memcpy(tmp, rescode, 2);
	tmp[2] = '\0';

	switch(atoi(tmp)){
		case 0:
			p = "交易成功";
			break;
		case 4:
			p = "特殊条件下没收卡";
			break;			
		case 5:
			p = "上送信息错误";
			break;
		case 14:
			p = "卡号不存在";
			break;
		case 34:
			p = "卡磁道错误次数超限";
			break;			
		case 40:
			p = "请求功能尚不支持";
			break;	
		case 41:
			p = "挂失卡";
			break;			
		case 51:
			p = "资金不足";
			break;
		case 54:
			p = "无卡支付过期卡";
			break;	
		case 55:
			p = "密码错误";
			break;	
		case 57:
			p = "受限制卡";
			break;
		case 59:
			p = "没有该客户号";
			break;
		case 61:
			p = "超级金额限制";
			break;
		case 65:
			p = "超出取款次数限制";
			break;
		case 75:
			p = "已锁卡";
			break;
		case 96:
			p = "系统异常";
			break;

		default:
			p = "没有找到错误码中文意思";
	}
	
	return p;

}

u_char *convert_trans_type(int type){

	u_char *p = NULL;
	switch(type){
		case 0:
			p = "商品和服务";
			break;
		case 1:
			p = "现金";
			break;
		case 2:
		    p = "调整";
		    break;
		case 3:
			p = "支票担保";
			break;
		case 4:
			p = "支票核实";
			break;
		case 5:
			p = "欧洲支票";
			break;
		case 6:
			p = "旅行支票";
			break;
		case 7:
		    p = "信用证";
		    break;
		case 8:
			p = "直接转账";
			break;
		case 9:
			p = "现金支付的商品和服务";
			break;
		case 20:
			p = "退款";
			break;
		case 21:
			p = "存款";
			break;
		case 22:
		    p = "调整";
		    break;
		case 23:
			p = "支票存款担保";
			break;
		case 24:
			p = "支票存款";
			break;			
		case 30:
			p = "可用金额查询";
			break;
		case 31:
		    p = "余额查询";
		    break;
		case 40:
		case 41:
		case 42:
		case 43:
		case 44:
		case 45:
		case 46:
		case 47:
		case 48:
		case 49:
			p = "转账";
			break;
		case 70:
			p = "修改密码";
			break;
		case 90:
			p = "建立委托关系";
			break;
		case 91:
			p = "撤销委托关系";
			break;
		default:
			p = "无中文含义";
	}

	return p;

}

/*return 0 表示ok, 返回-1表示出错*/
int parse_cups(struct cups *cups, u_char *data, u_int32_t len){

	int offset;
	memset(cups, 0x00, sizeof(struct cups));
	parse_cups_header(cups, data, len);
	memcpy(cups->type, data + 46, 4);
	memcpy(cups->mastermap, data + 50, 8);
	offset = parse_cups_masterfields(cups, data, len);
	//printf("master filed offset is %d\n", offset);

	//有次位图
	if(cups->mastermap[0] & 0x80){
		memcpy(cups->slavemap, data + 58, 8);
		offset = parse_cups_slavefields(cups, data, offset);
		//printf("slave filed offset is %d\n", offset);
	}

	return 0;
}
/*return 0 表示ok, 返回-1表示出错*/
int parse_cups_header(struct cups *cups, u_char *data, u_int32_t len){

	memcpy(&cups->header.headLen, data, 1);
	memcpy(&cups->header.headVer, data + 1, 1);
	memcpy(cups->header.cupsLen, data +2, 4);
	memcpy(cups->header.desID, data + 6, 11);
	memcpy(cups->header.srcID, data + 17, 11);
	memcpy(cups->header.reserved, data + 28, 3);
	memcpy(&cups->header.batchNum, data + 31, 1);
	memcpy(cups->header.transInfor, data + 32, 8);
	memcpy(&cups->header.userInfor, data + 40, 1);
	memcpy(cups->header.rejectCode, data + 41, 5);
	return 0;
}
/*return 返回offset整个cups报文的偏移量  理论上等于cups报文长度,如果有次位图,返回次位图域的首地址*/
int parse_cups_masterfields(struct cups *cups, u_char *data, u_int32_t len){

	/*主报文域未使用域: 8 17 20 21 24 27 29 30 31 34 40 46 47  55 56 64*/
	int offset = sizeof(cups->header) + sizeof(cups->type) + sizeof(cups->mastermap);
	if(cups->mastermap[0] & 0x80){
		offset += sizeof(cups->slavemap);
	}

	//printf("master map:\n");
	int i;

	//for(i=0; i<8; i++){
	//	printf("byte[%d]=%02x\t", i, cups->mastermap[i]);
	//}
	//printf("\n");

	int j = 0;
	char buff[10];
	memset(buff, 0x00, sizeof(buff));
	for(i=1; i<64; i++){

		if(TIBMAP_IS_SET(cups->mastermap, i)){
			//printf("field%d set\n", i+1);
			switch(i){
			case 1:
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				memcpy(cups->masterfields.PAN, data + offset, j);
				offset += j;
				break;
			case 2:
				memcpy(cups->masterfields.processCode, data + offset, 6);
				offset += 6;
				break;
			case 3:
				offset += 12;
				break;
			case 4:
				offset += 12;
				break;
			case 5:
				offset += 12;
				break;
			case 6:
				memcpy(cups->masterfields.transmissionTime, data + offset, 10);
				offset += 10;
				break;
			case 8:
				offset += 8;
				break;
			case 9:
				offset += 8;
				break;
			case 10:
				memcpy(cups->masterfields.systemTraceNumber, data + offset, 6);
				offset += 6;
				break;
			case 11:
				offset += 6;
				break;
			case 12:
				offset += 4;
				break;
			case 13:
				offset += 4;
				break;
			case 14:
				offset += 4;
				break;
			case 15:
				offset += 4;
				break;
			case 17:
				offset += 4;
				break;
			case 18:
				offset += 3;
				break;
			case 21:
				offset += 3;
				break;
			case 22:
				offset += 3;
				break;
			case 24:
				offset += 2;
				break;
			case 25:
				offset += 2;
				break;
			case 27:
				offset += 9;
				break;
			case 31:
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				memcpy(cups->masterfields.acquireInstID, data + offset, j);
				offset += j;
				break;
			case 32:
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				memcpy(cups->masterfields.forwardInstID, data + offset, j);
				offset += j;
				break;
			case 34:
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				offset += j;
				break;
			case 35:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 36:
				offset += 12;
				break;
			case 37:
				memcpy(cups->masterfields.authResID, data + offset, 6);
				offset += 6;
				break;
			case 38:
				memcpy(cups->masterfields.resCode, data + offset, 2);
				offset += 2;
				break;
			case 40:
				offset += 8;
				break;
			case 41:
				memcpy(cups->masterfields.cardID, data + offset, 15);
				offset += 15;
				break;
			case 42:
				offset += 40;
				break;
			case 43:
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				offset += j;
				break;
			case 44:
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				offset += j;
				break;
			case 47:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 48:
				offset += 3;
				break;
			case 49:
				offset += 3;
				break;
			case 50:
				offset += 3;
				break;
			case 51:
				offset += 8;
				break;
			case 52:
				offset += 16;
				break;
			case 53:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 54:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 56:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 57:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 58:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 59:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 60:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 61:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 62:
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;

			default:
				//printf("parse cups error.\n");
				break;
			}//end switch
		}//end if
	}// end for

	return offset;
}
/*return 返回offset整个cups报文的偏移量  理论上等于cups报文长度*/
int parse_cups_slavefields(struct cups *cups, u_char *data, u_int32_t offset){
	/*次报文域未使用域: 67 68 69 71 72 83 85 91 92 93 94 98 104 105~120 124~124*/
	//printf("slave map:\n");
	int i;
	//for(i=0; i<8; i++){
		//printf("byte[%d]=%02x\t", i, cups->slavemap[i]);
	//}
	//printf("\n");

	int j = 0;
	char buff[10];
	memset(buff, 0x00, sizeof(buff));

	for(i=0; i<64; i++){

		if(TIBMAP_IS_SET(cups->slavemap, i)){
			//printf("field%d set\n", i+64+1);
			switch(i){
			case 1://field 66
				offset += 1;
				break;
			case 5://field 70
				offset += 3;
				break;
			case 9://field 74
				offset += 10;
				break;
			case 10://field 75
				offset += 10;
				break;
			case 11://field 76
				offset += 10;
				break;
			case 12://77
				offset += 10;
				break;
			case 13://78
				offset += 10;
				break;
			case 14://79
				offset += 10;
				break;
			case 15://80
				offset += 10;
				break;
			case 16://81
				offset += 10;
				break;
			case 17://82
				offset += 12;
				break;
			case 19://84
				offset += 12;
				break;
			case 21://86
				offset += 16;
				break;
			case 22://87
				offset += 16;
				break;
			case 23://88
				offset += 16;
				break;
			case 24://89
				offset += 16;
				break;
			case 25://90
				memcpy(cups->slavefields.origData, data + offset, 42);
				offset += 42;
				break;
			case 30://95
				offset += 42;
				break;
			case 31://96
				offset += 8;
				break;
			case 32://97
				offset += 17;
				break;
			case 34://99
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				offset += j;
				break;
			case 35://100
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				offset += j;
				break;
			case 37://102
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				offset += j;
				break;
			case 38://103
				memcpy(buff, data + offset, 2);
				buff[2] = '\0';
				j = atoi(buff);
				offset += 2;
				offset += j;
				break;
			case 39://104
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 56://121
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 57://122
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 58://123
				memcpy(buff, data + offset, 3);
				buff[3] = '\0';
				j = atoi(buff);
				offset += 3;
				offset += j;
				break;
			case 63://128
				offset += 8;
				break;
			default:
				//printf("parse slave fields.error.\n");
				break;
			}//end switch
		}//end if
	}// end for

	return offset;
}

/*return 0 表示ok, 返回-1表示出错*/
void output_cups(struct cups *cups, u_char *output){

	u_char buff[256];

	//输出cups头信息
	sprintf(output, "cups header information:\n\theadlen=%d,headVer=%d,cupslen=%.*s,desID=%.*s,srcID=%.*s,transInfor=%.*s,rejectCode=%.*s\n",
			cups->header.headLen,
			cups->header.headVer,
			4, cups->header.cupsLen,
			11, cups->header.desID,
			11, cups->header.srcID,
			8, cups->header.transInfor,
			5, cups->header.rejectCode);

	//输出类型
	sprintf(buff, "cups message type=%.*s\n", 4, cups->type);
	strcat(output, buff);


	//输出主位图域
	sprintf(buff, "cups master fields informatino:\n\t pan=%.*s,processCode=%.*s,transmissionTime=%.*s, systemTraceNumber=%.*s,"
			"acquireInstID=%.*s, forwardInstID=%.*s,authResID=%.*s, resCode=%.*s, cardID=%.*s\n",
			21, cups->masterfields.PAN,
			6, cups->masterfields.processCode,
			10, cups->masterfields.transmissionTime,
			6, cups->masterfields.systemTraceNumber,
			13, cups->masterfields.acquireInstID,
			13, cups->masterfields.forwardInstID,
			6, cups->masterfields.authResID,
			2, cups->masterfields.resCode,
			15, cups->masterfields.cardID);

	strcat(output, buff);

	char tmp[3];
	memcpy(tmp, cups->masterfields.processCode, 2);
	tmp[2] = '\0';


	sprintf(buff, "%s|%s", convert_trans_type( atoi(tmp) ), strlen(cups->masterfields.resCode)>0? "响应报文": "请求报文" );
	strcat(output, buff);

	if(strlen(cups->masterfields.resCode) > 0){
		sprintf(buff, "|%.*s:%s", 2, cups->masterfields.resCode, convert_rescode(cups->masterfields.resCode) );
		strcat(output, buff);
	}
	

	sprintf(buff, "\n");
	strcat(output, buff);

	//输出次位图域
	//if(cups->mastermap[0] & 0x80){
	//	printf("cups slave fields informatino:\n\t origData=%.*s\n", 42, cups->slavefields.origData);
	//}

	return;
}