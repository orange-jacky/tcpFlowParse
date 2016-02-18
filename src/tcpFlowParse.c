
#include "tcpFlowParse.h"

//定义全局变量
int log_default_level = LOG_LEVEL_ERROR;/*默认日志级别*/
int max_desired_fds = 0;

struct logFile mylog;  //定义全局日志变量
struct logFile cupslog;
struct tcpFlowParse maincfg;
struct proto protos[MAX_DATAPROTO_NUMBER];
struct app apps[MAX_APPS_NUMBER];
int proto_number = 0;
int app_number = 0 ;


long total_packet = 0;
long total_bytes = 0;

//定义两个单链表
LinkList list1, list2;

int signal_stop = 0;


void usage(){
	fprintf(stdout, "Usage: tcpFlowParse [-?h] [-s sigal]\n"
			"Options:\n"
			" -?,-h 	        : this help\n"
			" -s signal 	: send signal to tcpFlowParse\n"
			"                  stop\n"
			"example:	\n"
			"1.start tcpFlowParse, execute a command:\n"
			"./tcpFlowParse\n"
			"2.stop tcpFlowParse, execute a command:\n"
			"./tcpFlowParse -s stop\n"
			"\n\n");
}


RETSIGTYPE terminate(int sig)
{
    logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", "terminating");
  	//释放资源
	int j;
	for(j = 0; j< MAX_DATAPROTO_NUMBER &&  j< proto_number; j++ ){
		free_proto(&protos[j]);
	}

	for(j = 0; j< MAX_APPS_NUMBER && j < app_number; j++ ){
		free_app(&apps[j]);
	}
	free_tcpFlowParse(&maincfg);

	DestroyList(&list1);
    logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", "free list1");
    DestroyList(&list2);
    logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", "free list2");

	logFile_colse(&mylog);
	logFile_colse(&cupslog);

  	exit(0); /* libpcap uses onexit to clean up */
}

void main(int argc, char *argv[]){


 /* set up signal handlers for graceful exit (pcap uses onexit to put
     interface back into non-promiscuous mode */
  	
	pid_t pid;
	pid = fork();
	if(pid < 0){
		fprintf(stderr, "fork child process fail.\n");
		exit(-1);
	}else if ( pid > 0){//父进程
		//fprintf(stdout, "exit parent process.\n");
		exit(0);
	}else{//子进程



	int opt;
	char *optstring = "s:h";
	while( (opt = getopt(argc, argv, optstring) )  != -1){

		switch(opt){
			case 's':

				printf("-s param is %s\n", optarg);

			 	if( strcmp(optarg, "stop") == 0){
			 		signal_stop = 1;
			    	break;
			 	}else{
			 		usage();
					exit(0);
			 	}

			case '?':
			case 'h':
				usage();
				exit(0);
		}

	}



  	portable_signal(SIGTERM, terminate);
  	portable_signal(SIGINT, terminate);
  	portable_signal(SIGHUP, terminate);

	//找出程序绝对路径
	char buff[512];
	realpath(argv[0], buff);
	//fprintf(stdout, "abs path is [%s]\n", buff);
    //计算出程序的根路径
    char tmp[512];
    sprintf(tmp, "%s%s", "/bin/", PROGRAM_NAME);
    char *start, *end;
    end = strstr(buff, tmp);
    //printf("%s\n", buff);
    while(*end!= '\0'){
    	*end = '\0';
    	end++;
    }


    printf("signal_stop=%d\n", signal_stop);
    sprintf(tmp, "%s/%s", buff, "tcpFLowParse.pid");
    if(signal_stop == 1){

    	FILE *fp = fopen(tmp, "r");
    	if(fp == NULL){
    		printf(stderr, "cant find %s\n", tmp);
    		exit(-1);
    	}
    	char bu[512];
    	fgets(bu, sizeof(bu), fp);
    	pid_t pid = atoi(bu);

    	printf("pid=%s\n", bu);

    	kill(pid, SIGTERM);

    	remove(tmp);

    	exit(0);
    }	


    if( file_check_exist(tmp) == 0){
		FILE *fp = fopen(tmp, "r");
    	if(fp == NULL){
    		printf(stderr, "cant open %s\n", tmp);
    		exit(-1);
    	}
    	char bu[512];
    	fgets(bu, sizeof(bu), fp);
    	pid_t pid = atoi(bu);

    	//printf("pid=%s\n", bu);

    	int ret = kill(pid, 0);
    	if(ret == 0){
    		printf("process is running, can't run again\n.");
    		fclose(fp);
    		exit(0);
    	}else{
    		printf("start process...\n");
    		remove(tmp);
    	}
    }

	FILE *fp = fopen(tmp, "w");
    if(fp == NULL){
    	printf(stderr, "can't create %s\n", tmp);
    	exit(-1);
    }
    fprintf(fp, "%d", getpid());
    fclose(fp);


	//产生总的日志文件名称
	struct timeval now;
	struct tm *tm_ptr;
	char dt[512];
	gettimeofday(&now, NULL);
	tm_ptr = localtime(&now.tv_sec);
	sprintf(dt, "%s_%d%02d%02d-%02d%02d%02d%s", PROGRAM_NAME, tm_ptr->tm_year+1900, tm_ptr->tm_mon+1, tm_ptr->tm_mday,
				 tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec, ".log") ;
    


    //查找老的日志文件
	DIR *dir;
	struct dirent *ent;
	int find_log_file = 0;
	sprintf(tmp, "%s", buff);
	if( (dir = opendir(tmp) ) != NULL){
		while( (ent =  readdir(dir)) !=  NULL)
			if(strstr(ent->d_name, ".log") != NULL){
					char tmp1[512];
					sprintf(tmp1, "%s/%s", tmp, ent->d_name);
					//存在的日志文件小于64MB
					if( get_file_size(tmp1) < MAX_LOGFILE_SIZE){
						memset(&mylog, 0x00, sizeof(mylog));
						logFile_open(&mylog, tmp1);
						#define TAG_START "===================================>>>>>>>>>>>>>"
						logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", TAG_START"reopen mylog file");
						find_log_file = 1;
					}			
			}
	}


	//生成日志文件
	if(find_log_file == 0){
	    memset(&mylog, 0x00, sizeof(mylog));
		sprintf(tmp, "%s/%s", buff,dt);
		logFile_open(&mylog, tmp);
		logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", "create mylog file");	
	}


	//计算能够使用的最大文件描述符
	logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "max fds is %d", get_max_fds());

	//解析主配置文件
	sprintf(tmp, "%s/%s", buff,"etc/tcpFlowParse.xml");
	logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "main configure file is %s", tmp);

	memset(&maincfg, 0x00, sizeof(maincfg));
	parse_tcpFlowParse(&maincfg, tmp);

    //设置告警级别
	if(!strcasecmp(&maincfg.loglevel, "all")){
		log_default_level = LOG_LEVEL_ALL;
	}else if(!strcasecmp(&maincfg.loglevel, "error")){
		log_default_level = LOG_LEVEL_ERROR;
	}else if(!strcasecmp(&maincfg.loglevel, "warn")){
		log_default_level = LOG_LEVEL_WARN;
	}else if(!strcasecmp(&maincfg.loglevel, "info")){
		log_default_level = LOG_LEVEL_INFO;
	}else if(!strcasecmp(&maincfg.loglevel, "debug")){
		log_default_level = LOG_LEVEL_DEBUG;
	}else{
		/*nothing*/
	}


  	InitList(&list1);
  	InitList(&list2);

		logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "list1 length %d", ListLength(list1));

		logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "list2 length %d", ListLength(list2));


	//输出主配置文件内容
	print_tcpFlowParse(&maincfg);


	//读取数据协议信息
	memset(protos, 0x00, sizeof(protos));
	sprintf(tmp, "%s/%s", buff,"etc/protocols");
	if( (dir = opendir(tmp) ) != NULL){
		while( (ent =  readdir(dir)) !=  NULL)
			if(strstr(ent->d_name, ".xml") != NULL){
					char tmp1[512];
					sprintf(tmp1, "%s/%s", tmp, ent->d_name);
					parse_proto(&protos[proto_number], tmp1);
					print_proto(&protos[proto_number]);
					proto_number++;
			}
	}else{
		logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", "opendir etc/protocols error.");
	}


	//读取应用配置信息
	memset(apps, 0x00, sizeof(apps));
	sprintf(tmp, "%s/%s", buff,"etc/applications");
	if( (dir = opendir(tmp) ) != NULL){
		while( (ent =  readdir(dir)) !=  NULL)
			if(strstr(ent->d_name, ".xml") != NULL){
					char tmp1[512];
					sprintf(tmp1, "%s/%s", tmp, ent->d_name);
					parse_app(&apps[app_number], tmp1);
					print_app(&apps[app_number]);
					app_number++;
			}
	}else{
		logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", "opendir etc/applications error.");
	}


	sprintf(tmp, "%s/%s/%s", buff, "var", maincfg.app_name[0]);
	dir_create(tmp);


	memset(&cupslog, 0x00, sizeof(mylog));
	sprintf(tmp, "%s/%s/%s/%s%s", buff, "var", maincfg.app_name[0], maincfg.app_name[0], ".log");
	logFile_open(&cupslog, tmp);
	logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", "create cupslog file");	




	//开始启动抓包程序
	pcap_t *pd;
  	struct bpf_program fcode;
  	pcap_handler handler;
	char error[PCAP_ERRBUF_SIZE];
	int no_promisc = 0;
	char *expression = NULL;
	int dlt = 0;

    logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "pcap lib is %s\n", pcap_lib_version());

  	if ( strlen(maincfg.pcap_filename) > 0 ) {
	   	 /* Since we don't need network access, drop root privileges */
	   	 setuid(getuid());

	    /* open the capture file */
	   	char mybuf[256];
	   	sprintf(mybuf, "%s/%s", maincfg.pcap_path, maincfg.pcap_filename); 
	    if ((pd = pcap_open_offline(mybuf, error)) == NULL){
	    	logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "pcap open savefile fail. %s", error);
	    	kill( getpid(), SIGHUP);
	    	return;
	    }
	    /* get the handler for this kind of packets */
	    dlt = pcap_datalink(pd);
	    handler = find_handler(dlt, mybuf);
  	} else {
  	  /* if the user didn't specify a device, try to find a reasonable one */
    	if (strlen(maincfg.nic) >0 ){
  		/* make sure we can open the device */
		    if ((pd = pcap_open_live(maincfg.nic, SNAPLEN, !no_promisc, 1000, error)) == NULL){
				logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "pcap open nic fail. %s", error);
	    		kill( getpid(), SIGHUP);
	    		return;
	    	}
		    /* drop root privileges - we don't need them any more */
		   // setuid(getuid());
		    /* get the handler for this kind of packets */
		    dlt = pcap_datalink(pd);
		    handler = find_handler(dlt, maincfg.nic);
    	} 
  	}
  	
  	expression = strlen(maincfg.filter) > 0 ? maincfg.filter : "tcp or (vlan and tcp)" ;
 	logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,"filter expression: '%s'", expression);


  /* install the filter expression in libpcap */
  if (pcap_compile(pd, &fcode, expression, 1, 0) < 0){
    	logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "pcap_compile error. %s", pcap_geterr(pd));
    	kill( getpid(), SIGHUP);
	    return;
	}

  if (pcap_setfilter(pd, &fcode) < 0){
  	logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "pcap_setfilter error. %s", pcap_geterr(pd));
    	kill( getpid(), SIGHUP);
	    return;
  }
  
  if (pcap_loop(pd, -1, handler, NULL) < 0){
  		logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "pcap_loop error. %s", pcap_geterr(pd));
    	kill( getpid(), SIGHUP);
	    return;
  }



  	logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "totoal_byte is %d", total_bytes);



	//释放资源
	int j;
	for(j = 0; j< MAX_DATAPROTO_NUMBER &&  j< proto_number; j++ ){
		free_proto(&protos[j]);
	}

	for(j = 0; j< MAX_APPS_NUMBER && j < app_number; j++ ){
		free_app(&apps[j]);
	}

	free_tcpFlowParse(&maincfg);
	DestroyList(&list1);
    logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", "free list1");
    DestroyList(&list2);
    logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "%s", "free list2");

	logFile_colse(&mylog);
	logFile_colse(&cupslog);

	return;
	}
}






