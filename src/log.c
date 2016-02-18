#include "tcpFlowParse.h"


/*默认日志级别*/
extern int log_default_level;


/*return 0 respresent success*/
int  logFile_open(struct logFile *logfile , char *filename){

	if(NULL == filename  || NULL == logfile) return -1;

	FILE *fp = NULL;
	fp = fopen(filename, "ab+");
	if(NULL == fp){
		return -2;
	}

	setbuf(fp, NULL);

	logfile->filename = strdup(filename);
	logfile->fp = fp;
	logfile->pos = 0;
	logfile->flags = 0;

	return 0;

}

void logFile_write_message(struct logFile * logfile, int loglevel, char *filename, int line, char *func, char *fmt, ...){

	if(log_default_level > loglevel) return;

	if(NULL == logfile) return ;

	struct timeval now;
	struct tm *tm_ptr;
	char dt[256];
    va_list  args;

	gettimeofday(&now, NULL);
	tm_ptr = localtime(&now.tv_sec);
	
	#if 0
	sprintf(dt, "(%d%02d%02d-%02d:%02d:%02d %s:%d %s", tm_ptr->tm_year+1900, tm_ptr->tm_mon+1, tm_ptr->tm_mday,
				 tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec, filename, line, func) ;
	#endif
	sprintf(dt, "%d%02d%02d %02d:%02d:%02d", tm_ptr->tm_year+1900, tm_ptr->tm_mon+1, tm_ptr->tm_mday,
				 tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec) ;

   	va_start(args, fmt);
	fprintf(logfile->fp, "%s", dt);
	//fprintf(logfile->fp, ")");

	switch(loglevel){
		case LOG_LEVEL_ALL:
			//fprintf(logfile->fp, "[default]");
			break;
		case LOG_LEVEL_ERROR:
			fprintf(logfile->fp, "[error]");
			break;
		case LOG_LEVEL_WARN:
			fprintf(logfile->fp, "[warn]");	
			break;
		case LOG_LEVEL_INFO:
			fprintf(logfile->fp, "[info]");
			break;
		case LOG_LEVEL_DEBUG:
			fprintf(logfile->fp, "[debug]");
			break;
		default:
			fprintf(logfile->fp, "[unknown level]");
	}

	vfprintf(logfile->fp, fmt, args);
	va_end(args);
	fprintf(logfile->fp, "%s", "\n");
	fflush(logfile->fp);
	return;
}

void logFile_colse(struct logFile * logfile){
	if(NULL == logfile) return ;

	if(logfile->filename)
	{
		free(logfile->filename);
		logfile->filename = NULL;
	}
	if(logfile->fp)
	{
		fclose(logfile->fp);
		logfile->fp = NULL;
	}
	return;
}

