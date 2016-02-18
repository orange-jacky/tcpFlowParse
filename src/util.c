#include "tcpFlowParse.h"

//定义全局日志变量
extern int max_desired_fds;

/* Simple wrapper around the malloc() function */
void *check_malloc(size_t size)
{
  void *ptr = NULL;
  ptr = malloc(size);
  return ptr;
}

/* Try to find the maximum number of FDs this system can have open */
int get_max_fds(void)
{
  int max_descs = 0;
  const char *method;

  /* First, we'll try using getrlimit/setrlimit.  This will probably
   * work on most systems.  HAS_RLIMIT is defined in sysdep.h.  */
#ifdef RLIMIT_NOFILE
  {
    struct rlimit limit;

    method = "rlimit";
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0) {
      // logFile_write_message(logfile, LOG_LEVEL_ALL,  LOG_FORMAT, "%s", "calling getrlimit");
     // exit(1);
    }

#ifdef RLIM_INFINITY
    if (limit.rlim_max == RLIM_INFINITY)
      max_descs = MAX_FD_GUESS * 4;
    else
#endif
      max_descs = limit.rlim_max;
  }


  /* rlimit didn't work, but you have OPEN_MAX */
#elif defined (OPEN_MAX)
  method = "OPEN_MAX";
  max_descs = OPEN_MAX;


  /* Okay, you don't have getrlimit() and you don't have OPEN_MAX.
   * Time to try the POSIX sysconf() function.  (See Stevens'
   * _Advanced Programming in the UNIX Environment_).  */
#elif defined (_SC_OPEN_MAX)
  method = "POSIX sysconf";
  errno = 0;
  if ((max_descs = sysconf(_SC_OPEN_MAX)) < 0) {
    if (errno == 0)
      max_descs = MAX_FD_GUESS * 4;
    else {
      //logFile_write_message(logfile, LOG_LEVEL_ALL,  LOG_FORMAT, "%s", "calling sysconf");
      //exit(1);
    }
  }

  /* if everything has failed, we'll just take a guess */
#else
  method = "random guess";
  max_descs = MAX_FD_GUESS;
#endif

  /* this must go here, after rlimit code */
  if (max_desired_fds) {
      //logFile_write_message(logfile, LOG_LEVEL_ALL,  LOG_FORMAT, "using only %d FDs", max_desired_fds);
   // DEBUG(10) ("using only %d FDs", max_desired_fds);
    return max_desired_fds;
  }

  //logFile_write_message(logfile, LOG_LEVEL_ALL,  LOG_FORMAT, "found max FDs to be %d using %s", max_descs, method);
  //DEBUG(10) ("found max FDs to be %d using %s", max_descs, method);
  return max_descs;
}



/* An attempt at making signal() portable.
 *
 * If we detect sigaction, use that;
 * otherwise if we have setsig, use that;
 * otherwise, cross our fingers and hope for the best using plain old signal().
 *
 * Our first choice is sigaction (sigaction() is POSIX; signal() is
 * not.)  Taken from Stevens' _Advanced Programming in the UNIX
 * Environment_.
 */
RETSIGTYPE (*portable_signal(int signo, RETSIGTYPE (*func)(int)))(int)
{
#if defined(HAVE_SIGACTION)
  struct sigaction act, oact;

  memset(&act, 0, sizeof(act));
  memset(&oact, 0, sizeof(oact));
  act.sa_handler = func;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;

  if (sigaction(signo, &act, &oact) < 0)
    return (SIG_ERR);

  return (oact.sa_handler);
#elif defined(HAVE_SIGSET)
  return sigset(signo, func);
#else
  return signal(signo, func);
#endif /* HAVE_SIGACTION, HAVE_SIGSET */

}


void flow_filename(flow_t flow, char *output)
{

  sprintf(output,
    "%d.%d.%d.%d:%d-%d.%d.%d.%d:%d",
    (u_int8_t) ((flow.src & 0xff000000) >> 24),
    (u_int8_t) ((flow.src & 0x00ff0000) >> 16),
    (u_int8_t) ((flow.src & 0x0000ff00) >> 8),
    (u_int8_t)  (flow.src & 0x000000ff),
    flow.sport,
    (u_int8_t) ((flow.dst & 0xff000000) >> 24),
    (u_int8_t) ((flow.dst & 0x00ff0000) >> 16),
    (u_int8_t) ((flow.dst & 0x0000ff00) >> 8),
    (u_int8_t)  (flow.dst & 0x000000ff),
    flow.dport);
  return;
}

//文件模式.等同于0755
#define FILE_MODE S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH
//0 success -1 fail
int dir_create(const char *path){

  if(path != NULL && dir_check_exist(path) == -1){
    return mkdir(path, FILE_MODE);
  }

  return -1;
}

//0 success -1 fail
int dir_check_exist(const char *path){

  if(path){
    return access(path, F_OK);
  }

  return -1;
}

//0 success -1 fail
int  file_check_exist(const char *path){

    if(path){
      return access(path, F_OK);
    }
  return -1;
}


//-1 表示出错,否则返回文件大小
unsigned long get_file_size(const char *path)  
{  
    unsigned long filesize = -1;      
    struct stat statbuff;  
    if(stat(path, &statbuff) < 0){  
        return filesize;  
    }else{  
        filesize = statbuff.st_size;  
    }  
    return filesize;  
}  

//0 表示找到, -1表示没有找到
int flow_app(flow_t *flow, struct app *app){

  if(flow_find_port(flow, app) == 0 ){
      return flow_find_ip(flow, app);
  }

  return -1;

}

int flow_find_ip(flow_t *flow, struct app *app){

    int i;
    char buff[32];
    int find_client = 0;
    int find_server = 0;

    sprintf(buff, "%d.%d.%d.%d",
        (u_int8_t) ((flow->src & 0xff000000) >> 24),
        (u_int8_t) ((flow->src & 0x00ff0000) >> 16),
        (u_int8_t) ((flow->src & 0x0000ff00) >> 8),
        (u_int8_t)  (flow->src & 0x000000ff));

    for(i = 0; i < MAX_FIELD_NUMBER  && app->clients[i] != NULL ; i++){
        if( strcmp(buff, app->clients[i]) == 0){
            find_client = 1;
            break;
        }
    }

    if(find_client == 0){
      return -1;
    }


    sprintf(buff, "%d.%d.%d.%d",
        (u_int8_t) ((flow->dst & 0xff000000) >> 24),
        (u_int8_t) ((flow->dst & 0x00ff0000) >> 16),
        (u_int8_t) ((flow->dst & 0x0000ff00) >> 8),
        (u_int8_t) (flow->dst & 0x000000ff));

    for(i = 0; i < MAX_FIELD_NUMBER  && app->servers[i] != NULL ; i++){
        if( strcmp(buff, app->servers[i]) == 0){
            find_server = 1;
            break;
        }
    }

    if(find_client == 1 && find_server ==1){
      return 0;
    }

    return -1;

}

int flow_find_port(flow_t *flow, struct app *app){

    int i;
    for(i = 0; i < MAX_FIELD_NUMBER  && app->ports[i] != NULL ; i++){
        if( atoi(app->ports[i]) ==  flow->dport || atoi(app->ports[i]) ==  flow->sport )
          return 0;
    }

    return -1;
}



void elsptime(struct timeval req, struct timeval resp, char *aa){

   time_t       tv_sec;     /* seconds */
   suseconds_t   tv_usec; /* microseconds */

  tv_sec = resp.tv_sec - req.tv_sec;
  tv_usec = resp.tv_usec - req.tv_usec;

  sprintf(aa, "%d", tv_sec*1000 + tv_usec/1000);

  return;
}



