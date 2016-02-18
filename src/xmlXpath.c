#include "tcpFlowParse.h"

/*默认日志级别*/
extern int log_default_level;
extern struct logFile mylog;  //定义全局日志变量


//解析内存中xml格式的字符串,buffer必须以null结尾才能解析
xmlDocPtr 
get_doc_from_memory(char *buffer, int size){
	
	if(NULL == buffer || size == 0)
		return NULL;	
	xmlDocPtr doc;
	doc = xmlParseMemory(buffer, size);
	if (doc == NULL ) {
		//fprintf(stderr,"Document not parsed successfully. \n");
		return NULL;
	}
	return doc;
}

//解析xml文件
xmlDocPtr 
get_doc_from_file (char *docname){

	if(NULL == docname)
		return NULL;
	xmlDocPtr doc;
	doc = xmlParseFile(docname);
	
	if (doc == NULL ) {
		//fprintf(stderr,"Document not parsed successfully. \n");
		return NULL;
	}
	return doc;
}

//get node set by xpath
xmlXPathObjectPtr 
get_node_set (xmlDocPtr doc, xmlChar *xpath){


	if(NULL == doc || NULL == xpath)
		return NULL;
	xmlXPathContextPtr context;
	xmlXPathObjectPtr result;

	context = xmlXPathNewContext(doc);
	if (context == NULL) {
		//printf("Error in xmlXPathNewContext\n");
		return NULL;
	}
	result = xmlXPathEvalExpression(xpath, context);
	xmlXPathFreeContext(context);
	if (result == NULL) {
		//printf("Error in xmlXPathEvalExpression\n");
		return NULL;
	}
	if(xmlXPathNodeSetIsEmpty(result->nodesetval)){
		xmlXPathFreeObject(result);
               // printf("No result\n");
		return NULL;
	}
	
	return result;
}



/*---------------read protocol configure infor--------------------*/
int
parse_tcpFlowParse(struct tcpFlowParse *maincfgPtr , char *filepath){

	xmlDocPtr doc;
	xmlChar *xpath = (xmlChar*)NULL;
	xmlNodeSetPtr nodeset;
	xmlXPathObjectPtr result;
	xmlChar *tagname, *attr_value = NULL;

	if(filepath == NULL)return -1;
	doc = get_doc_from_file(filepath);
	
 	if (!doc)
    	{
       	 //api->log_message(mylog, WRT_API_LOG_ERROR,
           //              __func__, __LINE__,
             //            "error: parese configure file [%s] error", filepath);
       	 return -1;
   	}

	xpath = (xmlChar*)"/root/interface";
	result = get_node_set (doc, xpath);
	int i;
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"nic");  
   			if(attr_value){
					maincfgPtr->nic = strdup((char *)attr_value);
	    			xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}


	xpath = (xmlChar*)"/root/savefile";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"path");  
   			if(attr_value){
					maincfgPtr->pcap_path = strdup((char *)attr_value); 
					xmlFree(attr_value);  
			}
			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"filename");  
   			if(attr_value){
				maincfgPtr->pcap_filename = strdup((char *)attr_value);
	    			xmlFree(attr_value);  
			} 
		}
		xmlXPathFreeObject (result);
	}


	xpath = (xmlChar*)"/root/filter";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"string");  
   			if(attr_value){
					maincfgPtr->filter = strdup((char *)attr_value); 
					xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}

	xpath = (xmlChar*)"/root/pcapstat";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"switch");  
   			if(attr_value){
					maincfgPtr->pcapstat = strdup((char *)attr_value); 
					xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}



	xpath = (xmlChar*)"/root/timeinterval";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"value");  
   			if(attr_value){
					maincfgPtr->timeinterval = atoi((char *)attr_value); 
					xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}


	xpath = (xmlChar*)"/root/mylog";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"level");  
   			if(attr_value){
					maincfgPtr->loglevel = strdup((char *)attr_value); 
					xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}

	xpath = (xmlChar*)"/root/applications/application";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"name");  
   			if(attr_value){
					maincfgPtr->app_name[i] = strdup((char *)attr_value); 
					xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}

	xmlFreeDoc(doc);
	xmlCleanupParser();
	return 0;
}


int
parse_app(struct app * appptr , char *filepath){

	xmlDocPtr doc;
	xmlChar *xpath = (xmlChar*)NULL;
	xmlNodeSetPtr nodeset;
	xmlXPathObjectPtr result;
	xmlChar *tagname, *attr_value = NULL;

	if(filepath == NULL)return -1;
	doc = get_doc_from_file(filepath);
	
 	if (!doc)
    	{
       	 //api->log_message(mylog, WRT_API_LOG_ERROR,
           //              __func__, __LINE__,
             //            "error: parese configure file [%s] error", filepath);
       	 return -1;
   	}

	xpath = (xmlChar*)"/application/transportProtocol";
	result = get_node_set (doc, xpath);
	int i;
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"base");  
   			if(attr_value){
					appptr->base = strdup((char *)attr_value);
	    			xmlFree(attr_value);  
			}

			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"ex");  
   			if(attr_value){
					appptr->ex = strdup((char *)attr_value);
	    			xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}


	xpath = (xmlChar*)"/application/dataProtocol";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"name");  
   			if(attr_value){
					appptr->dataproPtr = strdup((char *)attr_value); 
					xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}

	xpath = (xmlChar*)"/application/transportMethod";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
			tagname = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
   			if(tagname){
				appptr->transMethod = strdup((char *)tagname);
				xmlFree(tagname);
			} 
		}
		xmlXPathFreeObject (result);
	}

	xpath = (xmlChar*)"/application/output";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"tcp");  
   			if(attr_value){
					appptr->output_tcp = strdup((char *)attr_value); 
					xmlFree(attr_value);  
			}
			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"trans");  
   			if(attr_value){
					appptr->output_trans = strdup((char *)attr_value); 
					xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}


	xpath = (xmlChar*)"/application/serverports/port";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
			tagname = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
   			if(tagname){
				appptr->ports[i] = strdup((char *)tagname);
				xmlFree(tagname);
			} 
		}
		xmlXPathFreeObject (result);
	}


	xpath = (xmlChar*)"/application/serverlists/server";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
			tagname = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
   			if(tagname){
				appptr->servers[i] = strdup((char *)tagname);
				xmlFree(tagname);
			} 
		}
		xmlXPathFreeObject (result);
	}


	xpath = (xmlChar*)"/application/clientlists/client";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
			tagname = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
   			if(tagname){
				appptr->clients[i] = strdup((char *)tagname);
				xmlFree(tagname);
			} 
		}
		xmlXPathFreeObject (result);
	}

	xmlFreeDoc(doc);
	xmlCleanupParser();
	return 0;
}



int
parse_proto(struct proto * protoptr , char *filepath){

	xmlDocPtr doc;
	xmlChar *xpath = (xmlChar*)NULL;
	xmlNodeSetPtr nodeset;
	xmlXPathObjectPtr result;
	xmlChar *tagname, *attr_value = NULL;

	if(filepath == NULL)return -1;
	doc = get_doc_from_file(filepath);
	
 	if (!doc)
    	{
       	 //api->log_message(mylog, WRT_API_LOG_ERROR,
           //              __func__, __LINE__,
             //            "error: parese configure file [%s] error", filepath);
       	 return -1;
   	}

	xpath = (xmlChar*)"/protocol";
	result = get_node_set (doc, xpath);
	int i;
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"name");  
   			if(attr_value){
					protoptr->name = strdup((char *)attr_value);
	    			xmlFree(attr_value);  
			}
		}
		xmlXPathFreeObject (result);
	}

	
	xpath = (xmlChar*)"/protocol/recodeFields/field";
	result = get_node_set (doc, xpath);
	if (result) {
		nodeset = result->nodesetval;
		for (i=0; i < nodeset->nodeNr; i++) {
			tagname = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
   			if(tagname){
				protoptr->output_name[i] = strdup((char *)tagname);
				xmlFree(tagname);
			}
   			attr_value = xmlGetProp( nodeset->nodeTab[i], (xmlChar*)"item");  
   			if(attr_value){
				protoptr->get_fields[i] = strdup((char *)attr_value);
	    		xmlFree(attr_value);  
   			}		 
		}
		xmlXPathFreeObject (result);
	}

	xmlFreeDoc(doc);
	xmlCleanupParser();
	return 0;
}



//print protocol configure information
void
print_tcpFlowParse(struct tcpFlowParse *maincfgptr){

	logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "%s", "####tcpFlowParse main configure information:");

    if(maincfgptr->nic) logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT, "nic:%s", maincfgptr->nic);
    if(maincfgptr->pcap_path) logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "pcap_path:%s", maincfgptr->pcap_path);
    if(maincfgptr->pcap_filename) logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "pcap_filename:%s", maincfgptr->pcap_filename);
    if(maincfgptr->filter) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "filter:%s", maincfgptr->filter);
    if(maincfgptr->pcapstat) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "pcapstat:%s", maincfgptr->pcapstat);
    if(maincfgptr->timeinterval) logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "timeinterval:%d", maincfgptr->timeinterval);
    if(maincfgptr->loglevel) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "loglevel:%s", maincfgptr->loglevel);
 
    int i;
    for(i=0; i<MAX_APPS_NUMBER; i++){
    	if(maincfgptr->app_name[i]) logFile_write_message(&mylog, LOG_LEVEL_ALL, LOG_FORMAT,  "app[%d]:$s %s", i, maincfgptr->app_name[i], "enabled");
	}
}


//print protocol configure information
void
print_app(struct app * appptr){


	logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "%s", "####application configure information:");

    if(appptr->appname) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT,  "appname:%s", appptr->appname);
    if(appptr->base) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "base:%s", appptr->base);
    if(appptr->ex) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "ex:%s", appptr->ex);
    if(appptr->dataproPtr) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "dataproPtr:%s", appptr->dataproPtr);
    if(appptr->transMethod) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "transMethod:%s", appptr->transMethod);
    if(appptr->output_tcp) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "output_tcp:%s", appptr->output_tcp);
    if(appptr->output_trans) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "output_trans:%s", appptr->output_trans);
 

    int i;
    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(appptr->ports[i]) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "ports[%d]:%s", i, appptr->ports[i]);
	}

    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(appptr->servers[i]) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "servers[%d]:%s", i, appptr->servers[i]);
	}

    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(appptr->clients[i]) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "clients[%d]:%s", i, appptr->clients[i]);
	}	
}


void
print_proto(struct proto * protoptr){


	logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "%s", "####support data protocol information:");
    if(protoptr->name) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "name:%s", protoptr->name);
  
    int i;
    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(protoptr->get_fields[i]) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "get_fields[%d]:%s", i, protoptr->get_fields[i]);
	}

    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(protoptr->output_name[i]) logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "output_name[%d]:%s", i, protoptr->output_name[i]);
	}	
}



//print protocol configure information
void
free_tcpFlowParse(struct tcpFlowParse *maincfgptr){

	logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "%s", "####free tcpFlowParse main configure information");

    if(maincfgptr->nic) {free(maincfgptr->nic); maincfgptr->nic = NULL;}
    if(maincfgptr->pcap_path) {free(maincfgptr->pcap_path); maincfgptr->pcap_path = NULL;}
    if(maincfgptr->pcap_filename) {free(maincfgptr->pcap_filename); maincfgptr->pcap_filename = NULL;}
    if(maincfgptr->filter) {free(maincfgptr->filter); maincfgptr->filter = NULL;}
    if(maincfgptr->pcapstat) {free(maincfgptr->pcapstat); maincfgptr->pcapstat = NULL;}
    //if(maincfgptr->timeinterval) {free(maincfgptr->timeinterval);maincfgptr->timeinterval = NULL;}
    if(maincfgptr->loglevel) {free(maincfgptr->loglevel); maincfgptr->loglevel = NULL;}
 
    int i;
    for(i=0; i<MAX_APPS_NUMBER; i++){
    	if(maincfgptr->app_name[i]) {free(maincfgptr->app_name[i]); maincfgptr->app_name[i] = NULL;}
	}
}


//print protocol configure information
void
free_app(struct app * appptr){


	logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "%s", "####free application configure struct");

    if(appptr->appname) {free(appptr->appname); appptr->appname = NULL;}
    if(appptr->base) {free(appptr->base); appptr->base = NULL;}
    if(appptr->ex) {free(appptr->ex); appptr->ex = NULL;}
    if(appptr->dataproPtr) {free(appptr->dataproPtr);appptr->dataproPtr = NULL;}
    if(appptr->transMethod) {free(appptr->transMethod);appptr->transMethod = NULL;}
    if(appptr->output_tcp) {free(appptr->output_tcp);appptr->output_tcp = NULL;}
    if(appptr->output_trans) {free(appptr->output_trans);appptr->output_trans = NULL;}
 

    int i;
    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(appptr->ports[i]) {free(appptr->ports[i]); appptr->ports[i] = NULL;}
	}

    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(appptr->servers[i]) {free(appptr->servers[i]); appptr->servers[i] = NULL;}
	}

    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(appptr->clients[i]) {free(appptr->clients[i]); appptr->clients[i] = NULL;}
	}	
}

void
free_proto(struct proto * protoptr){

	logFile_write_message(&mylog, LOG_LEVEL_ALL,  LOG_FORMAT, "%s", "####free data protocol struct");
    if(protoptr->name) {free(protoptr->name);   protoptr->name = NULL;}
  
    int i;
    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(protoptr->get_fields[i]) {free(protoptr->get_fields[i]);  protoptr->get_fields[i] = NULL;}
	}

    for(i=0; i<MAX_FIELD_NUMBER; i++){
    	if(protoptr->output_name[i]) {free(protoptr->output_name[i]); protoptr->output_name[i] = NULL;}
	}	
}

