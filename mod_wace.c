#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_optional.h"
#include <string.h>
#include "modsecurity/modsecurity.h"
#include "modsecurity/re.h"
#include "modsecurity/msc_logging.h"
#include "grpc_client.hpp"

#define ALPHABET_SIZE       256


#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(wace);
#endif 
// ---TODOS list:
// - Add grpc server port as a config parameter of mod_wace  with context awarenes
// - Check why SELinux detects something?
// - WAF params how to pass it from the CRS.
// - Better error checking.
// - See when to match or not the rule. (excluding the check call of the operator)

typedef struct {
   const char * grpcServerURL; //The wace grpc server URL
} module_config;

static module_config config;
/**
 * Operator parameter initialization entry point.
 */
static int wace_init(msre_rule *rule, char **error_msg) {
    /* We just look for a non-empty parameter. */
    if ((rule->op_param == NULL)||(strlen(rule->op_param) == 0)) {
        *error_msg = apr_psprintf(rule->ruleset->mp, "Missing parameter for operator 'wace'.");
        return 0; /* ERROR */
    }
    rule->op_param_data = apr_pcalloc(rule->ruleset->mp, ALPHABET_SIZE * sizeof(int));//the param data
    /* OK */
    return 1;
}

// Auxiliary list to make the modelId string Array and headers Array
typedef struct StringListStruct{
        char * value;
        struct StringListStruct* next;
} StringList;

/**
 * Operator execution entry point.
 */
static int wace_exec(modsec_rec *msr, msre_rule *rule, msre_var *var, char **error_msg) {
	 if (config.grpcServerURL == NULL){
        *error_msg = apr_psprintf(rule->ruleset->mp, "No WACE server url configured in mod_wace. Please configure the url using the WaceServerUrl directive");
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace: No WACE server url configured. Please configure the url using the WaceServerUrl directive");
        return 1; /* ERROR */
    }

    char * call_type = (char *)rule->op_param;
    char * transact_id = msr->txid;
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:start,%s,%"APR_TIME_T_FMT,transact_id,call_type,apr_time_now());

    /*char * time = apr_palloc(msr->mp,APR_CTIME_LEN);
    apr_ctime (time,msr->request_time); 		
    apr_time_exp_t * time_e = apr_palloc(msr->mp,sizeof(apr_time_exp_t));
    apr_time_exp_lt (time_e,msr->request_time);
    */
    //ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace: Time %d:%d:%d.%d",time_e->tm_hour,time_e->tm_min,time_e->tm_sec,time_e->tm_usec);
    //ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace_time: %d",msr->request_time);
    //ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace_NOW: %d",apr_time_now());
    
    char ** models_list = NULL;
    int model_count=0;
    if(strcmp(call_type, "check") != 0){//if check there is no need of the models id
        //Split of the csv value models_id into an array of models_id
        msc_string* a = apr_table_get(msr->tx_vars,"models_id");//Get models id from ModSecurity TX.VAR

        //--Move the string handling to the C++ API?
        char *models_id=a->value;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,msr->r,"mod_wace: Models id read from ModSecurity - %s",a->value);
        
       
        if ((models_id != NULL) || strcmp(models_id, "") != 0){
            StringList * ml = apr_palloc(msr->mp,sizeof(StringList));
            ml->next = NULL;
            StringList * mlHead = ml;

            char *token, *str;
            str = apr_pstrdup(msr->mp,models_id); // Duplicate of const char * models_id
            //split the tx.model_id line by the , and fill a list with the values
            while ((token = strsep(&str, ","))){
                model_count++;
                ml->value=token;
                ml->next=apr_palloc(msr->mp,sizeof(StringList));
                ml = ml->next;
                ml->next=NULL;
            }
            //iterate over the auxiliary list created previously and create an array of the appropiate size,
            //put the data from the list to the array
            ml = mlHead;
            models_list=apr_palloc(msr->mp,sizeof(char *)*model_count);
            for(int i=0;i<model_count;i++){
                models_list[i]=ml->value;
                mlHead=ml->next;
                ml= mlHead;
            }
        }
    }



    if (strcmp(call_type, "reqlineheaders") == 0){
        
        char * req_line = msr->request_line;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: The request line is - %s and the transact id - %s",req_line, transact_id);
        
        char ** wace_req_headers=NULL;

        StringList * hl = apr_palloc(msr->mp,sizeof(StringList));
        hl->next = NULL;
        StringList * hlHead = hl;
        int header_count=0;
        //converting the response headers form apr table to an auxiliary list
        const apr_array_header_t *arr = apr_table_elts(msr->request_headers);
        apr_table_entry_t *entries = (apr_table_entry_t *)arr->elts;
        for (int i = 0; i < arr->nelts; i++) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"Key: %s, Value: %s\n", entries[i].key, entries[i].val);
            char * header = apr_palloc(msr->mp,strlen(entries[i].key)+strlen(entries[i].val)+strlen(": ")+1);//+1 for the \0
            if(header != NULL){
                header[0] = '\0';   // ensures the memory is an empty string
                strcat(header,entries[i].key);
                strcat(header,": ");
                strcat(header,entries[i].val);
                header_count++;
                hl->value=header;
                hl->next=apr_palloc(msr->mp,sizeof(StringList));
                hl = hl->next;
                hl->next=NULL;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: Request Header -> %s",header);
            } else {
                *(const char **)apr_array_push(msr->alerts) = apr_pstrdup(msr->mp, "mod_wace: Error parsing request headers.\n");
                ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace: Error parsing request headers"); 
            }
        }
        
        //Creating the wace_req_headers array from the list of headers
        hl = hlHead;
        wace_req_headers=apr_palloc(msr->mp,sizeof(char *)*header_count);
        for(int i=0;i<header_count;i++){
            wace_req_headers[i]=hl->value;
            hlHead=hl->next;
            hl= hlHead;
        }
        
        //DEBUG, printing the list - delete later
        /*for (int j=0;j<header_count;j++){
         ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: <!>HEADER%d: %s hcount %d",j,wace_req_headers[j],header_count);
        }*/
        char * status_msg;
        //Calling the grpc client
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:start,reqlineheaders,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        int status_code = SendReqLineAndHeaders(config.grpcServerURL,transact_id,req_line, wace_req_headers,header_count,models_list,model_count,&status_msg);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,reqlineheaders,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
    
        char * log_msg = NULL;
        if (status_code!=0){//error with the rpc call
           log_msg = apr_psprintf(msr->mp,"mod_wace: Error sending request line and headers to WACE server. (Transaction ID - %s Status Code - %d Status Msg - %s).",transact_id, status_code,status_msg);
            *(const char **)apr_array_push(msr->alerts) = log_msg;//apr_pstrdup(msr->mp, log_msg);
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"%s",log_msg);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,reqlineheaders,%"APR_TIME_T_FMT,transact_id,apr_time_now());
            return 1; //Match the rule on error ?.
        }
        
        log_msg = apr_psprintf(msr->mp,"mod_wace: Request line and headers sent successfully to WACE server. (Transaction ID - %s Status Code - %d Status Msg - %s).",transact_id, status_code,status_msg);
        *(const char **)apr_array_push(msr->alerts) = log_msg;//apr_pstrdup(msr->mp, log_msg);
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"%s",log_msg);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,reqlineheaders,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        
        return status_code;

    } else if (strcmp(call_type, "reqbody") == 0){
        char * req_body = msr->msc_reqbody_buffer;
        char * log_msg = NULL;
        if (req_body != NULL){
            char * status_msg;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: Sending to WACE server Request Body - %s",req_body);
            
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:start,reqbody,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
            int status_code = SendRequestBody(config.grpcServerURL, transact_id,req_body,models_list,model_count,&status_msg);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,reqbody,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
           
            if (status_code!=0){
                log_msg = apr_psprintf(msr->mp,"mod_wace: Error sending request body to WACE server. Check WACE server logs for details (Transaction ID - %s Status Code - %d Status Message - %s).\n",transact_id, status_code, status_msg);
                *(const char **)apr_array_push(msr->alerts) = apr_pstrdup(msr->mp, log_msg);
                ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"%s",log_msg);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,reqbody,%"APR_TIME_T_FMT,transact_id,apr_time_now());
                return 1; //Match the rule on error ?.
            }
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,reqbody,%"APR_TIME_T_FMT,transact_id,apr_time_now());
            return status_code;
        }else{
            log_msg = apr_psprintf(msr->mp,"mod_wace: Warning-> wace operator called with reqbody parameter, but request body is NULL. Ignoring call");
            *(const char **)apr_array_push(msr->alerts) = log_msg;
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace: Warning-> wace operator called with reqbody parameter, but body is NULL. Ignoring call");
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,reqbody,%"APR_TIME_T_FMT,transact_id,apr_time_now());
            return 0;
        }
    } else if (strcmp(call_type, "resplineheaders") == 0){
        char * resp_line = msr->status_line;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: Sending to WACE server Response Line -> %s", resp_line);
        char ** wace_resp_headers=NULL;
        
        StringList * hl = apr_palloc(msr->mp,sizeof(StringList));
        hl->next = NULL;
        StringList * hlHead = hl;
        int header_count=0;
        //converting the response headers form apr table to an auxiliary list
        const apr_array_header_t *arr = apr_table_elts(msr->request_headers);
        apr_table_entry_t *entries = (apr_table_entry_t *)arr->elts;
        for (int i = 0; i < arr->nelts; i++) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"Key: %s, Value: %s\n", entries[i].key, entries[i].val);
            char * header = apr_palloc(msr->mp,strlen(entries[i].key)+strlen(entries[i].val)+strlen(": ")+1);//+1 for the \0
            if(header != NULL){
                header[0] = '\0';   // ensures the memory is an empty string
                strcat(header,entries[i].key);
                strcat(header,": ");
                strcat(header,entries[i].val);
                header_count++;
                hl->value=header;
                hl->next=apr_palloc(msr->mp,sizeof(StringList));
                hl = hl->next;
                hl->next=NULL;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: Request Header -> %s",header);
            } else {
                *(const char **)apr_array_push(msr->alerts) = apr_pstrdup(msr->mp, "mod_wace: Error parsing request headers.\n");
                ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace: Error parsing request headers"); 
            }
        }
        //Creating the wace_req_headers array from the list of headers
        hl = hlHead;
        wace_resp_headers=apr_palloc(msr->mp,sizeof(char *)*header_count);
        for(int i=0;i<header_count;i++){
            wace_resp_headers[i]=hl->value;
            hlHead=hl->next;
            hl= hlHead;
        }
        //DEBUG, printing the list
       /*for (int j=0;j<header_count;j++){
         ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace: <!>HEADER%d: %s",j,wace_resp_headers[j]);
        }*/
        char * status_msg;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:start,resplineheaders,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        //Calling the grpc client
        int status_code = SendRespLineAndHeaders(config.grpcServerURL, transact_id,resp_line, wace_resp_headers,header_count,models_list,model_count,&status_msg);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,resplineheaders,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        char * log_msg;
        if (status_code!=0){
                log_msg=apr_psprintf(msr->mp,"mod_wace: Error sending response status line and headers to WACE server. Check WACE server logs for details (Transaction ID - %s Status Code - %d Status Message - %s).\n",transact_id, status_code,status_msg);
                *(const char **)apr_array_push(msr->alerts) = apr_pstrdup(msr->mp, log_msg);
                ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"%s",log_msg);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,resplineheaders,%"APR_TIME_T_FMT,transact_id,apr_time_now());
                return 1; //Match the rule on error ?.
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,resplineheaders,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        return 1;
    } else if (strcmp(call_type, "respbody") == 0){
        char * resp_body = msr->resbody_data;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: Response Body -> %s",resp_body);
        char * status_msg;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:start,respbody,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        int status_code = SendResponseBody(config.grpcServerURL,transact_id,resp_body,models_list,model_count,&status_msg);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,respbody,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        char * log_msg;
        if (status_code!=0){
                log_msg = apr_psprintf(msr->mp,"mod_wace: Error sending response body to WACE server. Check WACE server logs for details (Transaction ID - %s Status Code - %d Status Message - %s).\n",transact_id, status_code, status_msg);
                *(const char **)apr_array_push(msr->alerts) = apr_pstrdup(msr->mp, log_msg);
                ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"%s",log_msg);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,respbody,%"APR_TIME_T_FMT,transact_id,apr_time_now());
                return 1; //Match the rule on error ?.
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,respbody,%"APR_TIME_T_FMT,transact_id, apr_time_now());
        return 1;
    } else if (strcmp(call_type, "request") == 0){
        
        char * req_line = msr->request_line;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: The request line is - %s and the transact id - %s",req_line, transact_id);
        
        char ** wace_req_headers=NULL;

        StringList * hl = apr_palloc(msr->mp,sizeof(StringList));
        hl->next = NULL;
        StringList * hlHead = hl;
        int header_count=0;
        //converting the response headers form apr table to an auxiliary list
        const apr_array_header_t *arr = apr_table_elts(msr->request_headers);
        apr_table_entry_t *entries = (apr_table_entry_t *)arr->elts;
        for (int i = 0; i < arr->nelts; i++) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"Key: %s, Value: %s\n", entries[i].key, entries[i].val);
            char * header = apr_palloc(msr->mp,strlen(entries[i].key)+strlen(entries[i].val)+strlen(": ")+1);//+1 for the \0
            if(header != NULL){
                header[0] = '\0';   // ensures the memory is an empty string
                strcat(header,entries[i].key);
                strcat(header,": ");
                strcat(header,entries[i].val);
                header_count++;
                hl->value=header;
                hl->next=apr_palloc(msr->mp,sizeof(StringList));
                hl = hl->next;
                hl->next=NULL;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: Request Header -> %s",header);
            } else {
                *(const char **)apr_array_push(msr->alerts) = apr_pstrdup(msr->mp, "mod_wace: Error parsing request headers.\n");
                ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace: Error parsing request headers"); 
            }
        }
        //Creating the wace_req_headers array from the list of headers
        hl = hlHead;
        wace_req_headers=apr_palloc(msr->mp,sizeof(char *)*header_count);
        for(int i=0;i<header_count;i++){
            wace_req_headers[i]=hl->value;
            hlHead=hl->next;
            hl= hlHead;
        }

        //getting the req body data
        char * req_body = msr->msc_reqbody_buffer;
        char * log_msg = NULL;
        char * status_msg;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: Sending to WACE server Request");
        
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:start,request,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        int status_code = SendRequest(config.grpcServerURL, transact_id,req_line,wace_req_headers,header_count,req_body,models_list,model_count,&status_msg);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,request,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        
        if (status_code!=0){
            log_msg = apr_psprintf(msr->mp,"mod_wace: Error sending request to WACE server. Check WACE server logs for details (Transaction ID - %s Status Code - %d Status Message - %s).\n",transact_id, status_code, status_msg);
            *(const char **)apr_array_push(msr->alerts) = apr_pstrdup(msr->mp, log_msg);
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"%s",log_msg);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,request,%"APR_TIME_T_FMT,transact_id,apr_time_now());
            return 1; //Match the rule on error ?.
        }  
        log_msg = apr_psprintf(msr->mp,"mod_wace: Request sent successfully to WACE server. (Transaction ID - %s Status Code - %d Status Msg - %s).",transact_id, status_code,status_msg);
        *(const char **)apr_array_push(msr->alerts) = log_msg;//apr_pstrdup(msr->mp, log_msg);
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"%s",log_msg);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,request,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        
        return status_code;

    }else if (strcmp(call_type, "check") == 0){
        char * log_msg;
        log_msg = apr_psprintf(msr->mp,"mod_wace: Checking transaction data in WACE server. (Transaction ID - %s).\n",transact_id);
        *(const char **)apr_array_push(msr->alerts) = apr_pstrdup(msr->mp, log_msg);
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"%s",log_msg);

        msc_string* decision_id = apr_table_get(msr->tx_vars,"decision_id");
        msc_string* anomaly_score = apr_table_get(msr->tx_vars,"anomaly_score");
        msc_string* inbound_score = apr_table_get(msr->tx_vars,"inbound_anomaly_score_threshold");
        //TODO: See how to pass the WAFParams from the CRS into this function call
        //array of WAFParams
        WAFParams * wparams = apr_palloc(msr->mp,sizeof(WAFParams)*2);
        wparams[0].key = "inbound_blocking";
        wparams[0].value = anomaly_score->value;
        wparams[1].key = "inbound_threshold";
        wparams[1].value = inbound_score->value;

        //return values of check call
        char * status_msg;
        char * wace_msg;
        int block_transact;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:start,check,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        int status_code = Check(config.grpcServerURL, transact_id,decision_id->value,wparams,2,&block_transact,&wace_msg, &status_msg);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,check,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        if (status_code == 0){
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace: Check result - Block transaction? %d, WACE Msg - %s, Status Msg - %s",block_transact,wace_msg,status_msg);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,check,%"APR_TIME_T_FMT",%"APR_TIME_T_FMT,transact_id,apr_time_now(),msr->request_time);
            return block_transact;
        }else{
            char * log_msg = NULL;
            log_msg = apr_psprintf(msr->mp,"mod_wace: Error checking transaction data in WACE server. Check WACE server logs for details (Transaction ID - %s Status Code - %d Status Message - %s Wace Message - %s ).\n",transact_id, status_code, status_msg,wace_msg);
            *(const char **)apr_array_push(msr->alerts) = apr_pstrdup(msr->mp, log_msg);
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"%s",log_msg);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:end,check,%,%"APR_TIME_T_FMT",%"APR_TIME_T_FMT,transact_id,apr_time_now(),msr->request_time);
            return 0; //Match the rule on error ?.
        }
    } else if (strcmp(call_type, "init") == 0) {
        char * status_msg;
        int error = Init(config.grpcServerURL,transact_id,&status_msg);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:start,init,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        return 1;

    } else if (strcmp(call_type, "close") == 0) {
        char * status_msg;
        int error = Close(config.grpcServerURL,transact_id,&status_msg);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, msr->r,"mod_wace_time[%s]:start,close,grpc,%"APR_TIME_T_FMT,transact_id,apr_time_now());
        return 1;

    } else {
        *error_msg = apr_psprintf(rule->ruleset->mp, "mod_wace: Unknown parameter passed to the wace operator, a valid parameter is needed.");
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, msr->r,"mod_wace: Unknown parameter passed to the wace operator, a valid parameter is needed.");
        return 1;
    }
}

static int hook_pre_config(apr_pool_t *mp, apr_pool_t *mp_log, apr_pool_t *mp_temp) {
    void (*fn)(const char *name, void *fn_init, void *fn_exec);

    // Look for the registration function exported by ModSecurity.
    fn = APR_RETRIEVE_OPTIONAL_FN(modsec_register_operator);
    if (fn) {
        //Register operation with the ModSec registration function 
        fn("wace", (void *)wace_init, (void *)wace_exec);
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, NULL,
            "mod_wace Unable to find modsec_register_operator.");
    }

    return OK;
}

static void register_hooks(apr_pool_t *p) {
    ap_hook_pre_config(hook_pre_config, NULL, NULL, APR_HOOK_LAST);
}
/* Handler for the "grpcServerUrl" directive */
const char *config_set_grpc_server(cmd_parms *cmd, void *cfg, const char *arg){
    config.grpcServerURL = arg;
    return NULL;
}
//for the configuraton parameters of the module
static const command_rec wace_configuration[] = {
    AP_INIT_TAKE1("WaceServerUrl", config_set_grpc_server, NULL, RSRC_CONF, "The URL and port of the WACE server"),
    { NULL }
};
/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA wace_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    wace_configuration,    /* table of config file commands       */
    register_hooks         /* register hooks                      */
};
