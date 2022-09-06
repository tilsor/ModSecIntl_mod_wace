#ifndef MIXEDCCPP_H
#define MIXEDCCPP_H

#ifdef __cplusplus
extern "C" {
#endif
typedef struct WAFParamsStruct{
    char * key;
    char * value;
} WAFParams;

int SendRequest(const char * grpcServerUrl, char * transaction_id,  char * req_line, char ** req_headers,int req_header_count, char * body, char ** models_id, int number_of_models, char * *returnMsg);

int SendReqLineAndHeaders(const char * grpcServerUrl, char * transaction_id, char * req_line, char ** req_headers,int req_header_count, char ** models_id, int number_of_models, char * *returnMsg);

int SendRequestBody(const char * grpcServerUrl, char * transactID, char * body, char ** modelsId, int modelNumber, char * *returnMsg);

int SendResponse(const char * grpcServerUrl, char * transactID, char * response, char ** modelsId, int modelNumber, char * *returnMsg);

int SendRespLineAndHeaders(const char * grpcServerUrl, char * transactID, char * statusLine, char ** respHeaders, int headerNumber, char ** modelsId, int modelNumber, char * *returnMsg);

int SendResponseBody(const char * grpcServerUrl, char * transactID, char * body, char ** modelsId, int modelNumber, char * *returnMsg);
  
int Check(const char * grpcServerUrl, char * transactID, char * decisionID, WAFParams * wafParams, int numberWAFParams, int *blockTransaction,  char * *waceMsg, char * *returnMsg);

#ifdef __cplusplus
}
#endif

#endif // MIXEDCCPP_H
