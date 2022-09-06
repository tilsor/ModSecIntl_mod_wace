// This implements the necessary functions to talk to the WACE gRPC server

#include "grpc_client.hpp"

#include <string>

#include "grpcpp/grpcpp.h"

#include "wace.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using waceproto::SendRequestParams;
using waceproto::SendRequestResult;
using waceproto::SendReqLineAndHeadersParams;
using waceproto::SendReqLineAndHeadersResult;
using waceproto::SendRequestBodyParams;
using waceproto::SendRequestBodyResult;
using waceproto::SendResponseParams;
using waceproto::SendResponseResult;
using waceproto::SendRespLineAndHeadersParams;
using waceproto::SendRespLineAndHeadersResult;
using waceproto::SendResponseBodyParams;
using waceproto::SendResponseBodyResult;
using waceproto::CheckParams;
using waceproto::CheckResult;



//--TODO list:
//- Proper error handling
//- Channel needs to be created every time, or reuse the same instance?
//- Change the protobuff to receive the request headers as char ** ??
//- gRPC channel secure?

struct returnStatus{
  int grpc_status_code;
  std::string grpc_status_message;
  int wace_status_code;
};

class WaceClient {
 public:
  WaceClient(std::shared_ptr<Channel> channel)
      : stub_(waceproto::WaceProto::NewStub(channel)) {}

  // Assembles client payload, sends it to the server, and returns its response
  returnStatus sendRequest(char * transactId, std::string req, char ** modelsId, int modelNumber   ) {
       
    // Data to be sent to server
    SendRequestParams request;
    request.set_transact_id(transactId);
    request.set_request(req);
    for (int i=0; i<modelNumber; i++){
        request.add_model_id(modelsId[i]);
    }

    // Container for server response
    SendRequestResult reply;
    // Context can be used to send meta data to server or modify RPC behaviour
    ClientContext context;

    // Actual Remote Procedure Call
    Status status = stub_->SendRequest(&context, request, &reply);

    returnStatus res;
    res.grpc_status_code = status.error_code();
    res.grpc_status_message = status.error_message();
    res.wace_status_code = reply.status_code();
   
    return res;
  }

  returnStatus sendReqLineAndHeaders(char * transactID, char * reqLine, std::string reqHeaders, char ** modelsId, int modelNumber){
    SendReqLineAndHeadersParams requestData;
    requestData.set_transact_id(transactID);
    requestData.set_req_line(reqLine);
    requestData.set_req_headers(reqHeaders);
    for (int i=0; i<modelNumber; i++){
        requestData.add_model_id(modelsId[i]);
    }

    SendReqLineAndHeadersResult result;
    ClientContext context;
    Status status= stub_->SendReqLineAndHeaders(&context,requestData,&result);
   
    returnStatus res;
    res.grpc_status_code = status.error_code();
    res.grpc_status_message = status.error_message();
    res.wace_status_code = result.status_code();
   
    return res;
  }

  returnStatus sendRequestBody(char * transactID, char * body, char ** modelsId, int modelNumber){
    SendRequestBodyParams requestData;
    requestData.set_transact_id(transactID);
    requestData.set_body(body);
    for (int i=0; i<modelNumber; i++){
        requestData.add_model_id(modelsId[i]);
    }

    SendRequestBodyResult result;
    ClientContext context;
    Status status= stub_->SendRequestBody(&context,requestData,&result);
    
    returnStatus res;
    res.grpc_status_code = status.error_code();
    res.grpc_status_message = status.error_message();
    res.wace_status_code = result.status_code();
   
    return res;
  }

  returnStatus sendResponse(char * transactID, char * response, char ** modelsId, int modelNumber){
    SendResponseParams responseData;
    responseData.set_transact_id(transactID);
    responseData.set_response(response);
    for (int i=0; i<modelNumber; i++){
        responseData.add_model_id(modelsId[i]);
    }

    SendResponseResult result;
    ClientContext context;
    Status status= stub_->SendResponse(&context,responseData,&result);
    // Returns results based on RPC status
    returnStatus res;
    res.grpc_status_code = status.error_code();
    res.grpc_status_message = status.error_message();
    res.wace_status_code = result.status_code();
   
    return res;
  }

  returnStatus sendRespLineAndHeaders(char * transactID, char * statusLine, std::string respHeaders, char ** modelsId, int modelNumber){
    SendRespLineAndHeadersParams responseData;
    responseData.set_transact_id(transactID);
    responseData.set_status_line(statusLine);
    responseData.set_resp_headers(respHeaders);
    for (int i=0; i<modelNumber; i++){
        responseData.add_model_id(modelsId[i]);
    }

    SendRespLineAndHeadersResult result;
    ClientContext context;
    Status status= stub_->SendRespLineAndHeaders(&context,responseData,&result);
    
    returnStatus res;
    res.grpc_status_code = status.error_code();
    res.grpc_status_message = status.error_message();
    res.wace_status_code = result.status_code();
   
    return res;
  }
  
  returnStatus sendResponseBody(char * transactID, char * body, char ** modelsId, int modelNumber){
    SendResponseBodyParams responseData;
    responseData.set_transact_id(transactID);
    responseData.set_body(body);
    for (int i=0; i<modelNumber; i++){
        responseData.add_model_id(modelsId[i]);
    }

    SendResponseBodyResult result;
    ClientContext context;
    Status status= stub_->SendResponseBody(&context,responseData,&result);
    
    returnStatus res;
    res.grpc_status_code = status.error_code();
    res.grpc_status_message = status.error_message();
    res.wace_status_code = result.status_code();
   
    return res;
  }
  
  returnStatus check(char * transactID, char * decisionID, std::map<std::string,std::string> wafParams,CheckResult * rpcResults){
    CheckParams checkData;
    checkData.set_transact_id(transactID);
    checkData.set_decision_id(decisionID);
    auto wafmap = checkData.mutable_waf_params();
   
    
    std::map<std::string, std::string>::iterator it;

    for (it = wafParams.begin(); it != wafParams.end(); it++){
      wafmap->insert(google::protobuf::MapPair<std::string, std::string>(it->first,it->second));
    }
    CheckResult result;
    ClientContext context;
    Status status= stub_->Check(&context,checkData,&result);
    *rpcResults = result; // return the result of the call
    
    // Returns results based on RPC status
    returnStatus res;

    res.grpc_status_code = status.error_code();
    res.grpc_status_message = status.error_message();
    res.wace_status_code = result.status_code();

    return res;
  }

 private:
  std::unique_ptr<waceproto::WaceProto::Stub> stub_;
}; 

int main (){
  return 0;
}

extern "C" {
  // C Functions
  int SendRequest(const char * grpcServerUrl, char * transaction_id, char * req_line, char ** req_headers,int req_header_count, char * body, char ** models_id, int number_of_models, char * *returnMsg){
    // Instantiates the client
    WaceClient client(grpc::CreateChannel(grpcServerUrl, grpc::InsecureChannelCredentials()));
    //concatenate req line, headers and body into one string 
    std::string req = std::string(req_line) + "\n";
    for(int i=0;i<req_header_count;i++){
      req = req + "\n" + std::string(req_headers[i]);
    }
    if (body != NULL){
      req = req + "\n" + std::string(body);
    }
    
    returnStatus status = client.sendRequest(transaction_id,req,models_id,number_of_models);
    //Copy status message to the returnMsg param
    *returnMsg = new char[strlen(&status.grpc_status_message[0])+1];
    sprintf(*returnMsg, "%s", &status.grpc_status_message[0]);
    
    if (status.grpc_status_code != 0){//there was an error with the rpc call  
      return -1;
    }
    return status.wace_status_code;
  }
 
  int SendReqLineAndHeaders(const char * grpcServerUrl, char * transaction_id, char * req_line, char ** req_headers,int req_header_count, char ** models_id, int number_of_models, char * *returnMsg){
    // Instantiates the client
    std::string msg;
    std::shared_ptr<grpc::Channel> chan = grpc::CreateChannel(grpcServerUrl, grpc::InsecureChannelCredentials());

    WaceClient client(chan);
    //conctenate all the char ** req_headers into one string
    
    std::string allHeaders;
    for(int i=0;i<req_header_count;i++){
      if (i==0){
        allHeaders =  std::string(req_headers[i]);
      }else{
        allHeaders = allHeaders + "\n" + std::string(req_headers[i]);
      }
    }
    returnStatus status = client.sendReqLineAndHeaders(transaction_id,req_line,allHeaders, models_id, number_of_models);
    
    //Copy status message to the returnMsg param
    *returnMsg = new char[strlen(&status.grpc_status_message[0])+1];
    sprintf(*returnMsg,"%s", &status.grpc_status_message[0]);
    
    if (status.grpc_status_code != 0){//there was an error with the rpc call  
      return -1;
    }
    return status.wace_status_code;
  }

  int SendRequestBody(const char * grpcServerUrl, char * transactID, char * body, char ** modelsId, int modelNumber,  char * *returnMsg){
    // Instantiates the client
    WaceClient client(grpc::CreateChannel(grpcServerUrl, grpc::InsecureChannelCredentials()));
    
    returnStatus status = client.sendRequestBody(transactID,body,modelsId,modelNumber);
    sprintf(*returnMsg,"%s", &status.grpc_status_message[0]);
    
    if (status.grpc_status_code != 0){//there was an error with the rpc call  
      return -1;
    }
    return status.wace_status_code;
  }

  int SendResponse(const char * grpcServerUrl, char * transactID, char * response, char ** modelsId, int modelNumber,  char * *returnMsg){
    // Instantiates the client
    WaceClient client(grpc::CreateChannel(grpcServerUrl, grpc::InsecureChannelCredentials()));
  
    returnStatus status = client.sendResponse(transactID,response,modelsId,modelNumber);
    //Copy status message to the returnMsg param
    *returnMsg = new char[strlen(&status.grpc_status_message[0])+1];
    sprintf(*returnMsg,"%s", &status.grpc_status_message[0]);
    
    if (status.grpc_status_code != 0){//there was an error with the rpc call  
      return -1;
    }
    return status.wace_status_code;
  }

  int SendRespLineAndHeaders(const char * grpcServerUrl, char * transactID, char * statusLine,char ** respHeaders, int headerNumber, char ** modelsId, int modelNumber,  char * *returnMsg){
    // Instantiates the client
    WaceClient client(grpc::CreateChannel(grpcServerUrl, grpc::InsecureChannelCredentials()));
    
    std::string allHeaders;
    for(int i=0;i<headerNumber;i++){
      if (i==0){
        allHeaders =  std::string(respHeaders[i]);
      }else{
        allHeaders = allHeaders + "\n" + std::string(respHeaders[i]);
      }
    } 
    returnStatus status = client.sendRespLineAndHeaders(transactID,statusLine,allHeaders,modelsId,modelNumber);
    //Copy status message to the returnMsg param
    *returnMsg = new char[strlen(&status.grpc_status_message[0])+1];
    sprintf(*returnMsg,"%s", &status.grpc_status_message[0]);
    
    if (status.grpc_status_code != 0){//there was an error with the rpc call  
      return -1;
    }
    return status.wace_status_code;
  }

  int SendResponseBody(const char * grpcServerUrl, char * transactID, char * body, char ** modelsId, int modelNumber,  char * *returnMsg){
    // Instantiates the client
    WaceClient client(grpc::CreateChannel(grpcServerUrl, grpc::InsecureChannelCredentials()));
    
    returnStatus status = client.sendResponseBody(transactID,body,modelsId,modelNumber);
    //Copy status message to the returnMsg param
    *returnMsg = new char[strlen(&status.grpc_status_message[0])+1];
    sprintf(*returnMsg,"%s", &status.grpc_status_message[0]);
    
    if (status.grpc_status_code != 0){//there was an error with the rpc call  
      return -1;
    }
    return status.wace_status_code;
  }
  
  int Check(const char * grpcServerUrl, char * transactID, char * decisionID, WAFParams * wafParams, int numberWAFParams, int *blockTransaction, char * *waceMsg, char * *returnMsg){
    // Instantiates the client
    WaceClient client(grpc::CreateChannel(grpcServerUrl, grpc::InsecureChannelCredentials()));
    std::map<std::string,std::string> wafParamsMap;

    if (wafParams != NULL){
      for(int i=0; i<numberWAFParams; i++){
        wafParamsMap.insert(std::pair<std::string,std::string>(wafParams[i].key,wafParams[i].value));
      }
    }
    CheckResult res;
    returnStatus status = client.check(transactID, decisionID,wafParamsMap,&res);
    
    *blockTransaction = res.block_transaction();
    *waceMsg = new char[strlen(&res.msg()[0])+1];
    sprintf(*waceMsg,"%s", &res.msg()[0]);
    
    *returnMsg = new char[strlen(&status.grpc_status_message[0])+1];
    sprintf(*returnMsg,"%s", &status.grpc_status_message[0]);
    if (status.grpc_status_code != 0){//there was an error with the rpc call  
      return -1;
    }


    

    return status.wace_status_code;
  }
}
