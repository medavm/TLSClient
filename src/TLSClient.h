

#pragma once


#include <Arduino.h>

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"


#define TLSCLIENT_TIMEOUT_DEFAULT 1000l*5


#define TLSCLIENT_CONNECTING 1
#define TLSCLIENT_CONNECTED 2
#define TLSCLIENT_HANDSHAKE_INPROGRESS 3
#define TLSCLIENT_HANDSHAKE_COMPLETE 4
#define TLSCLIENT_DISCONNECTED 5

class TLSClient : public Client
{

public:
    TLSClient(/* args */);
    ~TLSClient();

    int connect(IPAddress ip, uint16_t port);
    int connect(const char *host, uint16_t port);
    int connectAsync(IPAddress ip, uint16_t port);
    int connectAsync(const char *host, uint16_t port);
    
    size_t write(uint8_t);
    size_t write(const uint8_t *buf, size_t size);
    int available();
    int read();
    int read(uint8_t *buf, size_t size);
    int peek();
    void flush();
    void stop();
    uint8_t connected();
    operator bool() {return connected();}

    /**
     * TLSCLIENT_CONNECTING             -> waiting for connection
     * TLSCLIENT_CONNECTED              -> tcp connection established
     * TLSCLIENT_HANDSHAKE_INPROGRESS   -> tls handshake in progress
     * TLSCLIENT_HANDSHAKE_COMPLETE     -> handshake success, tls client ready to use
     * TLSCLIENT_DISCONNECTED           -> disconnected
     * 
     */
    int status();


private:


    IPAddress _hostIP;
    char _host[256];
    int _port;

    int _status = TLSCLIENT_DISCONNECTED;

    int _sockfd = -1;
    int _peek = -1;

    uint32_t _connstarted = 0;

    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;


    int socketReady();
    int startHandshake();
    int handshakeComplete();

};