

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


class TLSClient : public Client
{

public:
    TLSClient(/* args */);
    ~TLSClient();

    //Client
    int connect(IPAddress ip, uint16_t port);
    int connect(const char *host, uint16_t port);
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



private:


    IPAddress _hostIP;
    char _host[256];
    int _port;

    int _sockfd = -1;
    int _peek = -1;
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;



    int timedConnect(IPAddress ip, int port, int timeout);
    int socketReady();

};