

#include <TLSClient.h>
#include <WiFi.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>


static int _print_error(int err, const char * function, int line)
{
    // if(err == -30848){
    //     return err;
    // }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    log_e("(%d) %s", err, error_buf);
#else
    log_e("code %d", err);
#endif
    return err;
}

#define print_error(e) _print_error(e, __FUNCTION__, __LINE__)


TLSClient::TLSClient()
{
    setTimeout(TLSCLIENT_TIMEOUT_DEFAULT);
    _host[0] = '\0';
}

TLSClient::~TLSClient()
{
    stop();
}

int TLSClient::socketReady()
{

    if(_sockedfd < 0)
        return -1;

    fd_set fdset;
    struct timeval tv;
    FD_ZERO(&fdset);
    FD_SET(_sockedfd, &fdset);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    
    int res = select(_sockedfd + 1, nullptr, &fdset, nullptr, &tv);
    if (res < 0) 
    {
        log_e("select() fd %d errno %d, \"%s\"", _sockedfd, errno, strerror(errno));
        return -1;
    } 
    else if (res == 0) 
    {
        log_v("select() ret to prevent blocking fd %d", _sockedfd);
        return 0;
    } 
    else 
    {
        int sockerr;
        socklen_t len = (socklen_t)sizeof(int);
        int res2 = getsockopt(_sockedfd, SOL_SOCKET, SO_ERROR, &sockerr, &len);

        if (res2 < 0) 
        {
            log_e("getsockopt() fd %d errno %d, \"%s\"", _sockedfd, errno, strerror(errno));
            return -1;
        }

        if (sockerr != 0) 
        {
            log_e("socket error fd %d errno: %d, \"%s\"", _sockedfd, sockerr, strerror(sockerr));
            return -1;
        }
    }

    log_d("select() fd %d ret %d, socket is ready?", _sockedfd, res);
    return 1;

}

int TLSClient::timedConnect(IPAddress ip, int port, int timeout)
{
    uint32_t start = millis();

    _sockedfd = socket(AF_INET, SOCK_STREAM, 0);
    if (_sockedfd < 0) 
    {
        log_e("failed to create socket fd %d", errno);
        return -1;
    }

    fcntl( _sockedfd, F_SETFL, fcntl( _sockedfd, F_GETFL, 0 ) | O_NONBLOCK );

    uint32_t ip_addr = ip;
    struct sockaddr_in serveraddr;
    memset((char *) &serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    memcpy((void *)&serveraddr.sin_addr.s_addr, (const void *)(&ip_addr), 4);
    serveraddr.sin_port = htons(port);

    int res = lwip_connect(_sockedfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

    if (res < 0 && errno != EINPROGRESS) 
    {
        log_e("lwip_connect() fd %d errno: %d, \"%s\"", _sockedfd, errno, strerror(errno));
        return -1;
    }

    while (true)
    {
        res = socketReady();
        if(res > 0)
        {
            return _sockedfd;
        }
        else if(res==0)
        {
            if(millis() - start > timeout)
            {
                log_e("aborted connection, timeout");
                return -1;
            }
        }
        else //error
        {
            log_e("connection failed, err");
            return -1;
        }

        log_v("waiting for connection, sleeping 100ms");
        delay(100);
    }

    return -1;
}

int TLSClient::connect(const char *host, uint16_t port)
{
    if(_sockedfd > -1)
        stop();

    if(host==NULL)
    {
        log_e("aborted connection, host is null");
        return 0;
    }

    if(strlen(host)+1 > sizeof(_host))
    {
        log_e("host len > %d not allowed", sizeof(_host));
        return 0;
    }
    
    IPAddress srv((uint32_t)0);
    if(!WiFiGenericClass::hostByName(host, srv)){
        return 0;
    }

    strncpy(_host, host, sizeof(_host));
    return connect(srv, port);
}

int TLSClient::connect(IPAddress ip, uint16_t port)
{
    if(_sockedfd > -1)
        stop();

    _hostIP = ip;
    _port = port;

    if(_host[0]=='\0')
        strncpy(_host, _hostIP.toString().c_str(), sizeof(_host));

    log_d("starting tls connection to %s:%d", _host, _port);

    if(_timeout < 1000)
    {
        log_w("timeout cannot be < 1000ms");
        _timeout = 1000;
    }

    uint32_t start = millis();

    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    int res = 0;
    const char* pers = "esp32_tls";
    mbedtls_entropy_init( &entropy );
    if( ( res = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        print_error(res);
        log_e( "mbedtls_entropy_init() failed, res %d", res);
        stop();
        return 0;
    }
    
    if( (res = timedConnect(ip, port, _timeout)) < 0)
    {
        stop();
        return 0;
    }
    _sockedfd = res;
    server_fd.fd = res;

    // char c_port[32];
    // itoa(_port, c_port, 10);
    // if( ( res = mbedtls_net_connect( &server_fd, _host, c_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    // {
    //     handle_error(res);
    //     log_e( "mbedtls_net_connect() failed, res %d", res);
    //     stop();
    //     return 0;
    // }
    // _sockedfd = server_fd.fd;

    // if( ( res = mbedtls_net_set_nonblock(&server_fd)) != 0 )
    // {
    //     handle_error(res);
    //     log_e( "mbedtls_net_set_nonblock() failed, res %d", res);
    //     stop();
    //     return 0;
    // }
    
    log_d("tcp connected to the server %dms", millis()-start);

    if( ( res = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        print_error(res);
        log_e( "mbedtls_ssl_config_defaults() failed, res %d", res);
        stop();
        return 0;
    }

    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE ); //insecure!

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );

    if( ( res = mbedtls_ssl_set_hostname( &ssl, _host )) != 0 )
    {
        print_error(res);
        log_e( "mbedtls_ssl_set_hostname() failed, res %d", res);
        stop();
        return 0;
    }

    if ((res = mbedtls_ssl_setup(&ssl, &conf)) != 0) 
    {
        print_error(res);
        log_e( "mbedtls_ssl_setup() failed, res %d", res);
        stop();
        return 0;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd.fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    log_d("starting handshake", millis()-start);
    while ((res = mbedtls_ssl_handshake(&ssl)) != 0) 
    {
        if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) 
        {
            print_error(res);
            log_e( "mbedtls_ssl_handshake() failed, res %d", res);
            stop();
            return 0;
        }

        if( millis()-start > _timeout)
        {
            log_e("mbedtls_ssl_handshake() failed, timeout");
            stop();
            return 0;
        }
            
        vTaskDelay(2);//2 ticks
    }
    log_d("handshake complete, tls tunnel ready %dms", millis()-start);

    return 1;
}

size_t TLSClient::write(uint8_t b)
{
    return write(&b, 1);
}

size_t TLSClient::write(const uint8_t *buf, size_t size)
{
    if(_sockedfd < 0)
        return -1;

    if(!size)
        return 0;

    uint32_t start = millis();
    int res = -1;
    while ((res = mbedtls_ssl_write(&ssl, buf, size)) <= 0) 
    {
        if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE && res < 0) 
        {
            log_e("mbedtls_ssl_write() failed, res %d", res); //for low level debug
            stop();
            return -1;
        }

        if(millis()-start > _timeout) 
        {
            log_e("mbedtls_ssl_write() failed, timeout");
            stop();
            return -1;
        }
        
        log_v("mbedtls_ssl_write() ret %d, trying again in 100ms", res);
        delay(100);
    }

    return res;
}

int TLSClient::available()
{
    if(_sockedfd < 0)
        return 0;
    /**
     * https://www.esp32.com/viewtopic.php?t=1101
     * 
     * "
     * This is partially a restriction in the design of mbedTLS, and partially a restriction in the design/necessities of the TLS protocol. 
     * Data has to be received via the underlying plain TCP socket, then full TLS messages have to be decrypted, and then that data is available to read back into the user program.
     * 
     * So data can be waiting up to 3 places: unread on the TCP socket, read on the TCP socket but not yet decrypted (because a full TLS message hasn't arrived), 
     * or decrypted and available to read back into the user program.
     * 
     * "mbedtls_ssl_get_bytes_avail() " gives you the last of these counts (already decrypted data), but can only account for decrypted messages. Calling this doesn't 
     * cause any data to be read from the TCP socket or decrypted.
     * 
     * I believe you call call mbedtls_ssl_read(ssl, NULL, 0) and then mbedtls_ssl_get_bytes_avail(ssl). The first call will try to read from the socket 
     * and process/decrypt incoming data if possible. Then the second call will return the number of decrypted bytes which would have been available to read after the first call.
     * "
     * 
     */

    int res = mbedtls_ssl_read(&ssl, NULL, 0); 
    if (res < 0 && res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) 
    {
        print_error(res);
        log_e("mbedtls_ssl_read() failed, res %d", res);
        stop();
        return 0;
    }

    if(_peek > -1)
        return mbedtls_ssl_get_bytes_avail(&ssl)+1;
    else
        return mbedtls_ssl_get_bytes_avail(&ssl);
}

int TLSClient::read()
{
    uint8_t b = 0;
    if(read(&b, 1)>0)
        return b;
    return -1;
}

int TLSClient::read(uint8_t *buf, size_t size)
{

    if(_sockedfd < 0)
        return -1;

    if(!size)
        return 0;
    
    int hasPeek = 0;
    if( _peek > -1)
    {
        buf[0] = _peek;
        _peek = -1;
        size--;
        buf++;
        hasPeek = 1;
        if(!size)
            return 1;
    }

    uint32_t start = millis();
    int res = -1;
    while ((res = mbedtls_ssl_read(&ssl, buf, size)) <= 0) 
    {
        if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE && res < 0) 
        {
            print_error(res);
            log_e("mbedtls_ssl_read() failed, res", res);
            stop();
            return -1;
        }

        if(hasPeek)
            return 1;

        if(millis()-start > _timeout) 
        {
            log_e("mbedtls_ssl_read() failed, timeout");
            stop();
            return -1;
        }
        
        log_v("mbedtls_ssl_read() ret %d, trying again in 100ms", res);
        delay(100);
    }

    return res+hasPeek;
}

int TLSClient::peek()
{
    if(_peek>-1)
        return _peek;
    
    if(available() > 0)
    {
        _peek = read();
        return _peek;
    }

    return -1;
}

void TLSClient::flush()
{
    log_w("flush() not implemented");
}

void TLSClient::stop()
{
    log_d("cleaning tls session");
    _sockedfd = -1;
    _host[0] = '\0';
    close(server_fd.fd);
    mbedtls_net_free( &server_fd );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    
}

uint8_t TLSClient::connected()
{
    if(_sockedfd < 0)
        return 0;

    int res = mbedtls_ssl_read(&ssl, NULL, 0);    
    if (res < 0 && res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) 
    {
        print_error(res);
        log_e("mbedtls_ssl_read() failed, res %d", res);
        stop();
        return 0;
    }
    
    return 1;
}
















