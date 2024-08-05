

#include <TLSClient.h>
#include <WiFi.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <mbedtls/debug.h>


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
    _status = TLSCLIENT_DISCONNECTED;
}

TLSClient::~TLSClient()
{
    stop();
}

int TLSClient::status()
{
    if(_status == TLSCLIENT_CONNECTING) //test if connected
    {
        int res = socketReady();
        if(res > 0) 
            _status = TLSCLIENT_CONNECTED;
        else if(res < 0) //error
            stop(); 
    }

    if(_status == TLSCLIENT_CONNECTED) //start handshake
    {
        int res = startHandshake();
        if(res > 0)
            _status = TLSCLIENT_HANDSHAKE_INPROGRESS;
        else if(res < 0)
            stop();
    }

    if(_status == TLSCLIENT_HANDSHAKE_INPROGRESS) //test if handshake complete
    {
        int res = handshakeComplete();
        if(res > 0)
            _status = TLSCLIENT_HANDSHAKE_COMPLETE;
        else if(res < 0)
            stop();
    }

    if(_status == TLSCLIENT_HANDSHAKE_COMPLETE) //test is still alive
    {
        int res = mbedtls_ssl_read(&ssl, NULL, 0);    
        if (res < 0 && res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) 
        {
            print_error(res);
            log_e("fd %d mbedtls_ssl_read() failed %d", _sockfd, res);
            stop();
        }
    }

    return _status;
}


int TLSClient::socketReady()
{

    fd_set fdset;
    struct timeval tv;
    FD_ZERO(&fdset);
    FD_SET(_sockfd, &fdset);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    
    int res = select(_sockfd + 1, nullptr, &fdset, nullptr, &tv);
    if (res < 0) 
    {
        log_e("fd %d select() errno %d, \"%s\"", _sockfd, errno, strerror(errno));
        return -1;
    } 
    else if (res == 0) 
    {
        // log_v("fd %d select() 0", _sockfd);
        return 0;
    } 
    else 
    {
        int sockerr;
        socklen_t len = (socklen_t)sizeof(int);
        int res2 = getsockopt(_sockfd, SOL_SOCKET, SO_ERROR, &sockerr, &len);

        if (res2 < 0) 
        {
            log_e("fd %d getsockopt() errno %d, \"%s\"", _sockfd, errno, strerror(errno));
            return -1;
        }

        if (sockerr != 0) 
        {
            log_e("fd %d socket errno: %d, \"%s\"", _sockfd, sockerr, strerror(sockerr));
            return -1;
        }

        log_d("fd %d select() %d socket connected %dms", _sockfd, res, millis()-_connstarted);
        return 1;
    }

}

int TLSClient::startHandshake()
{
    if(_status != TLSCLIENT_CONNECTED)
        return -1;

    int res = 0;
    if( ( res = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        print_error(res);
        log_e( "fd %d mbedtls_ssl_config_defaults() failed %d", _sockfd, res);
        return -1;
    }

    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE ); //insecure!
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );

    if( ( res = mbedtls_ssl_set_hostname( &ssl, _host )) != 0 )
    {
        print_error(res);
        log_e( "fd %d mbedtls_ssl_set_hostname() failed %d", _sockfd, res);
        return -1;
    }

    if ((res = mbedtls_ssl_setup(&ssl, &conf)) != 0) 
    {
        print_error(res);
        log_e( "fd %d mbedtls_ssl_setup() failed %d", _sockfd, res);
        return -1;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd.fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    log_d("fd %d starting handshake", _sockfd);
    res = mbedtls_ssl_handshake(&ssl);
    if(res == 0)
    {
        return 1;
    }
    else if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) 
    {
        print_error(res);
        log_e( "fd %d mbedtls_ssl_handshake() failed %d", _sockfd, res);
        return -1;
    }
    
    return 1;
}

int TLSClient::handshakeComplete()
{
    if(_status != TLSCLIENT_HANDSHAKE_INPROGRESS)
        return -1;

    int res = -1;
    res = mbedtls_ssl_handshake(&ssl);
    if(res == 0)
    {
        log_d("fd %d handshake complete, tls ready %dms", _sockfd, millis()-_connstarted);
        return 1;
    }
    else if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) 
    {
        print_error(res);
        log_e( "fd %d mbedtls_ssl_handshake() failed %d", _sockfd, res);
        return -1;
    }

    return 0;
}

/*
void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    const char *p, *basename;
    (void) ctx;

    //Extract basename from file
    for(p = basename = file; *p != '\0'; p++) {
        if(*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
}
*/

int TLSClient::connectAsync(IPAddress ip, uint16_t port)
{
    
    if(_sockfd > -1)
        stop();

    _connstarted = millis();
    _peek = -1;

    _hostIP = ip;
    _port = port;
    if(_host[0]=='\0')
        strncpy(_host, _hostIP.toString().c_str(), sizeof(_host));

    log_d("starting tls connection to %s:%d", _host, _port);
    
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );

	// mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
    // mbedtls_debug_set_threshold(5);

    int res = -1;
    const char* pers = "esp32_tls";
    mbedtls_entropy_init( &entropy );
    if( ( res = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        print_error(res);
        log_e( "mbedtls_entropy_init() failed %d", res);
        stop();
        return 0;
    }

    _sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (_sockfd < 0) 
    {
        log_e("failed to create socket errno %d", errno);
        return 0;
    }

    fcntl( _sockfd, F_SETFL, fcntl( _sockfd, F_GETFL, 0 ) | O_NONBLOCK );
    uint32_t ip_addr = ip;
    struct sockaddr_in serveraddr;
    memset((char *) &serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    memcpy((void *)&serveraddr.sin_addr.s_addr, (const void *)(&ip_addr), 4);
    serveraddr.sin_port = htons(port);

    res = lwip_connect(_sockfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
    if (res < 0 && errno != EINPROGRESS) 
    {
        log_e("fd %d lwip_connect() errno: %d, \"%s\"", _sockfd, errno, strerror(errno));
        return 0;
    }

    _status = TLSCLIENT_CONNECTING;
    server_fd.fd = _sockfd;
    return 1;
}

int TLSClient::connectAsync(const char *host, uint16_t port)
{
    if(host==NULL)
    {
        log_e("cant connect to null host!");
        return 0;
    }

    IPAddress srv((uint32_t)0);
    if(!WiFiGenericClass::hostByName(host, srv)){
        return 0;
    }

    strncpy(_host, host, sizeof(_host));
    return connectAsync(srv, port);
}

int TLSClient::connect(IPAddress ip, uint16_t port)
{
    if(!connectAsync(ip, port))
        return 0;
    
    while (status() != TLSCLIENT_HANDSHAKE_COMPLETE && status() != TLSCLIENT_DISCONNECTED)
    {   
        if(millis() - _connstarted > _timeout)
        {
            log_e("fd %d connection timeout", _sockfd);
            stop();
            return 0;
        }

        delay(10);
    }
    
    return status()==TLSCLIENT_HANDSHAKE_COMPLETE;
}

int TLSClient::connect(const char *host, uint16_t port)
{
    if(host==NULL)
    {
        log_e("cant connect to null host!");
        return 0;
    }

    IPAddress srv((uint32_t)0);
    if(!WiFiGenericClass::hostByName(host, srv)){
        return 0;
    }

    strncpy(_host, host, sizeof(_host));
    return connect(srv, port);
}

size_t TLSClient::write(uint8_t b)
{
    return write(&b, 1);
}

size_t TLSClient::write(const uint8_t *buf, size_t size)
{
    if(status() != TLSCLIENT_HANDSHAKE_COMPLETE)
        return -1;

    if(!size)
        return 0;

    uint32_t start = millis();
    int res = -1;
    while ((res = mbedtls_ssl_write(&ssl, buf, size)) <= 0) 
    {
        if (res < 0 && res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) 
        {
            print_error(res);
            log_e("fd %d mbedtls_ssl_write() failed %d", _sockfd, res); //
            stop();
            return -1;
        }

        if(millis()-start > _timeout) 
        {
            log_w("fd %d mbedtls_ssl_write() %d aborting due to timeout", _sockfd, res);
            return -1;
        }
        
        // log_v("fd %d mbedtls_ssl_write() %d, trying again in 10ms", _sockfd, res);
        delay(10);
    }

    return res;
}

int TLSClient::available()
{
    if(status() != TLSCLIENT_HANDSHAKE_COMPLETE)
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
        log_e("fd %d mbedtls_ssl_read() failed %d", _sockfd, res);
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

    if(status() != TLSCLIENT_HANDSHAKE_COMPLETE)
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
        if (res < 0 && res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) 
        {
            print_error(res);
            log_e("fd %d mbedtls_ssl_read() failed %d", _sockfd, res);
            stop();
            return -1;
        }

        if(hasPeek)
            return 1;

        if(millis()-start > _timeout) 
        {
            log_w("fd %d mbedtls_ssl_read() %d aborting due to timeout", _sockfd, res);
            return -1;
        }
        
        // log_v("fd %d mbedtls_ssl_read() %d, trying again in 10ms", _sockfd, res);
        delay(10);
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
    if(_sockfd > -1)
    {
        log_d("fd %d cleaning tls session", _sockfd);
        close(_sockfd);
        _sockfd = -1;
        _host[0] = '\0';
        _peek = -1;
        _connstarted = 0;
        mbedtls_net_free( &server_fd );
        mbedtls_ssl_free( &ssl );
        mbedtls_ssl_config_free( &conf );
        mbedtls_ctr_drbg_free( &ctr_drbg );
        mbedtls_entropy_free( &entropy );
    }

    _status = TLSCLIENT_DISCONNECTED;
}

uint8_t TLSClient::connected()
{   
    return status() == TLSCLIENT_HANDSHAKE_COMPLETE;
}
















