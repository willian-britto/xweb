


void xquotes_web_init (void) {

    // INITIALIZE THE SSL LIBRARY
    wolfSSL_Init();
    
    // CREATE THE SSL CONTEXT
    sslCtx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    wolfSSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, NULL);
    wolfSSL_SetIORecv(sslCtx, (CallbackIORecv)xweb_ssl_read);
    wolfSSL_SetIOSend(sslCtx, (CallbackIOSend)xweb_ssl_write);

}
