
static WOLFSSL_CTX* sslCtx;

static uint sslInSize;
static void* sslInStart;
static uint sslOutFree;
static void* sslOutEnd;

// PUXA O ENCRIPTADO DO sslIn, E PASSA PARA O WOLFSSL
static int xweb_ssl_read (void* const restrict ign __unused, void* const restrict buff, uint size, void* const restrict ign2 __unused) {

    if (size > sslInSize)
        size = sslInSize;

    if (size == 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;

    memcpy(buff, sslInStart, size);

    sslInStart += size;
    sslInSize -= size;

    return size;
}

// RECEBE O ENCRIPTADO DO WOLFSSL, E POE NO BUFFER DE SAÍDA
static int xweb_ssl_write (void* const restrict ign __unused, const void* restrict buff, const uint size, Conn* const restrict conn) {

    uint remaining = size;

    while (remaining) {
        if (sslOutFree) {

            uint consume = remaining;

            if (consume > sslOutFree)
                consume = sslOutFree;

            memcpy(sslOutEnd, buff, consume); // TODO: FIXME: PODE SER ALINHADO

            sslOutEnd  += consume;
            buff       += consume;
            remaining  -= consume;
            sslOutFree -= consume;

        } else {

            uint alloced = 1*1024*1024;

            if (alloced < remaining)
                alloced = remaining + 1024;

            Out* const out = malloc(sizeof(Out) + alloced);

            out->type = OUT_TYPE_SIZED;
            out->size = alloced;
            out->start = out->buff;
            out->next = NULL;

            if (conn->sslOut_)
                conn->sslOut_->next = out;
            else
                conn->sslOut = out;
            conn->sslOut_ = out;

            sslOutEnd = out->buff;
            sslOutFree = alloced;
        }
    }

    return size;
}

void xweb_ssl_init (void) {

    // INITIALIZE THE SSL LIBRARY
    wolfSSL_Init();

    // CREATE THE SSL CONTEXT
    sslCtx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    wolfSSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, NULL);
    wolfSSL_SetIORecv(sslCtx, (CallbackIORecv)xweb_ssl_read);
    wolfSSL_SetIOSend(sslCtx, (CallbackIOSend)xweb_ssl_write);

}
