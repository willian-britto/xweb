
// TODO: FIXME: TIMEOUT SE NENHUMA MENSAGEM COMPLETA EM 50 SEGUNDOS - PELO MENOS UM PING, PONG ETC
// TODO: FIXME: SUPPORT FRAGMENTATION
static PyObject* xweb_PY_conn_ws_recv (void) {

    Conn* const conn = thread->conn;

    while (conn->in) { // TEM QUE SER LOOP, POIS ALGUMAS MENSAGENS COMO PING E PONG NAO SERAO CONSUMIDAS

        if (conn->in->start == conn->in->end) {
            xweb_conn_in_consumed(conn);
            continue;
        }

        if (conn->msgType == 0) { // OPCODE
            const uint opcode = *(u8*)conn->in->start++;
            if (opcode == CONN_MSG_TYPE_WS_CLOSE) {
                conn->poll = CONN_POLL_CLOSE;
                break; // NOTE: TEM QUE ESQUECER DO INPUT BUFFER A PARTIR DAQUI. RESPONSABILIDADE DO CALLER DE NAO CONSUMIR MAIS.
            }
            conn->msgType = opcode;
            conn->msgStarted = now;
        }

        if (conn->msgMore == 0) { // SIZE

            uint size; void* in = conn->in->start;

            if ((size = *(u8*)in++) == 126)
                { size = _to_be16(*(u16*)in); in += sizeof(u16); }
            elif (size == 127)
                { size = _to_be64(*(u64*)in); in += sizeof(u64); }

            if (in > conn->in->end) { // NAO DEU PARA LER O SIZE
                if (!conn->in->next)
                    break;
                *(u64*)(conn->in->next->start - 8) = *(u64*)(conn->in->end - 8);
                conn->in->next->start -= (conn->in->end - conn->in->start);
                conn->in->end = conn->in->start;
                continue;
            }

            conn->in->start = in;
            conn->msgMore = size;

            if (size == 0 || size > 128*1024*1024) {
                conn->poll = CONN_POLL_CLOSE;
                break; // BAD SIZE
            }

            if (conn->msgType == CONN_MSG_TYPE_WS_PONG) {
                dbg_conn("WEBSOCKET RECEIVE - PONG");
                continue;
            }

            if (conn->msgType == CONN_MSG_TYPE_WS_PING) {
                // NOTE: ASSUMINDO QUE O PING É PEQUENO
                // NOTE: ASSUMINDO QUE NÃO TEREMOS OUTRO PING ANTES DE ESVAZIAR ESTE
                dbg_conn("WEBSOCKET RECEIVE - PING");
                conn->tmpEnd = conn->tmp;
                *( u8*)conn->tmpEnd = 0x8A;               conn->tmpEnd += 1;
                *( u8*)conn->tmpEnd = 0b10000000U | size; conn->tmpEnd += 1;
                *(u32*)conn->tmpEnd = 0x00000000U;        conn->tmpEnd += 4;
                continue;
            }

            THREADMSGBUFF = malloc(size);
            THREADMSGSTART = THREADMSGBUFF;
            THREADMSGEND = THREADMSGBUFF;

            continue;
        }

        // PAYLOAD

        // VAI TENTAR LER TUDO O QUE DER
        uint size = conn->in->end - conn->in->start;

        // MAS SOMENTE O QUE FALTA
        if (size > conn->msgMore)
            size = conn->msgMore;

        conn->msgMore -= size;

        if (conn->msgType == CONN_MSG_TYPE_WS_PONG) {
            if (conn->msgMore == 0)
                conn->msgType = 0;
            conn->in->start += size;
            continue;
        }

        memcpy(THREADMSGEND, conn->in->start, size);

        conn->in->start += size;
        THREADMSGEND += size;

        if (conn->msgMore == 0) {
            if (conn->msgType != CONN_MSG_TYPE_WS_PING) {
                // BINARY | STRING | INVALID MESSAGE TYPE
                thread->msg->ob_bytes = THREADMSGEND;
                thread->msg->ob_start = THREADMSGSTART;
                thread->msg->ob_alloc = THREADMSGEND;

                Py_REFCNT(thread->msg) = 2;

                conn->msgType  = 0;
                conn->msgSkip  = 0;
                conn->msgWait  = 0;
                conn->msgMore  = 0;

                return (PyObject*)thread->msg;
            }
            // PING
            // NOW REGISTER THE PONG
            xweb_conn_out(conn, xweb_out_static(conn->tmp, conn->tmpEnd - conn->tmp));

            conn->msgType  = 0;
            conn->msgSkip  = 0;
            conn->msgWait  = 0;
            conn->msgMore  = 0;
        }
    }

    if (conn->poll)
        return None;

    return Err;
}

// TODO: FIXME: UMA VERSÃO DISSO PARA INSERIR  UMA JÁ CONSTRUÍDA
// SE ESTIVER FECHADA, NEM TENTA
static PyObject* xweb_PY_conn_ws_send_bytes_str (PyObject* const bytes) {

    Conn* const conn = thread->conn;

    char* payload = PY_BYTES_VALUE(bytes);
    uint size = PY_BYTES_SIZE(bytes);

    if (size > (WS_MSG_SIZE_MAX - 32)) {
        return Err; // INVALID SIZE / TRYING TO SEND A MESSAGE TOO BIG
    }

    if (conn->poll == CONN_POLL_CLOSE) {
        return Err;
    }

    // NOTE: TEM QUE SER U64 E TODOS COM O MESMO BYTE
    const u64 mask = XWEB_WEBSOCKET_MASK;

    char* encoded = xweb_conn_out_sized(conn, ((size > 0xFFFFU) ? 14 : (size >= 126) ? 8 : 6) + size*!!mask);

    if (size > 0xFFFFU) {
        *(u16*)encoded = 0xFF81U;                         encoded += sizeof(u16);
        *(u64*)encoded = __builtin_bswap64(((u64)size));  encoded += sizeof(u64);
        *(u32*)encoded = mask;                            encoded += sizeof(u32);
    } elif (size >= 126) { // TODO: FIXME: ASSUMING WE ARE IN LITTLE ENDIAN
        *(u16*)encoded = 0xFE81U;                         encoded += sizeof(u16); // deixa marcado como 126
        *(u16*)encoded = __builtin_bswap16(((u16)size));  encoded += sizeof(u16);
        *(u32*)encoded = mask;                            encoded += sizeof(u32);
    } else { // <= 125
        *( u8*)encoded = 0x81;                            encoded += sizeof(u8);
        *( u8*)encoded = 0b10000000U | size;              encoded += sizeof(u8);
        *(u32*)encoded = mask;                            encoded += sizeof(u32);
    }

    if (mask) { // COPY IT, MASKING
        while (size >= sizeof(u64)) {
     *(u64*)encoded = *(u64*)payload ^ mask;
            encoded += sizeof(u64);
            payload += sizeof(u64);
            size    -= sizeof(u64);
        }
        while (size--)
           *encoded++ = *payload++ ^ mask;
    } else // ACIMA SÓ COLOCOU O HEADER
        xweb_conn_out_bytes(conn, bytes);

    return None;
}
