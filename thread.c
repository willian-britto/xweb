
static PyObject* xweb_thread_new_PY (Thread* const parent) {

    const uint id = class->n++;

    char name[512];
    uint nameSize;

    if (parent)
        nameSize = snprintf(name, sizeof(name), "%.*s%.*s[%u]", parent->nameSize, parent->name, class->nameSize - parent->class->nameSize, class->name + parent->class->nameSize, id);
    else
        nameSize = snprintf(name, sizeof(name), "%.*s[%u]", class->nameSize, class->name, id);

    Thread* const new = malloc(sizeof(Thread) + nameSize);

    memcpy(new->name, name, (new->nameSize = nameSize));

    new->next = threads;
    new->class = class;
    new->classNext = class->threads;
    new->class->threads = new;
    new->site = class->site;
    new->id = id;
    new->started = 0;
    new->userAgent = NULL;
    new->cookies = NULL;
    new->msg = (PyByteArrayObject*)PyByteArray_FromStringAndSize("", 1);
    new->pool = NULL;
    new->conn = NULL;
    new->streamConn = NULL;
    PyObject_Free(new->msg->ob_bytes);
    new->msg->ob_bytes = NULL;

    if ((new->parent = parent)) {
        new->parentNext = parent->childs;
        new->parent->childs = new;
        new->pools = parent->pools;
    } else {
        new->parentNext = NULL;
        new->pools = malloc(SESSION_POOLS_ROOTS_N*sizeof(Pool*));
        clear(new->pools, SESSION_POOLS_ROOTS_N * sizeof(Pool*));
    }

    // ESTAMOS NELA
    site = new->site;
    class = new->class;

    return (new->obj = PTR_TO_PY((thread = (threads = new))));
}

static PyObject* xweb_thread_enter_PY (Thread* const thread_) {

    thread = thread_;
    site   = thread_->site;
    class  = thread_->class;

    return None;
}

PyObject* xweb_thread_leave_PY (void) {

    ASSERT(Py_REFCNT(thread->msg) == 1);

    if (thread->msg->ob_bytes) {
        free(thread->msg->ob_bytes);
        thread->msg->ob_bytes = NULL;
    }

    //
    if (thread->conn &&
        thread->conn->poll == CONN_POLL_CLOSE)
        thread->conn = NULL;

    // O MESMO COM A STREAM
    //if (thread->conn &&
        //thread->conn->poll == CONN_POLL_CLOSE)
        //thread->conn = NULL;

    if (thread->streamConn) {
        Conn* const conn = thread->streamConn;

        // TODO: FIXME: SE A STREAM FOR RAW-SSL, TEM QUE PERIODICAMENTE EXECUTAR O RECV/SEND POIS PODE ESTAR QUERENDO RENEGOCIAR ETC :S
        // TODO: FIXME: SE O WRITE ESTIVER TRAVADO POR CAUSA DO SSLWANT READ, VAI FICAR MANDANDO MAIS PINGS POIS O OUTTIME NAO ESTÁ AJUSTADO
        if (1) {
            // WEBSOCKET
            if (conn->out == NULL && (conn->outTime + 30*1000) < now && (conn->inTime + 45*1000) < now) {
                // MUITO TEMPO SEM ENVIAR NADA E NÃO VAI ENVIAR NADA AGORA / MUITO TEMPO SEM RECEBER NADA
                //  -> ENVIA UM PING, PARA FORÇAR UM ENVIO E/OU RECEBER ALGO
                dbg("POLL() - SENDING PING");
                // ESTE TIME TEM QUE SER O DO SOCKET E NAO O SSL
                //conn->again = now + 30*1000;
                *(u16*)xweb_conn_out_sized(conn, 2) = 0x8009U;
            }
        }
    }

    //s[o deixa colocar outs quando xweb.connect() for True

    PyObject* const threadObj = thread->obj;

    thread = NULL;
    site   = NULL;
    class  = NULL;

    Py_REFCNT(threadObj) = 0xFFFFFFFFU;

    return threadObj;
}
