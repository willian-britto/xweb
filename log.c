
#define LOG_BUFFER_SIZE (2*1024*1024)

static char* logBuffer;
static char* logBufferReady;
static char* logBufferFlushing;
static char* logEnd;
static uint logFree;

static PyObject* xweb_PY_log_ (const char* const pre, uint preSize, const char* const msg, uint msgSize) {

    if (logFree < (msgSize + 8192)) {
        logFree = LOG_BUFFER_SIZE;
        logEnd = logBuffer;
    }

    memcpy(logEnd, pre, preSize);
    logEnd += preSize;
    logFree -= preSize;

    if (thread) {
        memcpy(logEnd, thread->name, thread->nameSize);
        logEnd += thread->nameSize;
        logFree -= thread->nameSize + 1; // JA DESCONTA O \n
    } elif (class) {
        memcpy(logEnd, class->name, class->nameSize);
        logEnd += class->nameSize;
        logFree -= class->nameSize + 1;
    } else {
        memcpy(logEnd, "[main]", 6);
        logEnd += 6;
        logFree -= 7;
    }

    if (msgSize > logFree)
        msgSize = logFree;

    memcpy(logEnd, msg, msgSize);

    logEnd += msgSize;
    logFree -= msgSize;

    memcpy(logEnd, "\n", 1);

    logEnd += 1;

#if 1
    write(STDOUT_FILENO, logBuffer, logEnd - logBuffer);
    logEnd = logBuffer;
    logFree = LOG_BUFFER_SIZE;
#endif
    return None;
}

void xweb_log_init (void) {

    logBuffer = malloc(LOG_BUFFER_SIZE);
    logBufferReady = malloc(LOG_BUFFER_SIZE);
    logBufferFlushing = NULL;
    logEnd = logBuffer;
    logFree = LOG_BUFFER_SIZE;
}
