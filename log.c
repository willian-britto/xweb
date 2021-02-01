
void xweb_log_init (void) {

    logBuffer = malloc(LOG_BUFFER_SIZE);
    logBufferReady = malloc(LOG_BUFFER_SIZE);
    logBufferFlushing = NULL;
    logEnd = logBuffer;
    logFree = LOG_BUFFER_SIZE;
}
