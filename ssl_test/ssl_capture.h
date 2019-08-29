


#ifdef __cplusplus
extern "C" {
#endif

    char SSL_CAPTURE_ENTRY(stSessionInfo* session_info, void **param, int thread_seq, struct streaminfo *a_tcp, void *a_packet);
    int SSL_CAPTURE_INTI(void);
    void SSL_CAPTURE_DESTROY(void);

#ifdef __cplusplus
}
#endif

