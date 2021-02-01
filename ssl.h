#define WC_NO_HARDEN 1

#include <wolfssl/ssl.h>

#define WOLFSSL_SNI_HOST_NAME 0

extern int wolfSSL_UseSNI(void*, int, char*, unsigned short);

typedef WOLFSSL WOLFSSL;
typedef WOLFSSL_CTX WOLFSSL_CTX;
