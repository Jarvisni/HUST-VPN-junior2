#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <string.h>

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"ya.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",X509_verify_cert_error_string(err));
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;

    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
	ERR_print_errors_fp(stderr);
	exit(-2);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
	ERR_print_errors_fp(stderr);
	exit(-3);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
	printf("Private key does not match the certificate public keyn");
	exit(-4);
    }
    ssl = SSL_new(ctx);

    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    return ssl;
}


int setupTCPClient(const char* hostname, int port)
{
    struct sockaddr_in server_addr;

    // Get the IP address from hostname
    struct hostent *hp = gethostbyname(hostname);

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // Fill in the destination information (IP, port #, and family)
    memset(&server_addr, '\0', sizeof(server_addr));
    memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;

    // Connect to the destination
    connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    return sockfd;
}

int createTunDevice() {
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);

    return tunfd;
}

typedef struct thread_data{
    int tunfd;
    SSL *ssl;
}THDATA,*PTHDATA;


char* last;

void* listen_tun(void* threadData)
{
    PTHDATA ptd = (PTHDATA) threadData;
    while (1)
    {
        int len;
        char buff[2000];

        bzero(buff, 2000);
        len = read(ptd->tunfd, buff, 2000);
        if (len > 19 && buff[0] == 0x45)
        {
            if ((int) buff[15] == atoi(last))
            {
                printf("Received(TUN) len = %d\n", len);
                SSL_write(ptd->ssl, buff, len);
            }
            else
            {
                printf("Incorrect IP: 192.168.53.%s", last);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    char *hostname = "vpnlabserver.com";
    int port = 4433;
    
    char us[100];
    char ps[100];
    char iipp[100];    

    hostname = argv[1];
    port = atoi(argv[2]);
    
    printf("Input the username:");
    scanf("%s",us);
    getchar();
    printf("Input the password:");
    scanf("%s",ps);
    getchar();
    printf("Input the tun ip(only the last like 5):");
    scanf("%s",iipp);
    getchar();
    last=iipp;

    /*----------------TLS initialization -----------------------*/
    SSL *ssl = setupTLSClient(hostname);

    /*----------------Create a TCP connection ------------------*/
    int sockfd = setupTCPClient(hostname, port);

    /*----------------TLS handshake ----------------------------*/
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl);
    CHK_SSL(err);
    printf("SSL connection is successful\n");
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    SSL_write(ssl, us, strlen(us));
    SSL_write(ssl, ps, strlen(ps));
    SSL_write(ssl, last, strlen(last));

    /*----------------Send/Receive data -------------------------*/
    int tunfd = createTunDevice();
    pthread_t listen_tun_thread;
    THDATA threadData;
    threadData.tunfd = tunfd;
    threadData.ssl = ssl;
    pthread_create(&listen_tun_thread, NULL, listen_tun, (void*) &threadData);

    // redirect and routing
    char cmd[100];
    sprintf(cmd, "sudo ifconfig tun0 192.168.53.%s/24 up && sudo route add -net 192.168.60.0/24 tun0", last);
    system(cmd);

    int len;
    do
    {
        char buf[9000];
        len = SSL_read(ssl, buf, sizeof(buf) - 1);
        write(tunfd, buf, len);
        printf("Receive SSL: %d\n", len);
    } while (len > 0);
    pthread_cancel(listen_tun_thread);
    printf("Close connection.\n");
    return 0;
}
