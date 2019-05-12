#include <stdint.h>
#include <stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<netdb.h>
#include<errno.h>

#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#define RSA_KEY_BITS (4096)

#define REQ_DN_C "SE"
#define REQ_DN_ST ""
#define REQ_DN_L ""
#define REQ_DN_O "Example Company"
#define REQ_DN_OU ""
#define REQ_DN_CN "VNF Application"
#define PORT 2346
#define MAXSIZE 2048

static void cleanup_crypto(void);
static void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size);
static void req_to_pem(X509_REQ *req, uint8_t **req_bytes, size_t *req_size); // add 证书请求=>pem
static int generate_key_csr(EVP_PKEY **key, X509_REQ **req);
static int generate_set_random_serial(X509 *crt);
static int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, X509_REQ **req, X509 **crt);
static void initialize_crypto(void);
static void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static void pub_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_pub_path, EVP_PKEY **ca_pub);
static void print_bytes(uint8_t *data, size_t size);
static char *my_encrypt(char *str,char *path_key);
static char *my_decrypt(char *str,char *path_key);
static char *my_sk_encrypt(char *str, char *path_key);
static char *my_pk_decrypt(char *str, char *path_key);

int main(int argc, char **argv)
{
	// /* Assumes the CA certificate and CA key is given as arguments. */
	// if (argc != 3) {
	// 	fprintf(stderr, "usage: %s <cakey> <cacert>\n", argv[0]);
	// 	return 1;
	// }

	// char *ca_key_path = argv[1];
	// char *ca_crt_path = argv[2];
	// char *ca_pub_path = "pubca.key";

	// char *ca_key_path = "ncc.key";
	// char *ca_pub_path = "pubncc.key";
	// /* Load CA key and cert. */
	// initialize_crypto();
	// EVP_PKEY *ca_key = NULL;
	// EVP_PKEY *ca_pub = NULL;
	// if (!load_ca(ca_key_path, &ca_key, ca_pub_path, &ca_pub)) {
	// 	fprintf(stderr, "Failed to load CA certificate and/or key!\n");
	// 	return 1;
	// }

	//socket 过程
	int sockfd, newsockfd;
	//定义服务端套接口数据结构
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int sin_zise, portnumber;
	//发送数据缓冲区
	char buf[MAXSIZE];
	//定义客户端套接口数据结构
	int addr_len = sizeof(struct sockaddr_in);
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr, "create socket failed\n");
		exit(EXIT_FAILURE);
	}
	//puts("create socket success");
	//printf("sockfd is %d\n", sockfd);
	//清空表示地址的结构体变量
	bzero(&server_addr, sizeof(struct sockaddr_in));
	//设置addr的成员变量信息
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	//设置ip为本机IP
	// server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_addr.s_addr = inet_addr("192.168.242.136");
	if (bind(sockfd, (struct sockaddr*)(&server_addr), sizeof(struct sockaddr)) < 0)
	{
		fprintf(stderr, "bind failed \n");
		exit(EXIT_FAILURE);
	}
	//puts("bind success\n");
	if (listen(sockfd, 10) < 0)
	{
		perror("listen fail\n");
		exit(EXIT_FAILURE);
	}
	//puts("listen success\n");
	int sin_size = sizeof(struct sockaddr_in);
	//printf("sin_size is %d\n", sin_size);
	if ((newsockfd = accept(sockfd, (struct sockaddr *)(&client_addr), &sin_size)) < 0)
	{
		perror("accept error");
		exit(EXIT_FAILURE);
	}
	
	//printf("new socket id is %d\n", newsockfd);
	//printf("Accept clent ip is %s\n", inet_ntoa(client_addr.sin_addr));

	//发送随机字符串
	char *random_str = "a415ab5cc17c8c093c015ccdb7e552aee7911aa4";
	send(newsockfd, random_str, strlen(random_str), 0);
	// send(newsockfd, sendfirstbuf, ca_pub_size, 0);
	//接收密文
	char recvbuf[2048];	
	recv(newsockfd, recvbuf, sizeof(recvbuf), 0);
	// printf("收到encode_id：%s \n", recvbuf);
	//解密密文并验证random_str
	char *app_pk = "pubapp.key";
	char *decode_str;
	decode_id = my_pk_decrypt(recvbuf, app_pk);
	printf("收到字符串：%s \n", decode_str);
	//验证random_str

	//if ID合法 => 认证成功
	char *verify = "success";
	send(newsockfd, verify, strlen(verify), 0);	
	
	close(newsockfd);
	close(sockfd);

	exit(EXIT_SUCCESS);


	// /* Free stuff. */
	// EVP_PKEY_free(ca_key);
	// EVP_PKEY_free(key);
	// X509_free(ca_crt);
	// X509_free(crt);
	// free(key_bytes);
	// free(crt_bytes);

	cleanup_crypto();

	return 0;
}

void cleanup_crypto()
{
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
	CRYPTO_mem_leaks_fp(stderr);
}

void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size)
{
	/* Convert signed certificate to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	*crt_size = BIO_pending(bio);
	*crt_bytes = (uint8_t *)malloc(*crt_size + 1);
	BIO_read(bio, *crt_bytes, *crt_size);
	BIO_free_all(bio);
}

void req_to_pem(X509_REQ *req, uint8_t **req_bytes, size_t *req_size)
{
	/* Convert signed certificate to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio, req);
	*req_size = BIO_pending(bio);
	*req_bytes = (uint8_t *)malloc(*req_size + 1);
	BIO_read(bio, *req_bytes, *req_size);
	BIO_free_all(bio);
}

int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, X509_REQ **req, X509 **crt)
{
	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt)) goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*365*3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(*req));
	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(*req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

	X509_REQ_free(*req);
	return 1;
err:
	// EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	X509_free(*crt);
	return 0;
}

int generate_key_csr(EVP_PKEY **key, X509_REQ **req)
{
	*key = EVP_PKEY_new();
	if (!*key) goto err;
	*req = X509_REQ_new();
	if (!*req) goto err;

	RSA *rsa = RSA_generate_key(RSA_KEY_BITS, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(*key, rsa)) goto err;

	X509_REQ_set_pubkey(*req, *key);

	/* Set the DN of the request. */
	X509_NAME *name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)REQ_DN_C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)REQ_DN_O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)REQ_DN_CN, -1, -1, 0);

	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, *key, EVP_sha256())) goto err;
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	return 0;
}

int generate_set_random_serial(X509 *crt)
{
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

void initialize_crypto()
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	CRYPTO_malloc_debug_init(); 
	CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL); 
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
}

void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size)
{
	/* Convert private key to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
	*key_size = BIO_pending(bio);
	*key_bytes = (uint8_t *)malloc(*key_size + 1);
	BIO_read(bio, *key_bytes, *key_size);
	BIO_free_all(bio);
}

void pub_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size)
{
	/* Convert private key to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, key);
	*key_size = BIO_pending(bio);
	*key_bytes = (uint8_t *)malloc(*key_size + 1);
	BIO_read(bio, *key_bytes, *key_size);
	BIO_free_all(bio);
}

int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_pub_path, EVP_PKEY **ca_pub)
{
	BIO *bio = NULL;
	*ca_key = NULL;
	*ca_pub = NULL;

	/* Load CA real public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_pub_path)) goto err;
	*ca_pub = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!*ca_pub) goto err;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_key_path)) goto err;
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!ca_key) goto err;
	BIO_free_all(bio);
	return 1;
err:
	BIO_free_all(bio);
	EVP_PKEY_free(*ca_key);
	return 0;
}

void print_bytes(uint8_t *data, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		printf("%c", data[i]);
	}
}

 //加密
 char *my_encrypt(char *str, char *path_key)
 {
     char *p_en = NULL;
     RSA  *p_rsa = NULL;
     FILE *file = NULL;

     int  lenth = 0;    //flen为源文件长度， rsa_len为秘钥长度

     //1.打开秘钥文件
     if((file = fopen(path_key, "rb")) == NULL)
     {
        perror("fopen() error 111111111 ");
         goto End;
     }        

     //2.从公钥中获取 加密的秘钥
     if((p_rsa = PEM_read_RSA_PUBKEY(file, NULL,NULL,NULL )) == NULL)
     {
         ERR_print_errors_fp(stdout);
         goto End;
     }
     lenth = strlen(str);

     p_en = (char *)malloc(256);
     if(!p_en)
     {
         perror("malloc() error 2222222222");
         goto End;
     }    
     memset(p_en, 0, 256);

     //5.对内容进行加密
     if(RSA_public_encrypt(lenth, (unsigned char*)str, (unsigned char*)p_en, p_rsa, RSA_PKCS1_PADDING) < 0)
     {
     perror("RSA_public_encrypt() error 2222222222");
     goto End;
     }
 End:

     //6.释放秘钥空间， 关闭文件
     if(p_rsa)    RSA_free(p_rsa);
     if(file)     fclose(file);

     return p_en;
 } 
//解密
 char *my_decrypt(char *str, char *path_key)
 {
     char *p_de = NULL;
     RSA  *p_rsa = NULL;
     FILE *file = NULL;

    //1.打开秘钥文件
    file = fopen(path_key, "rb");
    if(!file)
    {
        perror("fopen() error 22222222222");
        goto End;
    }        

    //2.从私钥中获取 解密的秘钥
    if((p_rsa = PEM_read_RSAPrivateKey(file, NULL,NULL,NULL )) == NULL)
    {
        ERR_print_errors_fp(stdout);
        goto End;
    }

    p_de = (char *)malloc(245);
    if(!p_de)
    {
        perror("malloc() error ");
        goto End;
    }    
    memset(p_de, 0, 245);

    //5.对内容进行加密
    if(RSA_private_decrypt(256, (unsigned char*)str, (unsigned char*)p_de, p_rsa, RSA_PKCS1_PADDING) < 0)
    {
        perror("RSA_public_encrypt() error ");
        goto End;
    }

    End:
    //6.释放秘钥空间， 关闭文件
     if(p_rsa)    RSA_free(p_rsa);
    if(file)     fclose(file);

    return p_de;
}

 //私钥加密
 char *my_sk_encrypt(char *str, char *path_key)
 {
     char *p_en = NULL;
     RSA  *p_rsa = NULL;
     FILE *file = NULL;

     int  lenth = 0;    //flen为源文件长度， rsa_len为秘钥长度

     //1.打开秘钥文件
     if((file = fopen(path_key, "rb")) == NULL)
     {
        perror("fopen() error 111111111 ");
         goto End;
     }        

     //2.从私钥中获取 加密的秘钥
     if((p_rsa = PEM_read_RSAPrivateKey(file, NULL,NULL,NULL )) == NULL)
     {
         ERR_print_errors_fp(stdout);
         goto End;
     }
     lenth = strlen(str);

     p_en = (char *)malloc(256);
     if(!p_en)
     {
         perror("malloc() error 2222222222");
         goto End;
     }    
     memset(p_en, 0, 256);

     //5.对内容进行加密
     if(RSA_private_encrypt(lenth, (unsigned char*)str, (unsigned char*)p_en, p_rsa, RSA_PKCS1_PADDING) < 0)
     {
     perror("RSA_private_encrypt() error 2222222222");
     goto End;
     }
 End:

     //6.释放秘钥空间， 关闭文件
     if(p_rsa)    RSA_free(p_rsa);
     if(file)     fclose(file);

     return p_en;
 } 
//公钥解密
 char *my_pk_decrypt(char *str, char *path_key)
 {
     char *p_de = NULL;
     RSA  *p_rsa = NULL;
     FILE *file = NULL;

    //1.打开秘钥文件
    file = fopen(path_key, "rb");
    if(!file)
    {
        perror("fopen() error 22222222222");
        goto End;
    }        

    //2.从公钥中获取 解密的秘钥
    if((p_rsa = PEM_read_RSA_PUBKEY(file, NULL,NULL,NULL )) == NULL)
    {
        ERR_print_errors_fp(stdout);
        goto End;
    }

    p_de = (char *)malloc(245);
    if(!p_de)
    {
        perror("malloc() error ");
        goto End;
    }    
    memset(p_de, 0, 245);

    //5.对内容进行加密
    if(RSA_public_decrypt(256, (unsigned char*)str, (unsigned char*)p_de, p_rsa, RSA_PKCS1_PADDING) < 0)
    {
        perror("RSA_public_encrypt() error ");
        goto End;
    }

    End:
    //6.释放秘钥空间， 关闭文件
     if(p_rsa)    RSA_free(p_rsa);
    if(file)     fclose(file);

    return p_de;
}
