#include <stdint.h>
#include <stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netdb.h>
#include<string.h>
#include<errno.h>

int count = 1;
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

static void cleanup_crypto(void);
static void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size);
static void req_to_pem(X509_REQ *req, uint8_t **req_bytes, size_t *req_size); // add 证书请求=>pem
static int generate_key_csr(EVP_PKEY **key, X509_REQ **req);
static int generate_set_random_serial(X509 *crt);
static int generate_signed_key_pair(EVP_PKEY **key, X509_REQ **req, X509 **crt);
static void initialize_crypto(void);
static void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static void pub_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static int load_client(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_pub_path, EVP_PKEY **ca_pub);
static void print_bytes(uint8_t *data, size_t size);
static void write_bytes(const char *path, uint8_t *data, size_t size);
static char *my_encrypt(char *str,char *path_key);
static char *my_decrypt(char *str,char *path_key);

int main(int argc, char **argv)
{
	initialize_crypto();

	/* Load client pk and sk. */
	char *client_key_path = "app.key";
	char *client_pub_path = "pubapp.key";
	initialize_crypto();
	EVP_PKEY *client_key = NULL;
	EVP_PKEY *client_pub = NULL;
	if (!load_client(client_key_path, &client_key, client_pub_path, &client_pub)) {
		fprintf(stderr, "Failed to load client certificate and/or key!\n");
		return 1;
	}	

	//socket 过程
	int sockfd;	
	char buffer[2014];
	struct sockaddr_in server_addr;
	struct hostent *host;
	int nbytes;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		fprintf(stderr, "Socket Error is %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	// server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_addr.s_addr = inet_addr("192.168.242.136");
	//客户端发出请求
	if (connect(sockfd, (struct sockaddr *)(&server_addr), sizeof(struct sockaddr)) == -1)
	{
		fprintf(stderr, "Connect failed\n");
		exit(EXIT_FAILURE);
	}
	puts("发起认证请求");
	//接收随机字符串
	char recvbuf[2048];	
	recv(sockfd, recvbuf, sizeof(recvbuf), 0);

	printf("收到随机字符串：%s \n", recvbuf);

	//对ID进行加密
	char *app_key = "app.key";
	char *encode_str;
	encode_str = my_sk_encrypt(recvbuf, app_key);
	//发送encode_str
	send(sockfd, encode_str, strlen(encode_str), 0);
	char recv_verrify[2048];	
	recv(sockfd, recv_verrify, sizeof(recv_verrify), 0);
	printf("认证结果：%s \n", recv_verrify);

	close(sockfd);
	exit(EXIT_SUCCESS);

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

int generate_signed_key_pair(EVP_PKEY **key, X509_REQ **req, X509 **crt)
{
	/* Generate the private key and corresponding CSR. */
	// X509_REQ *req = NULL;
	if (!generate_key_csr(key, req)) {
		fprintf(stderr, "Failed to generate key and/or CSR!\n");
		return 0;
	}

	// /* Convert req to PEM format. */
	// // 将private key 和 csr 写入文件
	// uint8_t *req_bytes = NULL;
	// size_t req_size = 0;
	// uint8_t *key_bytes = NULL;
	// size_t key_size = 0;
	// req_to_pem(*req, &req_bytes, &req_size);
	// char *csr_path = "app.csr";
	// write_bytes(csr_path, req_bytes, req_size);
	// key_to_pem(*key, &key_bytes, &key_size);
	// char *key_path = "app.key";
	// write_bytes(key_path, key_bytes, key_size);
	
	return 1;
// 	/* Sign with the CA. */
// 	*crt = X509_new();
// 	if (!*crt) goto err;

// 	X509_set_version(*crt, 2); /* Set version to X509v3 */

// 	/* Generate random 20 byte serial. */
// 	if (!generate_set_random_serial(*crt)) goto err;

// 	/* Set issuer to CA's subject. */
// 	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

// 	/* Set validity of certificate to 2 years. */
// 	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
// 	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*365*3600);

// 	/* Get the request's subject and just use it (we don't bother checking it since we generated
// 	 * it ourself). Also take the request's public key. */
// 	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
// 	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
// 	X509_set_pubkey(*crt, req_pubkey);
// 	EVP_PKEY_free(req_pubkey);

// 	/* Now perform the actual signing with the CA. */
// 	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

// 	X509_REQ_free(req);
// 	return 1;
// err:
// 	EVP_PKEY_free(*key);
// 	X509_REQ_free(req);
// 	X509_free(*crt);
// 	return 0;
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

int load_client(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_pub_path, EVP_PKEY **ca_pub)
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

void write_bytes(const char *path, uint8_t *data, size_t size)
{
    FILE *fp;
    if((fp=fopen(path,"a"))==NULL)
        printf("file cannot open \n");
    // else
    //     printf("file opened for writing \n");
	for (size_t i = 0; i < size; i++) {
		// printf("%c", data[i]);
		fputc(data[i],fp); //输入到文件中
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
        perror("RSA_private_decrypt() error ");
        goto End;
    }

    End:
    //6.释放秘钥空间， 关闭文件
     if(p_rsa)    RSA_free(p_rsa);
    if(file)     fclose(file);

    return p_de;
}

