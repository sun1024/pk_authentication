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
#define PORT 2345
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
static int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_pub_path, EVP_PKEY **ca_pub, const char *ca_crt_path, X509 **ca_crt);
static void print_bytes(uint8_t *data, size_t size);
static char *my_encrypt(char *str,char *path_key);
static char *my_decrypt(char *str,char *path_key);

int main(int argc, char **argv)
{
	/* Assumes the CA certificate and CA key is given as arguments. */
	if (argc != 3) {
		fprintf(stderr, "usage: %s <cakey> <cacert>\n", argv[0]);
		return 1;
	}

	char *ca_key_path = argv[1];
	char *ca_crt_path = argv[2];
	char *ca_pub_path = "pubca.key";

	/* Load CA key and cert. */
	initialize_crypto();
	EVP_PKEY *ca_key = NULL;
	EVP_PKEY *ca_pub = NULL;
	X509 *ca_crt = NULL;
	if (!load_ca(ca_key_path, &ca_key, ca_pub_path, &ca_pub, ca_crt_path, &ca_crt)) {
		fprintf(stderr, "Failed to load CA certificate and/or key!\n");
		return 1;
	}

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
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
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

	//发送公钥(ca_pub)
	uint8_t *ca_pub_bytes = NULL;
	size_t ca_pub_size = 0;
	pub_to_pem(ca_pub, &ca_pub_bytes, &ca_pub_size);
	// print_bytes(ca_pub_bytes, ca_pub_size);

	char sendfirstbuf[2048];
	strcpy(sendfirstbuf, ca_pub_bytes);
	// send(newsockfd, sendfirstbuf, strlen(sendfirstbuf), 0);
	send(newsockfd, sendfirstbuf, ca_pub_size, 0);
	//接收证书请求的密文
	char recvbuf[2048];	
	recv(newsockfd, recvbuf, sizeof(recvbuf), 0);
	// printf("收到encode_id：%s \n", recvbuf);
	//使用私钥解密密文得到csr
	char *ca_sk = "ca.key";
	char *decode_id;
	decode_id = my_decrypt(recvbuf, ca_sk);
	printf("收到id：%s \n", decode_id);
	
	
	// //csr 写入文件
	// FILE *fp;
    // if((fp=fopen("app.csr","w"))==NULL)
    //     printf("file cannot open \n");
	// fputs(recvbuf, fp);
	// fclose(fp);
	// //读取app.csr 得到X509_REQ
	// X509_REQ *req = NULL;
	// const char *x509ReqFile = "app.csr";
	// BIO *in;
	// in = BIO_new_file(x509ReqFile, "r");
	// req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
	// BIO_free(in);

	// uint8_t *req_bytes = NULL;
	// size_t req_size = 0;
	// req_to_pem(req, &req_bytes, &req_size);
	// print_bytes(req_bytes, req_size);

	// X509 *crt = NULL;
	// int ret = generate_signed_key_pair(ca_key, ca_crt, &req, &crt);
	// if (!ret) {
	// 	fprintf(stderr, "Failed to generate key pair!\n");
	// 	return 1;
	// }
	// // /* Convert key and certificate to PEM format. */
	// uint8_t *crt_bytes = NULL;
	// size_t crt_size = 0;
	// crt_to_pem(crt, &crt_bytes, &crt_size);
	// print_bytes(crt_bytes, crt_size);

	// //发送签名证书
	// char sendsecondbuf[2048];
	// strcpy(sendsecondbuf, crt_bytes);
	// send(newsockfd, sendsecondbuf, strlen(sendsecondbuf), 0);	
	
	close(newsockfd);
	close(sockfd);
	// puts("注册成功");
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

int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_pub_path, EVP_PKEY **ca_pub, const char *ca_crt_path, X509 **ca_crt)
{
	BIO *bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;
	*ca_pub = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_crt_path)) goto err;
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*ca_crt) goto err;
	BIO_free_all(bio);

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
	X509_free(*ca_crt);
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
char *my_encrypt(char *str,char *path_key){
    char *p_en;
    RSA *p_rsa;
    FILE *file;
    int flen,rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;    
    }   
    if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){
    //if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   换成这句死活通不过，无论是否将公钥分离源文件
        ERR_print_errors_fp(stdout);
        return NULL;
    }   
    flen=strlen(str);
    rsa_len=RSA_size(p_rsa);
    p_en=(unsigned char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
    if(RSA_public_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_en;
}
// 解密
char *my_decrypt(char *str,char *path_key){
    char *p_de;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return NULL;
    }
    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    rsa_len=RSA_size(p_rsa);
    p_de=(unsigned char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
    if(RSA_private_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_de;
}
