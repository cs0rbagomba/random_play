/*  gcc ./openssl_sign.c -lssl */

#include <stdio.h>
#include <string.h>
#include <error.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>


int pass_cb( char *buf, int size, int rwflag, void *u )
{
  if ( rwflag == 1 ) {
    /* What does this really means? */
  }

  int len;
  char tmp[1024];
  printf( "Enter pass phrase for '%s': ", (char*)u );
  scanf( "%s", tmp );
  len = strlen( tmp );

  if ( len <= 0 ) return 0;
  if ( len > size ) len = size;

  memset( buf, '\0', size );
  memcpy( buf, tmp, len );
  return len;
}

RSA* getRsaFp( const char* rsaprivKeyPath )
{
  FILE* fp;
  fp = fopen( rsaprivKeyPath, "r" );
  if ( fp == 0 ) {
    fprintf( stderr, "Couldn't open RSA priv key: '%s'. %s\n",
             rsaprivKeyPath, strerror(errno) );
    exit(1);
  }

  RSA *rsa = 0;
  rsa = RSA_new();
  if ( rsa == 0 ) {
    fprintf( stderr, "Couldn't create new RSA priv key obj.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    fclose( fp );
    exit( 1 );
  }

  rsa = PEM_read_RSAPrivateKey(fp, 0, pass_cb, (char*)rsaprivKeyPath);
  if ( rsa == 0 ) {
    fprintf( stderr, "Couldn't use RSA priv keyfile.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    fclose( fp );
    exit( 1 );
  }
  fclose( fp );
  return rsa;
}


int main( int argc, char* argv[] )
{
  if ( argc != 2 ) {
    fprintf( stderr, "Usage: %s <text to sign>\n", argv[0] );
    exit( 1 );
  }
  const char *clearText = argv[1];

  char rsaprivKeyPath[1024];
  sprintf( rsaprivKeyPath, "%s/.ssh/id_rsa",  getenv ("HOME") );

  SSL_load_error_strings();

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();


  EVP_PKEY *evpKey = 0;
  evpKey = EVP_PKEY_new();
  if ( evpKey == 0 ) {
    fprintf( stderr, "Couldn't create new EVP_PKEY object.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    exit(1);
  }

  RSA *rsa = 0;
  rsa = getRsaFp( rsaprivKeyPath );

  if ( EVP_PKEY_set1_RSA( evpKey, rsa ) == 0 ) {
    fprintf( stderr, "Couldn't set EVP_PKEY to RSA key.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    exit(1);
  }

  EVP_MD_CTX* ctx = 0;
  ctx = EVP_MD_CTX_create();
  if ( ctx == 0 ) {
    fprintf( stderr, "Couldn't create EVP context.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    exit(1);
  }

  if ( EVP_SignInit_ex( ctx, EVP_sha1(), 0 ) == 0 ) {
    fprintf( stderr, "Couldn't exec EVP_SignInit.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    exit(1);
  }

  if ( EVP_SignUpdate( ctx, clearText, strlen( clearText ) ) == 0 ) {
    fprintf( stderr, "Couldn't calculate hash of message.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    exit(1);
  }

  const int MAX_LEN = 1024;
  unsigned char sig[MAX_LEN];
  unsigned int sigLen;
  memset(sig, 0, MAX_LEN);

  if ( EVP_SignFinal( ctx, sig, &sigLen, evpKey ) == 0 ) {
    fprintf( stderr, "Couldn't calculate signature.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    exit(1);
  }

  printf( "Got signature: '%s'\n", sig );

  EVP_MD_CTX_destroy( ctx );
  RSA_free( rsa );
  EVP_PKEY_free( evpKey );
  ERR_free_strings();
  return 0;
}
