#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>


int main( int argc, char* argv[] )
{
  if ( argc != 2 ) {
    fprintf( stderr, "Usage: %s <text to base64>\n", argv[0] );
    exit( 1 );
  }

  BIO *bio, *b64;
  const char* message = argv[1];

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_write(bio, message, strlen(message));
  BIO_flush(bio);

  BIO_free_all(bio);

}