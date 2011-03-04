#include <string.h>
#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>


char *uchar_to_base64(const unsigned char *input, int length)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(sizeof(char) * bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  BIO_free_all(b64);
  return buff;
}


char* base64_to_uchar(unsigned char *input, int length)
{
  BIO *b64, *bmem;

  char *buffer = (char *)malloc(length);
  memset(buffer, 0, length);

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);

  BIO_read(bmem, buffer, length);

  BIO_free_all(bmem);

  return buffer;
}


int main()
{
  const unsigned char clearText[] = "denes";
  printf("Original text: '%s'\n", clearText);
  char *b64_output = uchar_to_base64((unsigned char*)clearText, strlen((char*)clearText));
  printf("Base64: '%s'\n", b64_output);

  char *uchar_output;
  uchar_output = base64_to_uchar((unsigned char *)b64_output, strlen(b64_output));
  free(b64_output);

  printf("uchar: '%s'\n", uchar_output);
  free(uchar_output);

  return 0;
}
