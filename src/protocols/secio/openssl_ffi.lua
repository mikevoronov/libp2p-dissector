-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local ffi = require("ffi")

-- https://stackoverflow.com/questions/35557928/ffi-encryption-decryption-with-luajit
ffi.cdef [[
  typedef struct evp_cipher_st EVP_CIPHER;
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
  typedef struct engine_st ENGINE;

  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx);
  void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
         ENGINE *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, const unsigned char *in, int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl);

  int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
         ENGINE *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, const unsigned char *in, int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);


  const EVP_CIPHER *EVP_aes_128_ctr(void);
  const EVP_CIPHER *EVP_aes_256_ctr(void);
]]
