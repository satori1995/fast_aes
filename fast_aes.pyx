from libc.stdint cimport uint32_t
from libc.string cimport memmove, memset
from libc.stdlib cimport malloc, free
from cpython.bytes cimport PyBytes_FromStringAndSize

cdef extern from "aes.h":
    ctypedef struct aes_context:
        int nr
        uint32_t *rk
        uint32_t buf[68]

    cdef int AES_ENCRYPT
    cdef int AES_DECRYPT
    void aes_init(aes_context *)
    int aes_setkey_enc(aes_context *, const unsigned char *, unsigned int)
    int aes_setkey_dec(aes_context *, const unsigned char *, unsigned int)
    int aes_crypt_ecb(aes_context *, int, const unsigned char[16], unsigned char[16])


cdef extern from "base64.h":
    int POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL = -0x002A
    int POLARSSL_ERR_BASE64_INVALID_CHARACTER = -0x002C
    int base64_encode(unsigned char *, size_t *, const unsigned char *, size_t)
    int base64_decode(unsigned char *, size_t *, const unsigned char *, size_t);


cdef extern from "md5.h":
    ctypedef struct md5_context:
        uint32_t total[2]
        uint32_t state[4]
        unsigned char buffer[64]
        unsigned char ipad[64]
        unsigned char opad[64]

    void md5_init(md5_context *)
    void md5_starts(md5_context *)
    void md5_update(md5_context *, const unsigned char *, size_t)
    void md5_finish(md5_context *, unsigned char[16])
    void md5_free(md5_context *)


# ********** Buffer **********
cdef struct Buffer:
    Py_ssize_t length
    unsigned char *content


cdef void buf_init(Buffer *buf, Py_ssize_t length):
    buf.length = length
    if length == 0:
        buf.content = NULL
        return
    buf.content = <unsigned char *> malloc((length // 16 + 1) * 16)
    memset(<void *> buf.content, 0, buf.length)


cdef void buf_free(Buffer *buf):
    if buf == NULL or buf.content == NULL:
        return
    free(<void *> buf.content)
    buf.content = NULL


cdef void buf_padding(Buffer *buf, size_t round_, unsigned char pad_char):
    cdef Buffer new_buf;
    new_buf.length = (((buf.length - 1) // round_) + 1) * round_
    new_buf.content = <unsigned char *> malloc(new_buf.length)
    memmove(new_buf.content, buf.content, buf.length)

    cdef Py_ssize_t i;
    for i in range(new_buf.length - buf.length):
        new_buf.content[i + buf.length] = pad_char

    free(buf.content)
    buf.content = new_buf.content
    buf.length = new_buf.length


cdef void buf_trim(Buffer *buf, unsigned char pad_char):
    cdef Py_ssize_t i
    for i in range(buf.length - 1, -1, -1):
        if buf.content[i] != pad_char:
            break
    buf.length = i + 1


# ********** 数据解密异常 **********
cdef class DecryptionError(Exception):
    cdef readonly bytes content

    def __init__(self, bytes content):
        self.content = content

    def __str__(self):
        return f"解密失败，可能是当前数据的格式和加密后的格式不一致，或者 key 指定错误"


# ********** FastAES **********
cdef class FastAES:
    """
    AES 的快速实现
    """
    salt = b"\x12\x24\x36\x48\x5a\x6c\x7e\x0f\x21\x42\x63\x84\xa5\xc6\x7e\xf0"

    cdef aes_context ctx
    cdef unsigned char key[16]

    def __init__(self):
        aes_init(&self.ctx)

    def set_key(self, bytes seed):
        """
        基于随机种子生成 aes key
        """
        cdef md5_context ctx
        md5_init(&ctx)
        md5_starts(&ctx)
        md5_update(&ctx, <unsigned char *> seed, len(seed))
        md5_update(&ctx, <unsigned char *> self.salt, 16)
        md5_finish(&ctx, self.key)

        cdef Py_ssize_t i
        for i in range(12):
            md5_init(&ctx)
            md5_starts(&ctx)
            md5_update(&ctx, <unsigned char *> self.key, 16)
            md5_update(&ctx, <unsigned char *> self.salt, 16)
            md5_finish(&ctx, self.key)

        md5_free(&ctx)

    cpdef bytes encrypt(self, bytes content):
        """
        对 content 进行加密
        """
        # plain：明文，encrypted：密文
        cdef Buffer plain, encrypted, base64
        plain.content = <unsigned char *> content
        plain.length = len(content)
        base64.length = 0
        base64_encode(NULL, <size_t *> &base64.length, plain.content, plain.length)
        buf_init(&base64, base64.length)
        base64_encode(base64.content, <size_t *> &base64.length, plain.content, plain.length)
        buf_padding(&base64, 32, <unsigned char> b" ")
        aes_setkey_enc(&self.ctx, <unsigned char *> self.key, 128)
        buf_init(&encrypted, base64.length)

        cdef Py_ssize_t i
        for i in range(0, encrypted.length, 16):
            aes_crypt_ecb(&self.ctx, AES_ENCRYPT, &base64.content[i], &encrypted.content[i])

        cdef bytes result = PyBytes_FromStringAndSize(<char *> encrypted.content, encrypted.length)
        buf_free(&base64)
        buf_free(&encrypted)

        return result

    cpdef decrypt(self, bytes content):
        """
        对 content 进行解密
        """
        # plain：明文，encrypted：密文
        cdef Buffer plain, encrypted, base64
        encrypted.content = <unsigned char *> content
        encrypted.length = len(content)

        buf_init(&base64, encrypted.length)
        aes_setkey_dec(&self.ctx, <unsigned char *> self.key, 128)

        cdef Py_ssize_t i
        for i in range(0, encrypted.length, 16):
            aes_crypt_ecb(&self.ctx, AES_DECRYPT, &encrypted.content[i], &base64.content[i])
        buf_trim(&base64, <unsigned char> b" ")

        if POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL != base64_decode(
                NULL, <size_t *> &plain.length, base64.content, base64.length):
            buf_free(&base64)
            raise DecryptionError(content)
        buf_init(&plain, plain.length)

        if base64_decode(plain.content, <size_t *> &plain.length, base64.content, base64.length) != 0:
            buf_free(&base64)
            buf_free(&plain)
            raise DecryptionError(content)

        cdef bytes result = PyBytes_FromStringAndSize(<char *> plain.content, plain.length)
        buf_free(&base64)
        buf_free(&plain)

        return result
