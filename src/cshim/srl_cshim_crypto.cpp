#include <string>
#include <dlfcn.h>
#include <cstring>
#include <iostream>

extern "C" bool _ZN7srlinux16IsUnitTestBinaryEv(void) {
    return false;
}

typedef void (*SecretKeyCtor)(void*, const std::string&);
typedef void (*SecretKeyDtor)(void*);
typedef void (*SecretKeyToPlain)(std::string*, const void*);

extern "C" int srl_decrypt_password(const char *in, char *out, size_t out_len) {
    if (!in || !out || out_len == 0) return -1;
    if (strncmp(in, "$aes1$", 6) != 0) {
        strncpy(out, in, out_len - 1);
        out[out_len - 1] = '\0';
        return 0;
    }
    // Attempt to load SR Linux crypto shared libraries
    dlopen("/opt/srlinux/lib/liblib_srlutil_misc.so", RTLD_NOW | RTLD_GLOBAL);
    dlopen("/opt/srlinux/lib/liblib_srlutil_crypto.so", RTLD_NOW | RTLD_GLOBAL);
    void *h = dlopen("/opt/srlinux/lib/liblib_srlutil_data_type.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        // Fallback to copying as-is if library not available (e.g. host development build)
        strncpy(out, in, out_len - 1);
        out[out_len - 1] = '\0';
        return 0;
    }
    SecretKeyCtor ctor = (SecretKeyCtor)dlsym(h, "_ZN9SecretKeyC1ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE");
    SecretKeyToPlain to_plain = (SecretKeyToPlain)dlsym(h, "_ZNK9SecretKey11ToPlainTextB5cxx11Ev");
    SecretKeyDtor dtor = (SecretKeyDtor)dlsym(h, "_ZN9SecretKeyD1Ev");
    if (!ctor || !to_plain) {
        strncpy(out, in, out_len - 1);
        out[out_len - 1] = '\0';
        return 0;
    }
    try {
        char sk_buf[256] = {0};
        std::string enc_str(in);
        ctor(sk_buf, enc_str);
        std::string plain;
        to_plain(&plain, sk_buf);
        if (dtor) dtor(sk_buf);
        explicit_bzero(sk_buf, sizeof(sk_buf));
        strncpy(out, plain.c_str(), out_len - 1);
        out[out_len - 1] = '\0';
        if (!plain.empty()) explicit_bzero(&plain[0], plain.size());
        return 0;
    } catch (...) {
        strncpy(out, in, out_len - 1);
        out[out_len - 1] = '\0';
        return -1;
    }
}
