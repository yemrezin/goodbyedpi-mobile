/*
 * GoodbyeDPI-Turkey Android Native Core (ported from src/goodbyedpi.c & src/fakepackets.c)
 */
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include "windows.h"
#include "goodbyedpi.h"
#include "dnsredir.h"
#include "ttltrack.h"
#include "blackwhitelist.h"
#include "utils/repl_str.h"

#define GOODBYEDPI_VERSION "v0.2.3rc3-turkey-mobile"

static const char http10_redirect_302[] = "HTTP/1.0 302 ";
static const char http11_redirect_302[] = "HTTP/1.1 302 ";
static const char http_host_find[] = "\r\nHost: ";
static const char http_host_replace[] = "\r\nhoSt: ";
static const char http_useragent_find[] = "\r\nUser-Agent: ";
static const char location_http[] = "\r\nLocation: http://";
static const char connection_close[] = "\r\nConnection: close";
static const char *http_methods[] = {
    "GET ",
    "HEAD ",
    "POST ",
    "PUT ",
    "DELETE ",
    "CONNECT ",
    "OPTIONS ",
};

// Captured from Firefox 130.0.1 (from fakepackets.c)
static const unsigned char fake_clienthello_part0[] = { // 116 bytes
    0x16, 0x03, 0x01, 0xDD, 0xDD, 0x01, 0x00, 0xDD, 0xDD, 0x03, 0x03,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x20,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x00, 0x22, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0xC0, 0x2B, 0xC0, 0x2F, 0xCC, 0xA9, 0xCC, 0xA8,
    0xC0, 0x2C, 0xC0, 0x30, 0xC0, 0x0A, 0xC0, 0x09, 0xC0, 0x13, 0xC0, 0x14, 0x00, 0x9C, 0x00, 0x9D,
    0x00, 0x2F, 0x00, 0x35,
    0x01, 0x00,
    0xDD, 0xDD,
};

static const unsigned char fake_clienthello_part1[] = { // 523 bytes
    0x00, 0x17, 0x00, 0x00,
    0xFF, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x0A, 0x00, 0x0E,
    0x00, 0x0C, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01,
    0x00, 0x0B, 0x00, 0x02, 0x01, 0x00,
    0x00, 0x23, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x0E,
    0x00, 0x0C, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2F, 0x31, 0x2E, 0x31,
    0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x22, 0x00, 0x0A, 0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03,
    0x00, 0x33, 0x00, 0x6B, 0x00, 0x69, 0x00, 0x1D, 0x00, 0x20,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x00, 0x17, 0x00, 0x41, 0x04,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x00, 0x2B, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03,
    0x00, 0x0D, 0x00, 0x18, 0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05,
    0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01,
    0x00, 0x2D, 0x00, 0x02, 0x01, 0x01,
    0x00, 0x1C, 0x00, 0x02, 0x40, 0x01,
    0xFE, 0x0D, 0x01, 0x19, 0x00, 0x00, 0x01, 0x00, 0x01, 0xAA, 0x00, 0x20,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x00, 0xEF,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
};

static char* dumb_memmem(const char* haystack, unsigned int hlen,
                         const char* needle, unsigned int nlen)
{
    if (nlen > hlen) return NULL;
    size_t i;
    for (i = 0; i < hlen - nlen + 1; i++) {
        if (memcmp(haystack + i, needle, nlen) == 0) {
            return (char*)(haystack + i);
        }
    }
    return NULL;
}

static void mix_case(char *pktdata, unsigned int pktlen) {
    unsigned int i;
    if (pktlen <= 0) return;
    for (i = 0; i < pktlen; i++) {
        if (i % 2) {
            pktdata[i] = (char) toupper((unsigned char)pktdata[i]);
        }
    }
}

static int is_passivedpi_redirect(const char *pktdata, unsigned int pktlen) {
    if (pktlen < sizeof(http11_redirect_302)) return FALSE;
    if (memcmp(pktdata, http11_redirect_302, sizeof(http11_redirect_302) - 1) == 0 ||
        memcmp(pktdata, http10_redirect_302, sizeof(http10_redirect_302) - 1) == 0)
    {
        if (dumb_memmem(pktdata, pktlen, location_http, sizeof(location_http) - 1) &&
            dumb_memmem(pktdata, pktlen, connection_close, sizeof(connection_close) - 1)) {
            return TRUE;
        }
    }
    return FALSE;
}

static int find_header_and_get_info(const char *pktdata, unsigned int pktlen,
                const char *hdrname,
                char **hdrnameaddr,
                char **hdrvalueaddr, unsigned int *hdrvaluelen) {
    char *data_addr_rn;
    char *hdr_begin;

    *hdrvaluelen = 0u;
    *hdrnameaddr = NULL;
    *hdrvalueaddr = NULL;

    hdr_begin = dumb_memmem(pktdata, pktlen, hdrname, strlen(hdrname));
    if (!hdr_begin) return FALSE;
    if (pktdata > hdr_begin) return FALSE;

    *hdrnameaddr = hdr_begin;
    *hdrvalueaddr = hdr_begin + strlen(hdrname);

    data_addr_rn = dumb_memmem(*hdrvalueaddr,
                        pktlen - (uintptr_t)(*hdrvalueaddr - pktdata),
                        "\r\n", 2);
    if (data_addr_rn) {
        *hdrvaluelen = (uintptr_t)(data_addr_rn - *hdrvalueaddr);
        if (*hdrvaluelen >= 3 && *hdrvaluelen <= HOST_MAXLEN)
            return TRUE;
    }
    return FALSE;
}

static int extract_sni(const char *pktdata, unsigned int pktlen,
                    char **hostnameaddr, unsigned int *hostnamelen) {
    unsigned int ptr = 0;
    unsigned const char *d = (unsigned const char *)pktdata;
    unsigned const char *hnaddr = 0;
    int hnlen = 0;

    while (ptr + 8 < pktlen) {
        if (d[ptr] == '\0' && d[ptr+1] == '\0' && d[ptr+2] == '\0' &&
            d[ptr+4] == '\0' && d[ptr+6] == '\0' && d[ptr+7] == '\0' &&
            d[ptr+3] - d[ptr+5] == 2 && d[ptr+5] - d[ptr+8] == 3)
        {
            if (ptr + 8 + d[ptr+8] > pktlen) {
                return FALSE;
            }
            hnaddr = &d[ptr+9];
            hnlen = d[ptr+8];
            if (hnlen < 3 || hnlen > HOST_MAXLEN) {
                return FALSE;
            }
            for (int i = 0; i < hnlen; i++) {
                if (!((hnaddr[i] >= '0' && hnaddr[i] <= '9') ||
                      (hnaddr[i] >= 'a' && hnaddr[i] <= 'z') ||
                      hnaddr[i] == '.' || hnaddr[i] == '-'))
                {
                    return FALSE;
                }
            }
            *hostnameaddr = (char*)hnaddr;
            *hostnamelen = (unsigned int)hnlen;
            return TRUE;
        }
        ptr++;
    }
    return FALSE;
}

static PVOID find_http_method_end(const char *pkt, unsigned int pktlen, unsigned int http_frag, int *is_fragmented) {
    unsigned int i;
    for (i = 0; i < (sizeof(http_methods) / sizeof(*http_methods)); i++) {
        size_t mlen = strlen(http_methods[i]);
        if (pktlen >= mlen && memcmp(pkt, http_methods[i], mlen) == 0) {
            if (is_fragmented) *is_fragmented = 0;
            return (char*)pkt + mlen - 1;
        }
        if ((http_frag == 1 || http_frag == 2) &&
            pktlen >= (mlen - http_frag) &&
            memcmp(pkt, http_methods[i] + http_frag, mlen - http_frag) == 0)
        {
            if (is_fragmented) *is_fragmented = 1;
            return (char*)pkt + mlen - http_frag - 1;
        }
    }
    return NULL;
}

static void set_uint16be(unsigned char *buffer, int offset, int value) {
    buffer[offset] = (value >> 8) & 0xFF;
    buffer[offset + 1] = value & 0xFF;
}

JNIEXPORT jstring JNICALL
Java_com_goodbyedpi_turkey_GoodbyeDpiEngine_nativeGetVersion(JNIEnv *env, jobject thiz) {
    return (*env)->NewStringUTF(env, GOODBYEDPI_VERSION);
}

JNIEXPORT jstring JNICALL
Java_com_goodbyedpi_turkey_GoodbyeDpiEngine_nativeExtractSni(JNIEnv *env, jobject thiz, jbyteArray packet) {
    if (!packet) return NULL;
    jsize len = (*env)->GetArrayLength(env, packet);
    if (len <= 8) return NULL;

    jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
    char *host_addr = NULL;
    unsigned int host_len = 0;
    jstring result = NULL;

    if (extract_sni((const char*)bytes, (unsigned int)len, &host_addr, &host_len)) {
        char buf[HOST_MAXLEN + 1];
        memcpy(buf, host_addr, host_len);
        buf[host_len] = '\0';
        result = (*env)->NewStringUTF(env, buf);
    }

    (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
    return result;
}

JNIEXPORT jint JNICALL
Java_com_goodbyedpi_turkey_GoodbyeDpiEngine_nativeCalcTlsSplitOffset(JNIEnv *env, jobject thiz, jbyteArray packet, jboolean fragBySni) {
    if (!packet) return -1;
    jsize len = (*env)->GetArrayLength(env, packet);
    if (len < 3) return -1;

    jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
    const unsigned char *u = (const unsigned char*)bytes;
    int offset = -1;

    // Check TLS Handshake ClientHello signature (\x16\x03\x01 .. \x16\x03\x03)
    if (u[0] == 0x16 && u[1] == 0x03 && (u[2] >= 0x01 && u[2] <= 0x03)) {
        offset = 2; // Default GoodbyeDPI -e 2 split size
        if (fragBySni) {
            char *host_addr = NULL;
            unsigned int host_len = 0;
            if (extract_sni((const char*)bytes, (unsigned int)len, &host_addr, &host_len)) {
                int sni_offset = (int)(host_addr - (const char*)bytes);
                if (sni_offset > 2 && sni_offset < len) {
                    offset = sni_offset;
                }
            }
        }
    }

    (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
    return offset;
}

JNIEXPORT jbyteArray JNICALL
Java_com_goodbyedpi_turkey_GoodbyeDpiEngine_nativeTransformHttpPayload(
        JNIEnv *env, jobject thiz, jbyteArray packet,
        jboolean replaceHost, jboolean mixHostCase, jboolean removeSpace) {
    if (!packet) return NULL;
    jsize len = (*env)->GetArrayLength(env, packet);
    if (len <= 16) return packet;

    jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
    char *buf = malloc(len);
    memcpy(buf, bytes, len);
    (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);

    int fragmented = 0;
    if (find_http_method_end(buf, (unsigned int)len, 2, &fragmented)) {
        char *hdr_name_addr = NULL;
        char *hdr_value_addr = NULL;
        unsigned int hdr_value_len = 0;

        if (find_header_and_get_info(buf, (unsigned int)len, http_host_find,
                                     &hdr_name_addr, &hdr_value_addr, &hdr_value_len) &&
            hdr_value_len > 0 && hdr_value_len <= HOST_MAXLEN)
        {
            char *host_addr = hdr_value_addr;
            unsigned int host_len = hdr_value_len;

            if (mixHostCase) {
                mix_case(host_addr, host_len);
            }
            if (replaceHost) {
                memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
            }
            if (removeSpace) {
                char *ua_name = NULL, *ua_val = NULL;
                unsigned int ua_len = 0;
                if (find_header_and_get_info(buf, (unsigned int)len, http_useragent_find,
                                             &ua_name, &ua_val, &ua_len) &&
                    ua_val && ua_len > 0)
                {
                    if (ua_val > host_addr) {
                        memmove(host_addr - 1, host_addr, (size_t)(ua_val + ua_len - host_addr));
                        *(char*)((unsigned char*)ua_val + ua_len - 1) = ' ';
                    } else {
                        memmove(ua_val + ua_len + 1, ua_val + ua_len,
                                (size_t)(host_addr - 1 - (ua_val + ua_len)));
                        *(char*)((unsigned char*)ua_val + ua_len) = ' ';
                    }
                }
            }
        }
    }

    jbyteArray out = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, out, 0, len, (const jbyte*)buf);
    free(buf);
    return out;
}

JNIEXPORT jboolean JNICALL
Java_com_goodbyedpi_turkey_GoodbyeDpiEngine_nativeIsPassiveDpiRedirect(JNIEnv *env, jobject thiz, jbyteArray packet) {
    if (!packet) return JNI_FALSE;
    jsize len = (*env)->GetArrayLength(env, packet);
    if (len <= 16) return JNI_FALSE;

    jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
    int res = is_passivedpi_redirect((const char*)bytes, (unsigned int)len);
    (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
    return res ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_goodbyedpi_turkey_GoodbyeDpiEngine_nativeIsQuicInitial(JNIEnv *env, jobject thiz, jint dstPort, jbyteArray udpPayload) {
    if (!udpPayload || dstPort != 443) return JNI_FALSE;
    jsize len = (*env)->GetArrayLength(env, udpPayload);
    // FILTER_PASSIVE_BLOCK_QUIC:
    // udp.DstPort == 443 and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xC0 and udp.Payload32[1b] == 0x01
    if (len < 1200) return JNI_FALSE;

    jbyte *bytes = (*env)->GetByteArrayElements(env, udpPayload, NULL);
    const unsigned char *u = (const unsigned char*)bytes;
    jboolean is_quic = JNI_FALSE;
    if (u[0] >= 0xC0 && u[1] == 0x00 && u[2] == 0x00 && u[3] == 0x00 && u[4] == 0x01) {
        is_quic = JNI_TRUE;
    }
    (*env)->ReleaseByteArrayElements(env, udpPayload, bytes, JNI_ABORT);
    return is_quic;
}

JNIEXPORT jbyteArray JNICALL
Java_com_goodbyedpi_turkey_GoodbyeDpiEngine_nativeBuildFakeClientHello(JNIEnv *env, jobject thiz, jstring domainName) {
    const char *domain = domainName ? (*env)->GetStringUTFChars(env, domainName, NULL) : "www.w3.org";
    const int name_size = (int)strlen(domain);
    const int part0_size = sizeof(fake_clienthello_part0);
    const int part1_size = sizeof(fake_clienthello_part1);
    const int sni_head_size = 9;
    const int packet_size = part0_size + part1_size + sni_head_size + name_size;

    unsigned char *packet = malloc(packet_size);
    memcpy(packet, fake_clienthello_part0, part0_size);
    memcpy(&packet[part0_size + sni_head_size + name_size], fake_clienthello_part1, part1_size);

    for (int i = 0; i < packet_size; i++) {
        if (packet[i] == 0xAA) {
            packet[i] = (unsigned char)((i * 37 + 19) & 0xFF);
        }
    }

    set_uint16be(packet, 0x0003, packet_size - 5);
    set_uint16be(packet, 0x0007, packet_size - 9);
    set_uint16be(packet, 0x0072, packet_size - 116);
    set_uint16be(packet, part0_size + 0, 0x0000);
    set_uint16be(packet, part0_size + 2, name_size + 5);
    set_uint16be(packet, part0_size + 4, name_size + 3);
    packet[part0_size + 6] = 0x00;
    set_uint16be(packet, part0_size + 7, name_size);
    memcpy(&packet[part0_size + sni_head_size], domain, name_size);

    if (domainName) {
        (*env)->ReleaseStringUTFChars(env, domainName, domain);
    }

    jbyteArray out = (*env)->NewByteArray(env, packet_size);
    (*env)->SetByteArrayRegion(env, out, 0, packet_size, (const jbyte*)packet);
    free(packet);
    return out;
}

JNIEXPORT jboolean JNICALL
Java_com_goodbyedpi_turkey_GoodbyeDpiEngine_nativeIsDnsPacket(JNIEnv *env, jobject thiz, jbyteArray payload, jboolean outgoing) {
    if (!payload) return JNI_FALSE;
    jsize len = (*env)->GetArrayLength(env, payload);
    if (len < 16) return JNI_FALSE;

    jbyte *bytes = (*env)->GetByteArrayElements(env, payload, NULL);
    int res = dns_is_dns_packet((const char*)bytes, (UINT)len, outgoing ? 1 : 0);
    (*env)->ReleaseByteArrayElements(env, payload, bytes, JNI_ABORT);
    return res ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_goodbyedpi_turkey_GoodbyeDpiEngine_nativeGetAutoTtl(
        JNIEnv *env, jobject thiz, jint ttl, jint autottl1, jint autottl2, jint minhops, jint maxttl) {
    return tcp_get_auto_ttl((uint8_t)ttl, (uint8_t)autottl1, (uint8_t)autottl2, (uint8_t)minhops, (uint8_t)maxttl);
}
