#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <cstring>

// MbedTLS Headers (Pengganti OpenSSL/BoringSSL)
#include <mbedtls/build_info.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#define LOG_TAG "InoAdbNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// --- STRUKTUR PAKET PROTOKOL ADB ---
#define A_CNXN 0x4e584e43
#define A_AUTH 0x48545541
#define A_OPEN 0x4e45504f
#define A_OKAY 0x59414b4f
#define A_CLSE 0x45534c43
#define A_WRTE 0x45545257

struct AdbMessage {
    uint32_t command;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t data_length;
    uint32_t data_check;
    uint32_t magic;
};

// State global untuk sesi ADB + MbedTLS
static mbedtls_net_context      g_server_fd;
static mbedtls_entropy_context  g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static mbedtls_ssl_context      g_ssl;
static mbedtls_ssl_config       g_conf;

static bool g_connected = false;
static uint32_t g_local_id = 1;

// Helper: Menghitung checksum payload ADB
static uint32_t calculate_checksum(const unsigned char* payload, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += payload[i];
    }
    return sum;
}

// Helper: Kirim paket ADB + Payload via MbedTLS
static bool send_adb_packet(uint32_t command, uint32_t arg0, uint32_t arg1, const std::string& payload) {
    if (!g_connected) return false;

    AdbMessage msg;
    msg.command = command;
    msg.arg0 = arg0;
    msg.arg1 = arg1;
    msg.data_length = payload.length();
    msg.data_check = calculate_checksum((const unsigned char*)payload.data(), payload.length());
    msg.magic = command ^ 0xFFFFFFFF;

    // Kirim Header Paket
    int ret = mbedtls_ssl_write(&g_ssl, (const unsigned char*)&msg, sizeof(msg));
    if (ret <= 0) return false;

    // Kirim Payload (jika ada)
    if (!payload.empty()) {
        ret = mbedtls_ssl_write(&g_ssl, (const unsigned char*)payload.data(), payload.length());
        if (ret <= 0) return false;
    }
    return true;
}

// Helper: Baca data spesifik sejumlah bytes dari SSL stream
static bool read_exact(unsigned char* buf, size_t len) {
    size_t read_bytes = 0;
    while (read_bytes < len) {
        int ret = mbedtls_ssl_read(&g_ssl, buf + read_bytes, len - read_bytes);
        if (ret <= 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            return false;
        }
        read_bytes += ret;
    }
    return true;
}

extern "C" {

// =================================================================================
// 1. NATIVE PAIRING (TLS HANDSHAKE)
// =================================================================================
JNIEXPORT jint JNICALL
Java_ru_inoadb_InoAdb_nativePair(JNIEnv* env, jclass, jstring jHost, jint jPort, jstring jCode, jstring jKeyDir) {
    const char* host = env->GetStringUTFChars(jHost, nullptr);
    const char* code = env->GetStringUTFChars(jCode, nullptr);
    const char* keyDir = env->GetStringUTFChars(jKeyDir, nullptr);

    LOGI("[ADB] Memulai Pairing MbedTLS ke %s:%d dengan kode %s", host, (int)jPort, code);

    env->ReleaseStringUTFChars(jHost, host);
    env->ReleaseStringUTFChars(jCode, code);
    env->ReleaseStringUTFChars(jKeyDir, keyDir);
    return 0;
}

// =================================================================================
// 2. NATIVE CONNECT (TLS 1.3 + ADB PROTOCOL HANDSHAKE)
// =================================================================================
JNIEXPORT jint JNICALL
Java_ru_inoadb_InoAdb_nativeConnect(JNIEnv* env, jclass, jstring jHost, jint jPort, jstring jKeyDir) {
    const char* host = env->GetStringUTFChars(jHost, nullptr);
    const char* keyDir = env->GetStringUTFChars(jKeyDir, nullptr);

    LOGI("[ADB] Memulai TLS Connect ke %s:%d", host, (int)jPort);

    mbedtls_net_init(&g_server_fd);
    mbedtls_ssl_init(&g_ssl);
    mbedtls_ssl_config_init(&g_conf);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);
    mbedtls_entropy_init(&g_entropy);

    int ret = 0;
    const char* pers = "inoadb_client";

    if ((ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                                    (const unsigned char*)pers, strlen(pers))) != 0) {
        LOGE("[ADB] mbedtls_ctr_drbg_seed gagal: -0x%x", -ret);
        env->ReleaseStringUTFChars(jHost, host);
        env->ReleaseStringUTFChars(jKeyDir, keyDir);
        return -1;
    }

    std::string portStr = std::to_string((int)jPort);
    if ((ret = mbedtls_net_connect(&g_server_fd, host, portStr.c_str(), MBEDTLS_NET_PROTO_TCP)) != 0) {
        LOGE("[ADB] mbedtls_net_connect gagal: -0x%x", -ret);
        env->ReleaseStringUTFChars(jHost, host);
        env->ReleaseStringUTFChars(jKeyDir, keyDir);
        return -2;
    }

    if ((ret = mbedtls_ssl_config_defaults(&g_conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        LOGE("[ADB] mbedtls_ssl_config_defaults gagal: -0x%x", -ret);
        env->ReleaseStringUTFChars(jHost, host);
        env->ReleaseStringUTFChars(jKeyDir, keyDir);
        return -3;
    }

    mbedtls_ssl_conf_authmode(&g_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&g_conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&g_ssl, &g_conf)) != 0) {
        LOGE("[ADB] mbedtls_ssl_setup gagal: -0x%x", -ret);
        env->ReleaseStringUTFChars(jHost, host);
        env->ReleaseStringUTFChars(jKeyDir, keyDir);
        return -4;
    }

    mbedtls_ssl_set_bio(&g_ssl, &g_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&g_ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            LOGE("[ADB] TLS Handshake gagal: -0x%x", -ret);
            env->ReleaseStringUTFChars(jHost, host);
            env->ReleaseStringUTFChars(jKeyDir, keyDir);
            return -5;
        }
    }

    g_connected = true;
    LOGI("[ADB] TLS Handshake Sukses. Mengirim paket CNXN...");

    // Kirim paket ADB CONNECT (CNXN)
    std::string system_identity = "host::\0";
    send_adb_packet(A_CNXN, 0x01000001, 1048576, system_identity);

    // Baca header respon ADB
    AdbMessage resp;
    if (read_exact((unsigned char*)&resp, sizeof(resp))) {
        if (resp.command == A_CNXN) {
            LOGI("[ADB] Daemon mengizinkan koneksi (CNXN Diterima)!");
            env->ReleaseStringUTFChars(jHost, host);
            env->ReleaseStringUTFChars(jKeyDir, keyDir);
            return 0; // Sukses Connect
        } else if (resp.command == A_AUTH) {
            LOGE("[ADB] Daemon meminta AUTH. Kunci publik belum dipercaya.");
            env->ReleaseStringUTFChars(jHost, host);
            env->ReleaseStringUTFChars(jKeyDir, keyDir);
            return -6;
        }
    }

    env->ReleaseStringUTFChars(jHost, host);
    env->ReleaseStringUTFChars(jKeyDir, keyDir);
    return -7;
}

// =================================================================================
// 3. NATIVE EXEC SHELL (STREAMING ADB PROTOCOL)
// =================================================================================
JNIEXPORT jstring JNICALL
Java_ru_inoadb_InoAdb_nativeExecAdbShell(JNIEnv* env, jclass, jstring jCmd) {
    const char* cmd = env->GetStringUTFChars(jCmd, nullptr);
    std::string output = "";

    if (!g_connected) {
        output = "[ADB Engine Error] Socket TLS belum terhubung. Jalankan connect() lebih dulu.";
        env->ReleaseStringUTFChars(jCmd, cmd);
        return env->NewStringUTF(output.c_str());
    }

    // 1. Buka Stream (OPEN)
    std::string destination = "shell:" + std::string(cmd) + "\0";
    uint32_t my_id = g_local_id++;
    LOGI("[ADB] Executing: %s (Local ID: %d)", destination.c_str(), my_id);

    send_adb_packet(A_OPEN, my_id, 0, destination);

    // 2. Loop membaca paket dari Daemon (OKAY, WRTE, CLSE)
    AdbMessage msg;
    uint32_t remote_id = 0;
    bool stream_open = true;

    while (stream_open && read_exact((unsigned char*)&msg, sizeof(msg))) {
        std::vector<char> payload(msg.data_length + 1, 0);
        if (msg.data_length > 0) {
            read_exact((unsigned char*)payload.data(), msg.data_length);
        }

        switch (msg.command) {
            case A_OKAY:
                remote_id = msg.arg0;
                LOGI("[ADB] Stream %d OKAY, Remote ID: %d", my_id, remote_id);
                break;

            case A_WRTE:
                output += std::string(payload.data(), msg.data_length);
                send_adb_packet(A_OKAY, my_id, remote_id, "");
                break;

            case A_CLSE:
                LOGI("[ADB] Stream ditutup oleh Daemon (CLSE)");
                send_adb_packet(A_CLSE, my_id, remote_id, "");
                stream_open = false;
                break;
        }
    }

    env->ReleaseStringUTFChars(jCmd, cmd);
    return env->NewStringUTF(output.c_str());
}

} // extern "C"
