#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <thread>

// Header BoringSSL / OpenSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

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

// State global untuk sesi ADB yang aktif
static int g_adb_socket = -1;
static SSL_CTX* g_ssl_ctx = nullptr;
static SSL* g_ssl_session = nullptr;
static uint32_t g_local_id = 1;

// Helper: Menghitung checksum payload ADB
static uint32_t calculate_checksum(const unsigned char* payload, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += payload[i];
    }
    return sum;
}

// Helper: Kirim paket ADB + Payload via TLS
static bool send_adb_packet(uint32_t command, uint32_t arg0, uint32_t arg1, const std::string& payload) {
    if (!g_ssl_session) return false;

    AdbMessage msg;
    msg.command = command;
    msg.arg0 = arg0;
    msg.arg1 = arg1;
    msg.data_length = payload.length();
    msg.data_check = calculate_checksum((const unsigned char*)payload.data(), payload.length());
    msg.magic = command ^ 0xFFFFFFFF;

    // Kirim Header
    if (SSL_write(g_ssl_session, &msg, sizeof(msg)) <= 0) return false;
    // Kirim Payload (jika ada)
    if (!payload.empty()) {
        if (SSL_write(g_ssl_session, payload.data(), payload.length()) <= 0) return false;
    }
    return true;
}

extern "C" {

// =================================================================================
// 1. NATIVE PAIRING (SPAKE2 + TLS HANDSHAKE)
// =================================================================================
JNIEXPORT jint JNICALL
Java_ru_inoadb_InoAdb_nativePair(JNIEnv* env, jclass, jstring jHost, jint jPort, jstring jCode, jstring jKeyDir) {
    const char* host = env->GetStringUTFChars(jHost, nullptr);
    const char* code = env->GetStringUTFChars(jCode, nullptr);
    const char* keyDir = env->GetStringUTFChars(jKeyDir, nullptr);

    LOGI("[ADB] Memulai SPAKE2 Pairing ke %s:%d dengan kode %s", host, (int)jPort, code);

    // Di sini adalah integrasi dengan modul AOSP pairing_connection.cpp
    // 1. Buat koneksi TCP ke host:port
    // 2. Inisialisasi BoringSSL dengan kurva SPAKE2
    // 3. Verifikasi kode pairing (Ed25519)
    // 4. Simpan sertifikat ke keyDir/adbkey dan keyDir/adbkey.pub
    
    // CATATAN: Untuk saat ini kita return 0 (sukses) 
    // agar bisa lanjut menguji koneksi JNI ke Java.
    // Implementasi kriptografi penuh membutuhkan linking AOSP libadbd.

    env->ReleaseStringUTFChars(jHost, host);
    env->ReleaseStringUTFChars(jCode, code);
    env->ReleaseStringUTFChars(jKeyDir, keyDir);
    return 0;
}


// =================================================================================
// 2. NATIVE CONNECT (TLS 1.3 & ADB PROTOCOL HANDSHAKE)
// =================================================================================
JNIEXPORT jint JNICALL
Java_ru_inoadb_InoAdb_nativeConnect(JNIEnv* env, jclass, jstring jHost, jint jPort, jstring jKeyDir) {
    const char* host = env->GetStringUTFChars(jHost, nullptr);
    const char* keyDir = env->GetStringUTFChars(jKeyDir, nullptr);

    LOGI("[ADB] Memulai TLS Connect ke %s:%d", host, (int)jPort);

    // Buka Socket TCP
    g_adb_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((int)jPort);
    inet_pton(AF_INET, host, &server_addr.sin_addr);

    if (connect(g_adb_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        LOGE("[ADB] Gagal connect socket TCP");
        return -1;
    }

    // Inisialisasi SSL Context
    SSL_library_init();
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    
    // TODO: Muat sertifikat (adbkey) dari keyDir menggunakan SSL_CTX_use_PrivateKey_file
    
    g_ssl_session = SSL_new(g_ssl_ctx);
    SSL_set_fd(g_ssl_session, g_adb_socket);

    if (SSL_connect(g_ssl_session) <= 0) {
        LOGE("[ADB] TLS Handshake gagal!");
        ERR_print_errors_fp(stderr);
        return -2;
    }

    LOGI("[ADB] TLS Handshake Sukses. Mengirim paket CNXN...");

    // Kirim paket ADB CONNECT (CNXN)
    std::string system_identity = "host::\0";
    // Versi protokol A_VERSION = 0x01000001, Max Payload = 1048576
    send_adb_packet(A_CNXN, 0x01000001, 1048576, system_identity);

    // Baca response (Harus A_CNXN atau A_AUTH)
    AdbMessage resp;
    if (SSL_read(g_ssl_session, &resp, sizeof(resp)) > 0) {
        if (resp.command == A_CNXN) {
            LOGI("[ADB] Daemon mengizinkan koneksi (CNXN Diterima)!");
            env->ReleaseStringUTFChars(jHost, host);
            env->ReleaseStringUTFChars(jKeyDir, keyDir);
            return 0; // Sukses Connect
        } else if (resp.command == A_AUTH) {
            LOGE("[ADB] Daemon meminta AUTH. Kunci publik belum dipercaya.");
            return -3;
        }
    }

    env->ReleaseStringUTFChars(jHost, host);
    env->ReleaseStringUTFChars(jKeyDir, keyDir);
    return -4;
}


// =================================================================================
// 3. NATIVE EXEC SHELL (STREAMING ADB PROTOCOL)
// =================================================================================
JNIEXPORT jstring JNICALL
Java_ru_inoadb_InoShell_nativeExecAdbShell(JNIEnv* env, jclass, jstring jCmd) {
    const char* cmd = env->GetStringUTFChars(jCmd, nullptr);
    std::string output = "";

    if (!g_ssl_session) {
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

    while (stream_open && SSL_read(g_ssl_session, &msg, sizeof(msg)) > 0) {
        // Baca payload jika ada
        std::vector<char> payload(msg.data_length + 1, 0);
        if (msg.data_length > 0) {
            SSL_read(g_ssl_session, payload.data(), msg.data_length);
        }

        switch (msg.command) {
            case A_OKAY:
                remote_id = msg.arg0;
                LOGI("[ADB] Stream %d OKAY, Remote ID: %d", my_id, remote_id);
                break;
                
            case A_WRTE:
                // Daemon mengirim output text shell
                output += std::string(payload.data(), msg.data_length);
                // Kita harus balas dengan OKAY agar daemon lanjut mengirim
                send_adb_packet(A_OKAY, my_id, remote_id, "");
                break;
                
            case A_CLSE:
                LOGI("[ADB] Stream ditutup oleh Daemon (CLSE)");
                // Balas CLSE
                send_adb_packet(A_CLSE, my_id, remote_id, "");
                stream_open = false;
                break;
        }
    }

    env->ReleaseStringUTFChars(jCmd, cmd);
    return env->NewStringUTF(output.c_str());
}

} // extern "C"
