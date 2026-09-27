#include <jni.h>
#include <android/log.h>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define LOG_TAG "InoAdbNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Struktur status TLS session ADB
static int g_adb_fd = -1;
static SSL* g_ssl_session = nullptr;

extern "C" {

// 1. Native Pairing (SPAKE2 Handshake)
JNIEXPORT jint JNICALL
Java_ru_inoadb_InoAdb_nativePair(JNIEnv* env, jclass, jstring jHost, jint jPort,
                                 jstring jCode, jstring jKeyDir) {
    const char* host = env->GetStringUTFChars(jHost, nullptr);
    const char* code = env->GetStringUTFChars(jCode, nullptr);
    const char* keyDir = env->GetStringUTFChars(jKeyDir, nullptr);

    LOGI("Memulai SPAKE2 Pairing ke %s:%d dengan kode %s...", host, (int)jPort, code);

    // TODO: Panggil pairing_connection_client_new() dari AOSP pairing_connection.h
    // Menyimpan RSA/Ed25519 Certs ke folder keyDir jika sukses

    env->ReleaseStringUTFChars(jHost, host);
    env->ReleaseStringUTFChars(jCode, code);
    env->ReleaseStringUTFChars(jKeyDir, keyDir);

    return 0; // 0 = Sukses
}

// 2. Native Connect (TLS Handshake & ADB CNXN)
JNIEXPORT jint JNICALL
Java_ru_inoadb_InoAdb_nativeConnect(JNIEnv* env, jclass, jstring jHost, jint jPort, jstring jKeyDir) {
    const char* host = env->GetStringUTFChars(jHost, nullptr);
    const char* keyDir = env->GetStringUTFChars(jKeyDir, nullptr);

    LOGI("Connect TLS ke %s:%d (Keys: %s)...", host, (int)jPort, keyDir);

    // 1. Buka TCP Socket ke host:port
    // 2. Load cert & private key dari keyDir
    // 3. Lakukan SSL_do_handshake()
    // 4. Kirim ADB CNXN Header ("CNXN\x00\x00\x00\x01\x00\x00\x10\x00...")

    env->ReleaseStringUTFChars(jHost, host);
    env->ReleaseStringUTFChars(jKeyDir, keyDir);

    return 0; // 0 = Connected
}

// 3. Native Exec Shell (ADB OPEN stream: "shell:<cmd>")
JNIEXPORT jstring JNICALL
Java_ru_inoadb_InoShell_nativeExecAdbShell(JNIEnv* env, jclass, jstring jCmd) {
    const char* cmd = env->GetStringUTFChars(jCmd, nullptr);
    std::string response = "";

    if (g_adb_fd < 0) {
        response = "[ADB Engine Error] Socket belum terhubung. Jalankan connect() lebih dulu.";
    } else {
        // 1. Kirim ADB OPEN Packet -> "shell:<cmd>"
        // 2. Read stream buffer dari daemon ADB sampai CLSE
        response = "Output dari ADB Shell: " + std::string(cmd);
    }

    env->ReleaseStringUTFChars(jCmd, cmd);
    return env->NewStringUTF(response.c_str());
}

} // extern "C"
