#pragma comment(lib, "ws2_32.lib")
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#pragma warning(disable: 4996)

SOCKET Connection;

void ClientHandler(RSA* rsa_public_key) {
    int msg_size;
    while (true) {
        recv(Connection, (char*)&msg_size, sizeof(int), NULL);
        unsigned char* encrypted = new unsigned char[msg_size];
        recv(Connection, (char*)encrypted, msg_size, NULL);

        // Расшифрование сообщения с помощью RSA
        char* decrypted = new char[RSA_size(rsa_public_key)];
        int decrypted_length = RSA_private_decrypt(msg_size, encrypted, (unsigned char*)decrypted, rsa_public_key, RSA_PKCS1_PADDING);
        if (decrypted_length == -1) {
            std::cerr << "Decryption failed" << std::endl;
        }
        else {
            std::cout << decrypted << std::endl;
        }

        delete[] encrypted;
        delete[] decrypted;
    }
}

int main(int argc, char* argv[]) {
    // Инициализация OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Загрузка публичного ключа RSA из файла
    FILE* fp = fopen("public_key.pem", "rb");
    if (!fp) {
        std::cerr << "Failed to open public key file" << std::endl;
        return 1;
    }
    RSA* rsa_public_key = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    if (!rsa_public_key) {
        std::cerr << "Failed to read public key" << std::endl;
        return 1;
    }
    fclose(fp);

    // WSAStartup
    WSAData wsaData;
    WORD DLLVersion = MAKEWORD(2, 1);
    if (WSAStartup(DLLVersion, &wsaData) != 0) {
        std::cout << "Error" << std::endl;
        exit(1);
    }
    SOCKADDR_IN addr;
    int sizeofaddr = sizeof(addr);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(1111);
    addr.sin_family = AF_INET;
    Connection = socket(AF_INET, SOCK_STREAM, NULL);
    if (connect(Connection, (SOCKADDR*)&addr, sizeof(addr)) != 0) {
        std::cout << "Error: failed connect to server.\n";
        return 1;
    }
    std::cout << "Connected!\n";

    int msg_size;
    recv(Connection, (char*)&msg_size, sizeof(int), NULL);
    unsigned char* encrypted = new unsigned char[msg_size];
    recv(Connection, (char*)encrypted, msg_size, NULL);

    // Расшифрование приветственного сообщения с помощью RSA
    char* decrypted = new char[RSA_size(rsa_public_key)];
    int decrypted_length = RSA_public_decrypt(msg_size, encrypted, (unsigned char*)decrypted, rsa_public_key, RSA_PKCS1_PADDING);
    if (decrypted_length == -1) {
        std::cerr << "Decryption failed";
            std::cerr << "Decryption failed" << std::endl;
    }
    else {
        std::cout << decrypted << std::endl;
    }

    delete[] encrypted;
    delete[] decrypted;

    // Создание потока для обработки сообщений от сервера
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ClientHandler, (LPVOID)rsa_public_key, NULL, NULL);

    std::string msg;
    while (true) {
        std::getline(std::cin, msg);

        // Шифрование сообщения с помощью RSA
        unsigned char* encrypted = new unsigned char[RSA_size(rsa_public_key)];
        int encrypted_length = RSA_public_encrypt(msg.length(), (unsigned char*)msg.c_str(), encrypted, rsa_public_key, RSA_PKCS1_PADDING);
        if (encrypted_length == -1) {
            std::cerr << "Encryption failed" << std::endl;
        }
        else {
            send(Connection, (char*)&encrypted_length, sizeof(int), NULL);
            send(Connection, (char*)encrypted, encrypted_length, NULL);
        }

        delete[] encrypted;
        Sleep(10);
    }

    // Очистка
    RSA_free(rsa_public_key);
    EVP_cleanup();
    ERR_free_strings();

    system("pause");
    return 0;
}