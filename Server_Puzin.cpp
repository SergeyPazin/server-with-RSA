#pragma comment(lib, "ws2_32.lib")
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#pragma warning(disable: 4996)

SOCKET Connections[100];
int Counter = 0;

void ClientHandler(int index, RSA* rsa_private_key) {
    int msg_size;
    while (true) {
        recv(Connections[index], (char*)&msg_size, sizeof(int), NULL);
        char* msg = new char[msg_size + 1];
        msg[msg_size] = '\0';
        recv(Connections[index], msg, msg_size, NULL);

        // Шифрование сообщения с помощью RSA
        unsigned char* encrypted = new unsigned char[RSA_size(rsa_private_key)];
        int encrypted_length = RSA_public_encrypt(msg_size, (unsigned char*)msg, encrypted, rsa_private_key, RSA_PKCS1_PADDING);
        if (encrypted_length == -1) {
            std::cerr << "Encryption failed" << std::endl;
        }
        else {
            for (int i = 0; i < Counter; i++) {
                if (i == index) {
                    continue;
                }
                send(Connections[i], (char*)&encrypted_length, sizeof(int), NULL);
                send(Connections[i], (char*)encrypted, encrypted_length, NULL);
            }
        }

        delete[] msg;
        delete[] encrypted;
    }
}

int main(int argc, char* argv[]) {
    // Инициализация OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Загрузка приватного ключа RSA из файла
    FILE* fp = fopen("private_key.pem", "rb");
    if (!fp) {
        std::cerr << "Failed to open private key file" << std::endl;
        return 1;
    }
    RSA* rsa_private_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if (!rsa_private_key) {
        std::cerr << "Failed to read private key" << std::endl;
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

    SOCKET sListen = socket(AF_INET, SOCK_STREAM, NULL);
    bind(sListen, (SOCKADDR*)&addr, sizeof(addr));
    listen(sListen, SOMAXCONN);

    SOCKET newConnection;
    while (true) {
        newConnection = accept(sListen, (SOCKADDR*)&addr, &sizeofaddr);
        if (newConnection == 0) {
            std::cout << "Error#2\n";
        }
        else {
            std::cout << "Client Connected!\n";
            std::string msg = "Hello dear user.";
            int msg_size = msg.size();

            // Шифрование приветственного сообщения с помощью RSA
            unsigned char* encrypted = new unsigned char[RSA_size(rsa_private_key)];
            int encrypted_length = RSA_private_encrypt(msg_size, (unsigned char*)msg.c_str(), encrypted, rsa_private_key, RSA_PKCS1_PADDING);
            if (encrypted_length == -1) {
                std::cerr << "Encryption failed" << std::endl;
            }
            else {
                send(newConnection, (char*)&encrypted_length, sizeof(int), NULL);
                send(newConnection, (char*)encrypted, encrypted_length, NULL);
            }
            delete[] encrypted;

            Connections[Counter] = newConnection;
            Counter++;
            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ClientHandler, (LPVOID)(Counter - 1), NULL, NULL);
        }
    }

    // Освобождение памяти
    RSA_free(rsa_private_key);
    EVP_cleanup();
    ERR_free_strings();

    system("pause");
    return 0;
}