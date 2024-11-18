#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1" // Dirección IP (localhost)
#define SERVER_PORT 55443     // Puerto para la conexión

int main() {
    int sock;
    struct sockaddr_in server_addr;

    // Inicializar la biblioteca OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Crear contexto SSL
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Crear un socket TCP/IP
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Error al crear el socket");
        exit(EXIT_FAILURE);
    }

    // Configurar la estructura de dirección del servidor
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Dirección IP no válida o no soportada");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Establecer conexión con el servidor
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error al conectar con el servidor");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("Conexión establecida con el servidor %s:%d\n", SERVER_IP, SERVER_PORT);

    // Crear un objeto SSL/TLS
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        ERR_print_errors_fp(stderr);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Asociar el socket con el objeto SSL
    SSL_set_fd(ssl, sock);

    // Realizar el handshake SSL/TLS
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    printf("Handshake SSL/TLS completado.\n");

    // Enviar mensaje al servidor
    const char *mensaje = "¡Hola, servidor!";
    if (SSL_write(ssl, mensaje, strlen(mensaje)) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    printf("Mensaje enviado al servidor: %s\n", mensaje);

    // Leer la respuesta del servidor
    char buffer[1024] = {0};
    int bytes_leidos = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_leidos <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Mensaje recibido del servidor: %s\n", buffer);
    }

    // Cerrar la conexión SSL/TLS y liberar recursos
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    printf("Conexión cerrada.\n");

    return 0;
}

