#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT 55443
#define CERT_FILE "certificado_auto_firmado.crt"
#define KEY_FILE  "llave_privada.pem"

int main() {
    int sockfd, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Inicializar la biblioteca OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Crear contexto SSL
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Cargar el certificado digital
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Cargar la llave privada
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Verificar que la llave privada coincide con el certificado público
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "La llave privada no coincide con el certificado público\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Crear un socket TCP/IP
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error al crear el socket");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Configurar la estructura de dirección del servidor
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;          // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Cualquier dirección entrante
    server_addr.sin_port = htons(SERVER_PORT); // Puerto

    // Enlazar el socket a la dirección y puerto especificados
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error al enlazar el socket");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Poner el socket en modo de escucha
    if (listen(sockfd, 1) < 0) {
        perror("Error al poner el socket en modo de escucha");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    printf("Servidor escuchando en el puerto %d...\n", SERVER_PORT);

    // Aceptar conexiones entrantes
    client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock < 0) {
        perror("Error al aceptar la conexión");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    printf("Conexión aceptada.\n");

    // Crear un objeto SSL y asociarlo al socket del cliente
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);

    // Realizar el handshake SSL/TLS
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    printf("Handshake SSL/TLS completado.\n");

    // Leer datos del cliente
    char buffer[1024] = {0};
    int bytes_leidos = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_leidos <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Mensaje recibido del cliente: %s\n", buffer);
    }

    // Enviar respuesta al cliente
    const char *respuesta = "¡Hola cliente!";
    if (SSL_write(ssl, respuesta, strlen(respuesta)) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Respuesta enviada al cliente: %s\n", respuesta);
    }

    // Cerrar la conexión SSL/TLS y liberar recursos
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);
    close(sockfd);
    SSL_CTX_free(ctx);
    printf("Conexión cerrada.\n");

    return 0;
}

