#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE *archivo, *archivoCifrado, *archivoDescifrado;
    char *textoPlano;
    long tamanoArchivo;
    EVP_PKEY *clavePublica = NULL;
    EVP_PKEY *clavePrivada = NULL;
    EVP_PKEY_CTX *ctx;
    unsigned char *mensajeCifrado;
    unsigned char *mensajeDescifrado;
    size_t longitudCifrada, longitudDescifrada;
    int resultado;
    FILE *archivoClavePublica, *archivoClavePrivada;

    // Abrir el archivo textoclaro.txt en modo lectura
    archivo = fopen("textoclaro.txt", "r");
    if (archivo == NULL) {
        printf("Error al abrir el archivo textoclaro.txt.\n");
        return 1;
    }

    // Obtener el tamaño del archivo
    fseek(archivo, 0, SEEK_END);
    tamanoArchivo = ftell(archivo);
    rewind(archivo);

    // Reservar memoria para almacenar el contenido del archivo
    textoPlano = (char *)malloc((tamanoArchivo + 1) * sizeof(char));
    if (textoPlano == NULL) {
        printf("Error al asignar memoria.\n");
        fclose(archivo);
        return 1;
    }

    // Leer el contenido del archivo y almacenarlo en la variable textoPlano
    fread(textoPlano, sizeof(char), tamanoArchivo, archivo);
    textoPlano[tamanoArchivo] = '\0';
    fclose(archivo);

    // Abrir el archivo de la clave pública
    archivoClavePublica = fopen("llave_publica.pem", "r");
    if (archivoClavePublica == NULL) {
        printf("Error al abrir el archivo llave_publica.pem.\n");
        free(textoPlano);
        return 1;
    }

    // Cargar la clave pública desde el archivo PEM usando la función moderna EVP
    clavePublica = PEM_read_PUBKEY(archivoClavePublica, NULL, NULL, NULL);
    if (clavePublica == NULL) {
        printf("Error al leer la clave pública.\n");
        free(textoPlano);
        fclose(archivoClavePublica);
        return 1;
    }
    fclose(archivoClavePublica);

    // Crear el contexto para el cifrado
    ctx = EVP_PKEY_CTX_new(clavePublica, NULL);
    if (!ctx) {
        printf("Error al crear el contexto.\n");
        EVP_PKEY_free(clavePublica);
        free(textoPlano);
        return 1;
    }

    // Inicializar el contexto para cifrado
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        printf("Error en la inicialización de cifrado.\n");
        EVP_PKEY_free(clavePublica);
        EVP_PKEY_CTX_free(ctx);
        free(textoPlano);
        return 1;
    }

    // Determinar el tamaño del mensaje cifrado
    if (EVP_PKEY_encrypt(ctx, NULL, &longitudCifrada, (unsigned char *)textoPlano, strlen(textoPlano)) <= 0) {
        printf("Error al determinar el tamaño del mensaje cifrado.\n");
        EVP_PKEY_free(clavePublica);
        EVP_PKEY_CTX_free(ctx);
        free(textoPlano);
        return 1;
    }

    // Reservar memoria para el mensaje cifrado
    mensajeCifrado = (unsigned char *)malloc(longitudCifrada);
    if (!mensajeCifrado) {
        printf("Error al asignar memoria para el mensaje cifrado.\n");
        EVP_PKEY_free(clavePublica);
        EVP_PKEY_CTX_free(ctx);
        free(textoPlano);
        return 1;
    }

    // Cifrar el mensaje
    if (EVP_PKEY_encrypt(ctx, mensajeCifrado, &longitudCifrada, (unsigned char *)textoPlano, strlen(textoPlano)) <= 0) {
        printf("Error durante el cifrado.\n");
        EVP_PKEY_free(clavePublica);
        EVP_PKEY_CTX_free(ctx);
        free(mensajeCifrado);
        free(textoPlano);
        return 1;
    }

    // Guardar el mensaje cifrado en un archivo
    archivoCifrado = fopen("criptograma.enc.rsa", "wb");
    if (!archivoCifrado) {
        printf("Error al crear el archivo criptograma.enc.rsa.\n");
        EVP_PKEY_free(clavePublica);
        EVP_PKEY_CTX_free(ctx);
        free(mensajeCifrado);
        free(textoPlano);
        return 1;
    }

    fwrite(mensajeCifrado, 1, longitudCifrada, archivoCifrado);
    fclose(archivoCifrado);

    // Limpiar
    EVP_PKEY_free(clavePublica);
    EVP_PKEY_CTX_free(ctx);
    free(mensajeCifrado);

    // ---- DESCIFRADO ----

    // Abrir el archivo de la clave privada
    archivoClavePrivada = fopen("llave_privada.pem", "r");
    if (!archivoClavePrivada) {
        printf("Error al abrir el archivo llave_privada.pem.\n");
        free(textoPlano);
        return 1;
    }

    // Cargar la clave privada
    clavePrivada = PEM_read_PrivateKey(archivoClavePrivada, NULL, NULL, NULL);
    if (!clavePrivada) {
        printf("Error al leer la clave privada.\n");
        fclose(archivoClavePrivada);
        free(textoPlano);
        return 1;
    }
    fclose(archivoClavePrivada);

    // Leer el mensaje cifrado desde el archivo
    archivoCifrado = fopen("criptograma.enc.rsa", "rb");
    if (!archivoCifrado) {
        printf("Error al abrir el archivo criptograma.enc.rsa.\n");
        EVP_PKEY_free(clavePrivada);
        free(textoPlano);
        return 1;
    }

    fseek(archivoCifrado, 0, SEEK_END);
    longitudCifrada = ftell(archivoCifrado);
    rewind(archivoCifrado);

    mensajeCifrado = (unsigned char *)malloc(longitudCifrada);
    fread(mensajeCifrado, 1, longitudCifrada, archivoCifrado);
    fclose(archivoCifrado);

    // Crear el contexto para el descifrado
    ctx = EVP_PKEY_CTX_new(clavePrivada, NULL);
    if (!ctx) {
        printf("Error al crear el contexto de descifrado.\n");
        EVP_PKEY_free(clavePrivada);
        free(mensajeCifrado);
        free(textoPlano);
        return 1;
    }

    // Inicializar el contexto para descifrado
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        printf("Error en la inicialización de descifrado.\n");
        EVP_PKEY_free(clavePrivada);
        EVP_PKEY_CTX_free(ctx);
        free(mensajeCifrado);
        free(textoPlano);
        return 1;
    }

    // Determinar el tamaño del mensaje descifrado
    if (EVP_PKEY_decrypt(ctx, NULL, &longitudDescifrada, mensajeCifrado, longitudCifrada) <= 0) {
        printf("Error al determinar el tamaño del mensaje descifrado.\n");
        EVP_PKEY_free(clavePrivada);
        EVP_PKEY_CTX_free(ctx);
        free(mensajeCifrado);
        free(textoPlano);
        return 1;
    }

    // Reservar memoria para el mensaje descifrado
    mensajeDescifrado = (unsigned char *)malloc(longitudDescifrada);
    if (!mensajeDescifrado) {
        printf("Error al asignar memoria para el mensaje descifrado.\n");
        EVP_PKEY_free(clavePrivada);
        EVP_PKEY_CTX_free(ctx);
        free(mensajeCifrado);
        free(textoPlano);
        return 1;
    }

    // Descifrar el mensaje
    if (EVP_PKEY_decrypt(ctx, mensajeDescifrado, &longitudDescifrada, mensajeCifrado, longitudCifrada) <= 0) {
        printf("Error durante el descifrado.\n");
        EVP_PKEY_free(clavePrivada);
        EVP_PKEY_CTX_free(ctx);
        free(mensajeDescifrado);
        free(mensajeCifrado);
        free(textoPlano);
        return 1;
    }

    // Guardar el mensaje descifrado en un archivo
    archivoDescifrado = fopen("textodescifrado.txt", "wb");
    if (!archivoDescifrado) {
        printf("Error al crear el archivo textodescifrado.txt.\n");
        EVP_PKEY_free(clavePrivada);
        EVP_PKEY_CTX_free(ctx);
        free(mensajeDescifrado);
        free(mensajeCifrado);
        free(textoPlano);
        return 1;
    }

    fwrite(mensajeDescifrado, 1, longitudDescifrada, archivoDescifrado);
    fclose(archivoDescifrado);

    // Limpiar
    EVP_PKEY_free(clavePrivada);
    EVP_PKEY_CTX_free(ctx);
    free(mensajeDescifrado);
    free(mensajeCifrado);
    free(textoPlano);

    printf("Descifrado exitoso. El resultado se ha guardado en textodescifrado.txt.\n");

    return 0;
}

