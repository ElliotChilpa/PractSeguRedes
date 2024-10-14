#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE *archivo, *archivoCifrado, *archivoDescifrado;
    char *textoPlano;
    long tamanoArchivo;
    RSA *rsa = NULL;
    unsigned char *mensajeCifrado;
    unsigned char *mensajeDescifrado;
    int resultado, longitudCifrada;
    FILE *archivoClavePublica, *archivoClavePrivada;
    size_t longitudDescifrada;

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
    textoPlano[tamanoArchivo] = '\0';  // Asegurarse de que el texto esté bien terminado
    fclose(archivo);

    // Abrir el archivo de la clave pública (en formato PEM)
    archivoClavePublica = fopen("llave_publica.pem", "r");
    if (archivoClavePublica == NULL) {
        printf("Error al abrir el archivo llave_publica.pem.\n");
        free(textoPlano);
        return 1;
    }

    // Cargar la clave pública desde el archivo PEM
    rsa = PEM_read_RSA_PUBKEY(archivoClavePublica, NULL, NULL, NULL);
    if (rsa == NULL) {
        printf("Error al leer la clave pública.\n");
        free(textoPlano);
        fclose(archivoClavePublica);
        return 1;
    }
    fclose(archivoClavePublica);

    // Reservar memoria para el mensaje cifrado
    longitudCifrada = RSA_size(rsa);
    mensajeCifrado = (unsigned char *)malloc(longitudCifrada);
    if (mensajeCifrado == NULL) {
        printf("Error al asignar memoria para el mensaje cifrado.\n");
        RSA_free(rsa);
        free(textoPlano);
        return 1;
    }

    // Cifrar el contenido de textoPlano con la clave pública
    resultado = RSA_public_encrypt(strlen(textoPlano), (unsigned char *)textoPlano, mensajeCifrado, rsa, RSA_PKCS1_OAEP_PADDING);
    if (resultado == -1) {
        printf("Error durante el cifrado.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        free(textoPlano);
        free(mensajeCifrado);
        return 1;
    }

    // Abrir el archivo criptograma.enc.rsa en modo escritura
    archivoCifrado = fopen("criptograma.enc.rsa", "wb");
    if (archivoCifrado == NULL) {
        printf("Error al crear el archivo criptograma.enc.rsa.\n");
        RSA_free(rsa);
        free(textoPlano);
        free(mensajeCifrado);
        return 1;
    }

    // Escribir el mensaje cifrado en el archivo criptograma.enc.rsa
    fwrite(mensajeCifrado, sizeof(unsigned char), resultado, archivoCifrado);

    // Cerrar el archivo criptograma.enc.rsa
    fclose(archivoCifrado);

    // -------- DESCIFRADO --------

    // Abrir el archivo criptograma.enc.rsa en modo lectura
    archivoCifrado = fopen("criptograma.enc.rsa", "rb");
    if (archivoCifrado == NULL) {
        printf("Error al abrir el archivo criptograma.enc.rsa.\n");
        RSA_free(rsa);
        free(textoPlano);
        free(mensajeCifrado);
        return 1;
    }

    // Leer el contenido cifrado
    fread(mensajeCifrado, sizeof(unsigned char), longitudCifrada, archivoCifrado);
    fclose(archivoCifrado);

    // Cargar la clave privada desde el archivo PEM
    archivoClavePrivada = fopen("llave_privada.pem", "r");
    if (archivoClavePrivada == NULL) {
        printf("Error al abrir el archivo llave_privada.pem.\n");
        RSA_free(rsa);
        free(textoPlano);
        free(mensajeCifrado);
        return 1;
    }

    rsa = PEM_read_RSAPrivateKey(archivoClavePrivada, NULL, NULL, NULL);
    if (rsa == NULL) {
        printf("Error al leer la clave privada.\n");
        ERR_print_errors_fp(stderr);
        free(textoPlano);
        free(mensajeCifrado);
        fclose(archivoClavePrivada);
        return 1;
    }
    fclose(archivoClavePrivada);

    // Reservar memoria para el mensaje descifrado
    mensajeDescifrado = (unsigned char *)malloc(longitudCifrada);
    if (mensajeDescifrado == NULL) {
        printf("Error al asignar memoria para el mensaje descifrado.\n");
        RSA_free(rsa);
        free(textoPlano);
        free(mensajeCifrado);
        return 1;
    }

    // Descifrar el contenido de mensajeCifrado con la clave privada
    resultado = RSA_private_decrypt(longitudCifrada, mensajeCifrado, mensajeDescifrado, rsa, RSA_PKCS1_OAEP_PADDING);
    if (resultado == -1) {
        printf("Error durante el descifrado.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        free(textoPlano);
        free(mensajeCifrado);
        free(mensajeDescifrado);
        return 1;
    }

    // Abrir el archivo textodescifrado.txt en modo escritura
    archivoDescifrado = fopen("textodescifrado.txt", "w");
    if (archivoDescifrado == NULL) {
        printf("Error al crear el archivo textodescifrado.txt.\n");
        RSA_free(rsa);
        free(textoPlano);
        free(mensajeCifrado);
        free(mensajeDescifrado);
        return 1;
    }

    // Escribir el mensaje descifrado en el archivo textodescifrado.txt
    fwrite(mensajeDescifrado, sizeof(unsigned char), resultado, archivoDescifrado);

    // Cerrar el archivo textodescifrado.txt
    fclose(archivoDescifrado);

    // Liberar memoria y recursos
    RSA_free(rsa);
    free(textoPlano);
    free(mensajeCifrado);
    free(mensajeDescifrado);

    printf("Descifrado exitoso. El resultado se ha guardado en textodescifrado.txt.\n");

    return 0;
}
 
