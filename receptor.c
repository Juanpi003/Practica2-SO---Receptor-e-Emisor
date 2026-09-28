//El codigo lo ejecute desde mi maquina virtual de linux mint, asi que no funciona bien para otros SO

#include <stdio.h>
#include <stdlib.h>
#include <string.h>     
#include <arpa/inet.h>   
#include <pcap.h>

#define ETHERTYPE 0x88B5 // Tome el ethertype en base a la captura de la practica
#define TAM_CABECERA           14 // Este representa el tamano de la cabecera Ethernet donde tenemos 6 bytes MAC destino 6 bytes MAC origen y 2 bytes EtherType
#define TAM_MAX_MENSAJE        1500 // Esto representa el tamano maximo permitido para el campo de datos 

// Imprime la direccion MAC en formato hexadecimal
static void imprimir_mac(const unsigned char *mac){

    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

}

/* 
* Es una funcion encargada de procesar cada trama capturada 
* Esta funcion es llamada automaticamente por pcap_loop() 
* cada vez que libpcap recibe una trama que debe procesarse. 
*/
static void procesar_trama(unsigned char *usuario,
                           const struct pcap_pkthdr *cabecera,
                           const unsigned char *paquete){

    const unsigned char *mac_destino = paquete; // Los primeros 6 bytes de una trama Ethernet que corresponden a la direccion MAC de destino
    const unsigned char *mac_origen  = paquete + 6; // Los siguientes 6 bytes que corresponden a la direccion MAC de origen
    unsigned short tipo; // Variable donde se almacenara el EtherType
    char mensaje[TAM_MAX_MENSAJE + 1]; // Es el buffer donde se almacenara el mensaje extraido del campo de datos de la trama. Se reserva un byte adicional para colocar '\0' y convertir el contenido en una cadena valida de C
    unsigned int tam_payload; // Almacena el tamano del campo de datos de la trama
    static const unsigned char broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Esta es la direccion de broadcast Ethernet

    (void)usuario;

    // Verifica que la trama tenga al menos los 14 bytes 
    if (cabecera->caplen < TAM_CABECERA)
        return;

    // Si el EtherType no corresponde al valor definido de la cabecera, la trama se ignora
    memcpy(&tipo, paquete + 12, 2);
    if (ntohs(tipo) != ETHERTYPE)
        return;

    // Extrae el mensaje asegurando que termine en '\0'
    tam_payload = cabecera->caplen - TAM_CABECERA;
    if (tam_payload > TAM_MAX_MENSAJE)
        tam_payload = TAM_MAX_MENSAJE;
    memcpy(mensaje, paquete + TAM_CABECERA, tam_payload);
    mensaje[tam_payload] = '\0';

    
    printf("\n Trama capa 2 recibia \n");
    fflush(stdout); // Fuerza la salida de la informacion almacenada temporalmente en el buffer de salida

    printf("MAC Origen:  ");
    imprimir_mac(mac_origen);
    printf("\n");

    printf("MAC Destino: ");
    imprimir_mac(mac_destino);
    if (memcmp(mac_destino, broadcast, 6) == 0)
        printf(" (Broadcast)");
    printf("\n");

    printf("EtherType:   0x%04X (Experimental)\n", ntohs(tipo));
    printf("Mensaje:     %s\n", mensaje);
    printf(" Procesamiento completado con exito \n");
    fflush(stdout);
}


int main(int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *interfaz;
    pcap_t *handle;

    // Verifica que se haya proporcionado el nombre de una interfaz de red
    if (argc < 2) {
        fprintf(stderr, "Uso: sudo %s <interfaz>\n", argv[0]);
        return 1;
    }
    interfaz = argv[1];

    handle = pcap_open_live(interfaz, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error en pcap_open_live: %s\n", errbuf);
        return 1;
    }

    // Se notifica que el receptor comenzo a escuchar la interfaz
    printf("Escuchando de forma cruda en %s esperando tramas experimentales...\n",
           interfaz);
    fflush(stdout);

    // Comienza la captura continua de tramas, -1 indica que pcap_loop() continuara capturando indefinidamente hasta que ocurra un error o se detenga la captura
    if (pcap_loop(handle, -1, procesar_trama, NULL) == -1)
        fprintf(stderr, "Error en pcap_loop: %s\n", pcap_geterr(handle));

    pcap_close(handle);
    return 0;

}
