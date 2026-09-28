//El codigo lo ejecute desde mi maquina virtual de linux mint, asi que no funciona bien para otros SO

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>   
#include <pcap.h>

#define ETHERTYPE 0x88B5 // Tome el ethertype en base a la captura de la practica
#define TAM_CABECERA           14 // Este representa el tamano de la cabecera Ethernet donde tenemos 6 bytes MAC destino 6 bytes MAC origen y 2 bytes EtherType
#define TAM_MIN_TRAMA          60 // Esto representa el tamano de la trama Ethernet (sin FCS)
#define TAM_MAX_PAYLOAD        1500 // Esto representa el tamano maximo permitido para el campo de datos 
#define MENSAJE_DEFECTO        "Hola Redes 2027-1" // Esto solo es un mensaje default por si no se escribe ninguno al momento de ejecutar el .c

/// Lee la MAC de la interfaz desde sysfs (Linux). Devuelve 0 si tuvo exito 
static int obtener_mac(const char *interfaz, unsigned char mac[6]){

    char ruta[128];
    unsigned int m[6];
    FILE *f;

    /* 
    * Desde Linux, la direccion MAC de una interfaz 
    * puede consultarse mediante 
    * /sys/class/net/<interfaz>/address 
    */
    snprintf(ruta, sizeof(ruta), "/sys/class/net/%s/address", interfaz);
    // Abre el archivo que contiene la direccion MAC de la interfaz.
    f = fopen(ruta, "r");
    if (f == NULL)
        return -1;

    // Lee los seis valores hexadecimales que forman la direccion MAC
    if (fscanf(f, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        fclose(f);
        return -1;
    }
    fclose(f);

    // Convierte cada valor obtenido a un byte y lo almacena en el arreglo mac
    for (int i = 0; i < 6; i++)
        mac[i] = (unsigned char)m[i];
    return 0;

}


int main(int argc, char *argv[]){

    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char trama[TAM_CABECERA + TAM_MAX_PAYLOAD]; // Arreglo donde se construira la trama Ethernet. Los primeros 14 bytes corresponden a la cabecera Ethernet y el resto al campo de datos
    unsigned char mac_origen[6]; // Direccion MAC de la interfaz desde donde se enviara la trama
    unsigned char mac_destino[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Esta es la direccion de broadcast Ethernet
    unsigned short tipo; // Variable donde se almacenara el EtherType de la trama
    const char *interfaz; 
    const char *mensaje; 
    int tam_trama;
    pcap_t *handle; // Este es un manejador utilizado por libpcap para acceder a la interfaz de red

    // Verifica que se haya proporcionado al menos el nombre de la interfaz
    if (argc < 2) {
        fprintf(stderr, "Uso: sudo %s <interfaz> [mensaje]\n", argv[0]);
        return 1;
    }
    interfaz = argv[1];
    mensaje  = (argc >= 3) ? argv[2] : MENSAJE_DEFECTO;

    // Obtiene la direccion MAC de la interfaz seleccionada
    if (obtener_mac(interfaz, mac_origen) != 0) {
        fprintf(stderr, "No se pudo obtener la MAC de la interfaz '%s'\n", interfaz);
        return 1;
    }

    memset(trama, 0, sizeof(trama)); // Inicializa toda la trama con ceros
    memcpy(trama,     mac_destino, 6); // Coloca la MAC de destino en los primeros 6 bytes de la trama Ethernet
    memcpy(trama + 6, mac_origen,  6); // Coloca la MAC de origen en los siguientes 6 bytes
    tipo = htons(ETHERTYPE); 
    memcpy(trama + 12, &tipo, 2); // Coloca el EtherType en los bytes 12 y 13
    strncpy((char *)(trama + TAM_CABECERA), mensaje, TAM_MAX_PAYLOAD - 1); //

    tam_trama = TAM_CABECERA + (int)strlen((char *)(trama + TAM_CABECERA)) + 1;  // Calcula el tamano de la trama
    // Si la trama construida es menor, se aumenta su tamano hasta 60 bytes. Y como la trama fue inicializada previamente con memset(), los bytes adicionales contienen cero y funcionan como relleno
    if (tam_trama < TAM_MIN_TRAMA)
        tam_trama = TAM_MIN_TRAMA;   

    
    handle = pcap_open_live(interfaz, BUFSIZ, 0, 1000, errbuf);
    // Verifica si libpcap pudo abrir correctamente la interfaz.
    if (handle == NULL) {
        fprintf(stderr, "Error en pcap_open_live: %s\n", errbuf);
        return 1;
    }

    printf("Mensaje: %s\n", mensaje);

    // Si ocurre un error durante el envio, se obtiene el mensaje de error por libpcap
    if (pcap_sendpacket(handle, trama, tam_trama) != 0) {
        fprintf(stderr, "Error en pcap_sendpacket: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    printf("Procesamiento completo con exito\n");
    return 0;
    
}
