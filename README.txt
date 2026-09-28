Como ejecutar el código:

En caso de no tener instalado libpcap, se debe de ejecutar el siguiente comando desde la terminal: 

sudo apt update
sudo apt install libpcap-dev

Y antes de usar gcc, lo mejor es revisar nuestro nombre de la interfaz con "ip link" o "ip addr" ya que vamos a utilizar el ip que tengamos para poder ser el emisor o el receptor.

Una vez instalado y verificado el nombre de la interfaz, se ejecuta:

gcc receptor.c -o receptor -lpcap
gcc emisor.c -o emisor -lpcap 

Ahora, si queremos ser el receptor entonces ejecutamos lo siguiente:

sudo ./receptor [NombreDeLaInterfaz]

Si todo va bien, debe de aparecer en la terminal "Escuchando de forma cruda en [NombreDeLaInterfaz] esperando tramas experimentales..."

Ahora, si queremos ser el emisor entonces ejecutamos lo siguiente:

sudo ./emisor [NombreDeLaInterfaz] o sudo ./emisor [NombreDeLaInterfaz] "Mensaje que va a aparecer para el receptor"

En caso de no enviar un mensaje, se enviara uno por default el cual va a decir "Hola Redes 2027-1"

INVESTIGACION

- pcap_open_live

pcap_open_live abre el dispositivo de red especificado para la captura de paquetes. El término "activo" indica que se está abriendo un dispositivo de red, en contraposición a un archivo que contiene datos de captura de paquetes. Esta subrutina debe llamarse antes de que se pueda producir la captura de paquetes. Todas las demás rutinas relacionadas con la captura de paquetes requieren el descriptor de captura de paquetes que se crea e inicializa con esta rutina.

Cuando se complete correctamente, la subrutina devolverá un puntero al descriptor de captura de paquetes que se ha creado. Si la subrutina no es satisfactoria, se devuelve Null y el texto que indica el error específico

- pcap_sendpacket

pcap_sendpacket() toma como argumentos un buffer que contiene los datos a enviar, la longitud del buffer y el adaptador que lo enviará.

- pcap_loop

pcap_loop lee y procesa paquetes. Esta subrutina se puede llamar para leer y procesar paquetes almacenados en un archivo de datos de captura de paquetes guardado anteriormente. La subrutina también puede leer y procesar paquetes que se están capturando en directo.

Al finalizar, la subrutina pcap_loop devuelve 0. También se devuelve 0 si se ha alcanzado EOF en un savefile. Si la subrutina pcap_loop no tiene éxito, se devuelve -1.

- pcap_close

pcap_close cierra los archivos asociados con el descriptor de captura de paquetes y desasigna recursos. Si la subrutina pcap_open_offline Anteriormente se llamaba, la subrutina pcap_close cierra el savefile.

La subrutina pcap_close cierra el dispositivo de captura de paquetes si la subrutina pcap_open_live fue llamada previamente.

- pcap_geterr

pcap_geterr devuelve el texto de error correspondiente al último error de biblioteca pcap. Esta subrutina sirve para obtener texto de error de las subrutinas que no devuelven una serie de error. Puesto que el puntero devuelto apunta a un espacio de memoria que será reutilizado por las subrutinas de la biblioteca pcap.

Finalmente devuelve un puntero al mensaje de error más reciente de una subrutina de biblioteca pcap. Si no había mensajes de error anteriores, se devuelve una serie con 0 como primer byte.


Fuentes:

https://www.ibm.com/docs/es/aix/7.2.0?topic=p-pcap-open-live-subroutine
https://linux.die.net/man/3/pcap_sendpacket
https://www.ibm.com/docs/es/aix/7.3.0?topic=p-pcap-loop-subroutine
https://www.ibm.com/docs/en/aix/7.2.0?topic=p-pcap-close-subroutine
https://www.ibm.com/docs/es/aix/7.3.0?topic=p-pcap-geterr-subroutine
https://man7.org/linux/man-pages/man3/pcap_sendpacket.3pcap.html
