/***************************************************************************
 practica4.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones
 
 Compila: make
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM v2
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "interface.h"
#include "practica4.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper; //y salida a pcap
uint64_t cont = 0; //Contador numero de mensajes enviados
char interface[10]; //Interface donde transmitir por ejemplo "eth0"
uint16_t ID = 1; //Identificador IP

void handleSignal(int nsignal) {
    printf("Control C pulsado (%"PRIu64")\n", cont);
    pcap_close(descr);
    exit(OK);
}

int main(int argc, char **argv) {

    char errbuf[PCAP_ERRBUF_SIZE];
    char fichero_pcap_destino[CADENAS];
    uint8_t IP_destino_red[IP_ALEN];
    uint16_t MTU;
    uint16_t datalink;
    uint16_t puerto_destino;
    char data[IP_DATAGRAM_MAX];
    uint16_t pila_protocolos[CADENAS];


    int long_index = 0;
    char opt;
    char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0;

    FILE* f = NULL;
    long tamf = 0;
    static struct option options[] = {
        {"if", required_argument, 0, '1'},
        {"ip", required_argument, 0, '2'},
        {"pd", required_argument, 0, '3'},
        {"f", required_argument, 0, '4'},
        {"h", no_argument, 0, '5'},
        {0, 0, 0, 0}
    };

    //Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
    while ((opt = getopt_long_only(argc, argv, "1:2:3:4:5", options, &long_index)) != -1) {
        switch (opt) {

            case '1':

                flag_iface = 1;
                //Por comodidad definimos interface como una variable global
                sprintf(interface, "%s", optarg);
                break;

            case '2':

                flag_ip = 1;
                //Leemos la IP a donde transmitir y la almacenamos en orden de red
                if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
                        &(IP_destino_red[0]), &(IP_destino_red[1]), &(IP_destino_red[2]), &(IP_destino_red[3])) != IP_ALEN) {
                    printf("Error: Fallo en la lectura IP destino %s\n", optarg);
                    exit(ERROR);
                }

                break;

            case '3':

                flag_port = 1;
                //Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
                puerto_destino = atoi(optarg);
                break;

            case '4':

                if (strcmp(optarg, "stdin") == 0) {
                    if (fgets(data, sizeof data, stdin) == NULL) {
                        printf("Error leyendo desde stdin: %s %s %d.\n", errbuf, __FILE__, __LINE__);
                        return ERROR;
                    }
                    sprintf(fichero_pcap_destino, "%s%s", "stdin", ".pcap");
                } else {
                    sprintf(fichero_pcap_destino, "%s%s", optarg, ".pcap");
                    //TODO Leer fichero en data [...]
                    f = fopen(optarg, "r");
                    if (f == NULL) {
                        printf("Error leyendo desde %s: %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
                        return ERROR;
                    }
                    fseek(f, 0, SEEK_END);
                    tamf = ftell(f);
                    fseek(f, 0, SEEK_SET);
                    fread(data, 1, tamf, f);
                    fclose(f);

                }
                flag_file = 1;

                break;

            case '5': printf("Ayuda. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n", argv[0], argc);
                exit(ERROR);
                break;

            case '?': printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n", argv[0], argc);
                exit(ERROR);
                break;

            default: printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n", argv[0], argc);
                exit(ERROR);
                break;
        }
    }

    if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)) {
        printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n", argv[0], argc);
        exit(ERROR);
    } else {
        printf("Interface:\n\t%s\n", interface);
        printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n", IP_destino_red[0], IP_destino_red[1], IP_destino_red[2], IP_destino_red[3]);
        printf("Puerto destino:\n\t%"PRIu16"\n", puerto_destino);
    }

    if (flag_file == 0) {
        sprintf(data, "%s", "Payload "); //Deben ser pares!
        sprintf(fichero_pcap_destino, "%s%s", "debugging", ".pcap");
    }

    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        return ERROR;
    }
    //Inicializamos las tablas de protocolos
    if (inicializarPilaEnviar() == ERROR) {
        printf("Error leyendo desde stdin: %s %s %d.\n", errbuf, __FILE__, __LINE__);
        return ERROR;
    }
    //Leemos el tamano maximo de transmision del nivel de enlace
    if (obtenerMTUInterface(interface, &MTU) == ERROR)
        return ERROR;
    //Descriptor de la interface de red donde inyectar trafico
    if ((descr = pcap_open_live(interface, MTU + ETH_HLEN, 0, 0, errbuf)) == NULL) {
        printf("Error: pcap_open_live(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        return ERROR;
    }

    datalink = (uint16_t) pcap_datalink(descr); //DLT_EN10MB==Ethernet

    //Descriptor del fichero de salida pcap para debugging
    descr2 = pcap_open_dead(datalink, MTU + ETH_HLEN);
    pdumper = pcap_dump_open(descr2, fichero_pcap_destino);

    //Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
    //Primero un paquete UDP
    //Definimos la pila de protocolos que queremos seguir
    pila_protocolos[0] = UDP_PROTO;
    pila_protocolos[1] = IP_PROTO;
    pila_protocolos[2] = ETH_PROTO;
    //Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
    Parametros parametros_udp;
    memcpy(parametros_udp.IP_destino, IP_destino_red, IP_ALEN);
    parametros_udp.puerto_destino = puerto_destino;
    //Enviamos
    if (enviar((uint8_t*) data, pila_protocolos, strlen(data), &parametros_udp) == ERROR) {
        printf("Error: enviar(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        return ERROR;
    } else cont++;

    printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont, fichero_pcap_destino);

    //Luego, un paquete ICMP en concreto un ping
    pila_protocolos[0] = ICMP_PROTO;
    pila_protocolos[1] = IP_PROTO;
    pila_protocolos[2] = ETH_PROTO;
    Parametros parametros_icmp;
    parametros_icmp.tipo = PING_TIPO;
    parametros_icmp.codigo = PING_CODE;
    memcpy(parametros_icmp.IP_destino, IP_destino_red, IP_ALEN);
    if (enviar((uint8_t*) "Probando a hacer un ping", pila_protocolos, strlen("Probando a hacer un ping"), &parametros_icmp) == ERROR) {
        printf("Error: enviar(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
        return ERROR;
    } else cont++;
    printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont, fichero_pcap_destino);

    //Cerramos descriptores
    pcap_close(descr);
    pcap_dump_close(pdumper);
    pcap_close(descr2);
    return OK;
}

/****************************************************************************************
 * Nombre: enviar 									*
 * Descripcion: Esta funcion envia un mensaje						*
 * Argumentos: 										*
 *  -mensaje: mensaje a enviar								*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen mensaje						*
 *  -parametros: parametros necesario para el envio (struct parametros)			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {
    uint16_t protocolo = pila_protocolos[0];
    printf("Enviar(%"PRIu16") %s %d.\n", protocolo, __FILE__, __LINE__);
    if (protocolos_registrados[protocolo] == NULL) {
        printf("Protocolo %"PRIu16" desconocido\n", protocolo);
        return ERROR;
    } else {
        return protocolos_registrados[protocolo](mensaje, pila_protocolos, longitud, parametros);
    }
    return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/

/****************************************************************************************
 * Nombre: moduloUDP 									*
 * Descripcion: Esta funcion implementa el modulo de envio UDP				*
 * Argumentos: 										*
 *  -mensaje: mensaje a enviar								*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen mensaje						*
 *  -parametros: parametros necesario para el envio este protocolo			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {
    uint8_t segmento[UDP_SEG_MAX] = {0};
    uint16_t puerto_origen = 0, suma_control = 0;
    uint16_t aux16;
    uint32_t pos = 0;
    uint16_t protocolo_inferior = pila_protocolos[1];

    printf("modulo UDP(%"PRIu16") %s %d.\n", protocolo_inferior, __FILE__, __LINE__);

    if (longitud > (pow(2, 16) - UDP_HLEN)) {
        printf("Error: mensaje demasiado grande para UDP (%f).\n", (pow(2, 16) - UDP_HLEN));
        return ERROR;
    }
    Parametros udpdatos = *((Parametros*) parametros);
    uint16_t puerto_destino = udpdatos.puerto_destino;

    if (obtenerPuertoOrigen(&puerto_origen) == ERROR) {
        printf("Error: obtenerPuertoOrigen\n");
        return -1;
    }
    //puerto origen
    aux16 = htons(puerto_origen);
    memcpy(segmento + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);

    //TODO Completar el segmento [...]

    //puerto destino
    aux16 = htons(puerto_destino);
    memcpy(segmento + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    //longitud segmento
    aux16 = htons(longitud + UDP_HLEN);
    memcpy(segmento + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    //checksum a 0
    aux16 = htons(suma_control);
    memcpy(segmento + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    //mensaje
    memcpy(segmento + pos, mensaje, longitud * sizeof (uint8_t));
    //Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
    return protocolos_registrados[protocolo_inferior](segmento, pila_protocolos, longitud + pos, parametros);
}

/****************************************************************************************
 * Nombre: moduloIP 									*
 * Descripcion: Esta funcion implementa el modulo de envio IP				*
 * Argumentos: 										*
 *  -segmento: segmento a enviar								*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen el segmento						*
 *  -parametros: parametros necesario para el envio este protocolo			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {
    uint8_t datagrama[IP_DATAGRAM_MAX] = {0};

    uint16_t aux16;
    uint8_t aux8;
    uint32_t pos = 0, pos_checksum = 0, pos_flag = 0, pos_lentot = 0;
    uint8_t IP_origen[IP_ALEN];

    uint16_t protocolo_superior = pila_protocolos[0];
    uint16_t protocolo_inferior = pila_protocolos[2];
    pila_protocolos++;
    uint8_t mascara[IP_ALEN], IP_rango_origen[IP_ALEN], IP_rango_destino[IP_ALEN];

    uint8_t checksum[2];
    int i, flag = 0;

    printf("modulo IP(%"PRIu16") %s %d.\n", protocolo_inferior, __FILE__, __LINE__);

    uint8_t* IP_aux = (uint8_t*) malloc(IP_ALEN * sizeof (uint8_t));
    Parametros ipdatos = *((Parametros*) parametros);
    uint8_t* IP_destino = ipdatos.IP_destino;
    //control de tamaño
    if (IP_DATAGRAM_MAX < (longitud + 20)) {//si el tamaño maximo es mayor que la long del segmento+tamaño de la cabecera
        printf("Error: datagrama demasiado grande\n");
        return -1;
    }
    //TODO
    //Llamar a ARPrequest(·) adecuadamente y usar ETH_destino de la estructura parametros
    if (obtenerMascaraInterface(interface, mascara) == ERROR) {
        printf("Error: obtenerMascaraInterface\n");
        return -1;
    }
    if (obtenerIPInterface(interface, IP_origen) == ERROR) {
        printf("Error: obtenerIPInterface\n");
        return -1;
    }
    if (aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR) {
        printf("Error: aplicarMascara\n");
        return -1;
    }
    if (aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR) {
        printf("Error: aplicarMascara\n");
        return -1;
    }
    for (i = 0; i < IP_ALEN; i++) {
        if (IP_rango_origen[i] != IP_rango_destino[i])
            flag = 1;
    }
    /*caso distinta subred*/
    if (flag == 1) {
        if (obtenerGateway(interface, IP_aux) == ERROR) {
            printf("Error: obtenerGateway\n");
            return -1;
        }
    } else { /*caso misma subred*/
        IP_aux = IP_destino;
    }

    if (ARPrequest(interface, IP_aux, ((Parametros*) parametros)->ETH_destino) == ERROR) {
        printf("Error: ARPrequest\n");
        return -1;
    }

    //[...] 
    //TODO A implementar el datagrama y fragmentación (en caso contrario, control de tamano)
    //version + IHL
    aux8 = (IP_ALEN << 4) + 5;
    memcpy(datagrama + pos, &aux8, sizeof (uint8_t));
    pos += sizeof (uint8_t);
    //tipo servicio
    aux8 = 0;
    memcpy(datagrama + pos, &aux8, sizeof (uint8_t));
    pos += sizeof (uint8_t);
    //Longitud total
    pos_lentot = pos;
    aux16 = htons(longitud + 20);
    memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    //identificador
    aux16 = htons(ID);
    memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    //flags+posicion
    pos_flag = pos;
    aux16 = htons(0x4000);
    memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    //tiempo de vida
    aux8 = 64;
    memcpy(datagrama + pos, &aux8, sizeof (uint8_t));
    pos += sizeof (uint8_t);
    //protocolo
    aux8 = protocolo_superior;
    memcpy(datagrama + pos, &aux8, sizeof (uint8_t));
    pos += sizeof (uint8_t);
    //checksum
    pos_checksum = pos;
    aux16 = 0;
    memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    //IPorigen
    for (i = 0; i < IP_ALEN; i++) {
        aux8 = IP_origen[i];
        memcpy(datagrama + pos, &aux8, sizeof (uint8_t));
        pos += sizeof (uint8_t);
    }
    //IPdestino
    for (i = 0; i < IP_ALEN; i++) {
        aux8 = IP_destino[i];
        memcpy(datagrama + pos, &aux8, sizeof (uint8_t));
        pos += sizeof (uint8_t);
    }

    //fragmentacion
    if (obtenerMTUInterface(interface, &aux16) == ERROR) {
        printf("Error: obtenerMTUInterface\n");
        return -1;
    }

    uint64_t tamDatagrama = longitud + pos; //tamDatagrama guarda el tamaño de mi datagrama en bytes
    uint64_t tamSegmento = longitud; //tamanio en bytes del segmento
    uint16_t MTU = aux16; //guarda el MTU (tamanio maximo de datagrama permitido)
    //MTUeth < tamDatagrama 
    if (MTU < tamDatagrama) { //si hay que fragmentar:
        int tamCU = MTU - 20; //tamCU = 1480B = tamaño de carga util
        tamCU = tamCU - (tamCU % 8); //nos aseguramos de que tamCU sea multiplo de 8
        printf("tam CU: %d\n", tamCU);
        //i se ejecuta las veces que haga falta hasta completar el segmento
        for (i = 0; i < tamSegmento; i += tamCU) {
            //inicializo checksum a 0 en cada iteracion
            aux16 = 0;
            memcpy(datagrama + pos_checksum, &aux16, sizeof (uint16_t)); //escribo 0s en el checksum
            //esto se ejecuta si no es el ultimo fragmento
            if (tamSegmento - i > tamCU) {
                //sobrescribo Longitud total
                aux16 = htons(tamCU + 20);
                memcpy(datagrama + pos_lentot, &aux16, sizeof (uint16_t));
                //aniado segmento
                memcpy(datagrama + pos, segmento + i, tamCU);
                //sobrescribo flag + posicion
                // 001  i/8
                aux16 = htons((1 << 13) + i / 8);
                memcpy(datagrama + pos_flag, &aux16, sizeof (uint16_t));
                //sobrescribo checksum
                if (calcularChecksum(20, datagrama, checksum) == ERROR) {
                    printf("Error: calcularChecksum\n");
                    return -1;
                }
                memcpy(datagrama + pos_checksum, checksum, sizeof (uint16_t));
                protocolos_registrados[protocolo_inferior](datagrama, pila_protocolos, tamCU + pos, parametros);

            } else { //ultimo fragmento
                //sobrescribo Longitud total
                aux16 = htons(tamSegmento - i + 20);
                memcpy(datagrama + pos_lentot, &aux16, sizeof (uint16_t));
                //aniado segmento
                memcpy(datagrama + pos, segmento + i, (tamSegmento - i));
                //sobrescribo flag + posicion
                //000 i/8
                aux16 = htons(i / 8);
                memcpy(datagrama + pos_flag, &aux16, sizeof (uint16_t));

                //sobrescribo checksum
                if (calcularChecksum(20, datagrama, checksum) == ERROR) {
                    printf("Error: calcularChecksum\n");
                    return -1;
                }
                memcpy(datagrama + pos_checksum, checksum, sizeof (uint16_t));
                protocolos_registrados[protocolo_inferior](datagrama, pila_protocolos, tamSegmento - i + pos, parametros);
            }

        }

    } else { // si no hay que fragmentar:
        //sobrescribo checksum
        if (calcularChecksum(20, datagrama, checksum) == ERROR) {
            printf("Error: calcularChecksum\n");
            return -1;
        }
        memcpy(datagrama + pos_checksum, checksum, sizeof (uint16_t));
        memcpy(datagrama + pos, segmento, longitud * sizeof (uint8_t));
        protocolos_registrados[protocolo_inferior](datagrama, pila_protocolos, longitud + pos, parametros);
    }
    return OK;
}

/****************************************************************************************
 * Nombre: moduloETH 									*
 * Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
 * Argumentos: 										*
 *  -datagrama: datagrama a enviar							*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen el datagrama						*
 *  -parametros: Parametros necesario para el envio este protocolo			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {
    //TODO
    //[....]
    //[...] Variables del modulo
    uint8_t trama[ETH_FRAME_MAX] = {0};
    struct pcap_pkthdr *cabecera = NULL;
    int pos = 0, i = 0;
    uint8_t ETH_origen[ETH_ALEN];

    uint8_t aux8;
    uint16_t aux16;

    Parametros ethdatos = *((Parametros*) parametros);
    uint8_t* ETH_destino = ethdatos.ETH_destino;

    printf("modulo ETH(fisica) %s %d.\n", __FILE__, __LINE__);


    //TODO
    //[...] Control de tamano
    if (ETH_FRAME_MAX < (longitud + ETH_HLEN)) {
        printf("Error: Tamaño de trama: %" PRIu64 " enorme!\n", (longitud + ETH_HLEN));
        return -1;
    }
    //TODO
    //[...] Cabecera del modulo
    //ETH destino
    for (i = 0; i < ETH_ALEN; i++) {
        aux8 = ETH_destino[i];
        memcpy(trama + pos, &aux8, sizeof (uint8_t));
        pos += sizeof (uint8_t);
    }
    //ETH origen
    if (obtenerMACdeInterface(interface, ETH_origen) == ERROR) {
        printf("Error: obtenerMACInterface\n");
        return -1;
    }
    for (i = 0; i < ETH_ALEN; i++) {
        aux8 = ETH_origen[i];
        memcpy(trama + pos, &aux8, sizeof (uint8_t));
        pos += sizeof (uint8_t);
    }

    //Tipo Ethernet
    aux16 = htons(0x0800);
    memcpy(trama + pos, &aux16, ETH_TLEN);
    pos += sizeof (uint16_t);
    //aniado datagrama
    memcpy(trama + pos, datagrama, longitud * sizeof (uint8_t));
    //TODO
    //Almacenamos la salida por cuestiones de debugging [...]
    if (pdumper) {
        cabecera = (struct pcap_pkthdr*) malloc(sizeof (struct pcap_pkthdr));
        cabecera->len = longitud + pos;
        gettimeofday(&(cabecera->ts), NULL);
        cabecera->caplen = longitud + pos;
        pcap_dump((uint8_t *) pdumper, cabecera, trama);
    }
    //Enviar a capa fisica [...]
    if (pcap_inject(descr, trama, longitud + pos) == -1) {
        printf("Error: pcap_inject\n");
        return -1;
    }
    //TODO

    ID++; //Aumentamos el ID para los siguientes paquetes que se envien

    return OK;
}

/****************************************************************************************
 * Nombre: moduloICMP 									*
 * Descripcion: Esta funcion implementa el modulo de envio ICMP				*
 * Argumentos: 										*
 *  -mensaje: mensaje a anadir a la cabecera ICMP					*
 *  -pila_protocolos: conjunto de protocolos a seguir					*
 *  -longitud: bytes que componen el mensaje						*
 *  -parametros: parametros necesario para el envio este protocolo			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje, uint16_t* pila_protocolos, uint64_t longitud, void *parametros) {
    //TODO
    //[....]
    uint8_t datagrama[ICMP_DATAGRAM_MAX] = {0};
    Parametros icmpdatos = *((Parametros*) parametros);
    uint8_t tipo = icmpdatos.tipo;
    uint8_t codigo = icmpdatos.codigo;

    uint16_t protocolo_inferior = pila_protocolos[1];
    uint8_t checksum[2];
    uint8_t aux8;
    uint16_t aux16;
    uint32_t pos = 0, pos_checksum = 0;

    //tipo
    aux8 = tipo;
    memcpy(datagrama + pos, &aux8, sizeof (uint8_t));
    pos += sizeof (uint8_t);
    //codigo
    aux8 = codigo;
    memcpy(datagrama + pos, &aux8, sizeof (uint8_t));
    pos += sizeof (uint8_t);

    //checksum
    pos_checksum = pos;
    aux16 = htons(0);
    memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    //identificador
    aux16 = htons(ID);
    memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);
    //numero secuencia
    aux16 = htons(0);
    memcpy(datagrama + pos, &aux16, sizeof (uint16_t));
    pos += sizeof (uint16_t);

    //mensaje
    memcpy(datagrama + pos, mensaje, longitud * sizeof (uint8_t));
    //en el caso en que la longitud de los datos sea impar
    //añado un byte con 0s y actualizo la longitud a algo valido
    if (longitud % 2 != 0) {
        aux8 = 0;
        memcpy(datagrama + pos + longitud, &aux8, sizeof (uint8_t));
        longitud++;
    }

    //sobrescribo checksum
    if (calcularChecksum(longitud + pos, datagrama, checksum) == ERROR) {
        printf("Error: calcularChecksum\n");
        return -1;
    }
    memcpy(datagrama + pos_checksum, checksum, sizeof (uint16_t));


    return protocolos_registrados[protocolo_inferior](datagrama, pila_protocolos, longitud + pos, parametros);
}


/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
 * Nombre: aplicarMascara 								*
 * Descripcion: Esta funcion aplica una mascara a una vector				*
 * Argumentos: 										*
 *  -IP: IP a la que aplicar la mascara en orden de red					*
 *  -mascara: mascara a aplicar en orden de red						*
 *  -longitud: bytes que componen la direccion (IPv4 == 4)				*
 *  -resultado: Resultados de aplicar mascara en IP en orden red				*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado) {
    int i;
    for (i = 0; i < longitud; i++) {
        resultado[i] = IP[i] & mascara[i];
    }
    return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
 * Nombre: mostrarPaquete 								*
 * Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector		*
 * Argumentos: 										*
 *  -paquete: bytes que conforman un paquete						*
 *  -longitud: Bytes que componen el mensaje						*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud) {
    uint32_t i;
    printf("Paquete:\n");
    for (i = 0; i < longitud; i++) {
        printf("%02"PRIx8" ", paquete[i]);
    }
    printf("\n");
    return OK;
}

/****************************************************************************************
 * Nombre: calcularChecksum							     	*
 * Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
 * Argumentos:										*
 *   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
 *   -datos: datos sobre los que calcular el checksum					*
 *   -checksum: checksum de los datos (2 bytes) en orden de red! 			*
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum = 0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i = 0; i < longitud; i = i + 2) {
        word16 = (datos[i] << 8) + datos[i + 1];
        sum += (uint32_t) word16;
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
 * Nombre: inicializarPilaEnviar     							*
 * Descripcion: inicializar la pila de red para enviar registrando los distintos modulos *
 * Retorno: OK/ERROR									*
 ****************************************************************************************/

uint8_t inicializarPilaEnviar() {
    bzero(protocolos_registrados, MAX_PROTOCOL * sizeof (pf_notificacion));
    if (registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados) == ERROR)
        return ERROR;
    if (registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados) == ERROR)
        return ERROR;

    //TODO
    //A registrar los modulos de UDP y ICMP [...] 
    if (registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados) == ERROR)
        return ERROR;
    if (registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados) == ERROR)
        return ERROR;
    return OK;
}

/****************************************************************************************
 * Nombre: registrarProtocolo 								*
 * Descripcion: Registra un protocolo en la tabla de protocolos 				*
 * Argumentos:										*
 *  -protocolo: Referencia del protocolo (ver RFC 1700)					*
 *  -handleModule: Funcion a llamar con los datos a enviar				*
 *  -protocolos_registrados: vector de funciones registradas 				*
 * Retorno: OK/ERROR 									*
 *****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados) {
    if (protocolos_registrados == NULL || handleModule == NULL) {
        printf("Error: registrarProtocolo(): entradas nulas.\n");
        return ERROR;
    } else
        protocolos_registrados[protocolo] = handleModule;
    return OK;
}


