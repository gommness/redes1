/***************************************************************************
 practica2.c
 Muestra las direciones Ethernet de la traza que se pasa como primer parametro.
 Debe complatarse con mas campos de niveles 2, 3, y 4 tal como se pida en el enunciado.
 Debe tener capacidad de dejar de analizar paquetes de acuerdo a un filtro.

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Javier Gomez Martinez y Carlos Li Hu
 2016 EPS-UAM
 ***************************************************************************/

#include "practica2.h"

pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipo_filtro[IP_ALEN] = {0};
uint8_t ipd_filtro[IP_ALEN] = {0};
uint16_t po_filtro = 0;
uint16_t pd_filtro = 0;

void handleSignal(int nsignal) {
    (void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

    printf("Control C pulsado (%"PRIu64" paquetes leidos)\n", contador);
    pcap_close(descr);
    exit(OK);
}

int main(int argc, char **argv) {

    uint8_t *paquete = NULL;
    struct pcap_pkthdr *cabecera;

    char errbuf[PCAP_ERRBUF_SIZE];
    char entrada[256];
    int long_index = 0, retorno = 0;
    char opt;

    (void) errbuf; //indicamos al compilador que no nos importa que errbuf no se utilice. Esta linea debe ser eliminada en la entrega final.

    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }

    if (argc > 1) {
        if (strlen(argv[1]) < 256) {
            strcpy(entrada, argv[1]);
        }

    } else {
        printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
        exit(ERROR);
    }

    static struct option options[] = {
        {"f", required_argument, 0, 'f'},
        {"i", required_argument, 0, 'i'},
        {"ipo", required_argument, 0, '1'},
        {"ipd", required_argument, 0, '2'},
        {"po", required_argument, 0, '3'},
        {"pd", required_argument, 0, '4'},
        {"h", no_argument, 0, '5'},
        {0, 0, 0, 0}
    };

    //Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
    while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
        switch (opt) {
            case 'i':
                if (descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
                    printf("Ha seleccionado más de una fuente de datos\n");
                    pcap_close(descr);
                    exit(ERROR);
                }
                
                if ((descr = pcap_open_live(optarg, ETH_FRAME_MAX, 0, 100, errbuf)) == NULL) {
                    printf("Error: pcap_open_live(): Interface: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
                    exit(ERROR);
                }
                break;

            case 'f':
                if (descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
                    printf("Ha seleccionado más de una fuente de datos\n");
                    pcap_close(descr);
                    exit(ERROR);
                }
                
                if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
                    printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
                    exit(ERROR);
                }

                break;

            case '1':
                if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipo_filtro[0]), &(ipo_filtro[1]), &(ipo_filtro[2]), &(ipo_filtro[3])) != IP_ALEN) {
                    printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                    exit(ERROR);
                }

                break;

            case '2':
                if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipd_filtro[0]), &(ipd_filtro[1]), &(ipd_filtro[2]), &(ipd_filtro[3])) != IP_ALEN) {
                    printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                    exit(ERROR);
                }

                break;

            case '3':
                if ((po_filtro = atoi(optarg)) == 0) {
                    printf("Error o_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                    exit(ERROR);
                }

                break;

            case '4':
                if ((pd_filtro = atoi(optarg)) == 0) {
                    printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                    exit(ERROR);
                }

                break;

            case '5':
                printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                exit(ERROR);
                break;

            case '?':
            default:
                printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                exit(ERROR);
                break;
        }
    }

    if (!descr) {
        printf("No selecciono ningún origen de paquetes.\n");
        return ERROR;
    }

    //Simple comprobacion de la correcion de la lectura de parametros
    printf("Filtro:");
    if(ipo_filtro[0]!=0)
		printf("ipo_filtro:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipo_filtro[0], ipo_filtro[1], ipo_filtro[2], ipo_filtro[3]);
    if(ipd_filtro[0]!=0)
		printf("ipd_filtro:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipd_filtro[0], ipd_filtro[1], ipd_filtro[2], ipd_filtro[3]);

    if (po_filtro != 0) {
        printf("po_filtro=%"PRIu16"\t", po_filtro);
    }

    if (pd_filtro != 0) {
        printf("pd_filtro=%"PRIu16"\t", pd_filtro);
    }

    printf("\n\n");

    do {
        retorno = pcap_next_ex(descr, &cabecera, (const u_char **) &paquete);

        if (retorno == 1) { //Todo correcto
            contador++;
            analizar_paquete(cabecera, paquete);

        } else if (retorno == -1) { //En caso de error
            printf("Error al capturar un paquete %s, %s %d.\n", pcap_geterr(descr), __FILE__, __LINE__);
            pcap_close(descr);
            exit(ERROR);

        }
    } while (retorno != -2);

    printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
    pcap_close(descr);
    return OK;
}



//--------------------------------------------------------------------------------------------------------------------------------------------

void analizar_paquete(const struct pcap_pkthdr *cabecera, const uint8_t *paquete) {
    int flag = 0;
    int ihl=0;
    int continuar = SI;
    int udp = NO;
    int i = 0;

    printf("Paquete numero %"PRIu64" capturado el %s\n", contador, ctime((const time_t *) & (cabecera->ts.tv_sec)));

    //CAMPOS DE NIVEL 2

    //campo direccion destino
    printf("--INFORMACION NIVEL 2--\nDireccion ETH destino= ");
    printf("%02X", paquete[0]);
    for (i = 1; i < ETH_ALEN; i++) {
        printf(":%02X", paquete[i]);
    }
    printf("\n");
    paquete += ETH_ALEN;


    //campo direccion origen
    printf("Direccion ETH origen = ");
    printf("%02X", paquete[0]);
    for (i = 1; i < ETH_ALEN; i++) {
        printf(":%02X", paquete[i]);
    }
    printf("\n");
    paquete += ETH_ALEN;


    //campo tipo ethernet
    printf("tipo ETH = %04X", ntohs(*(uint16_t*) paquete));
    printf("\n\n");

    //CAMPOS DE NIVEL 3
    if (paquete[0] == 0x08 && paquete[1] == 0x00 && (paquete[2]&0xF0) == 0x40) {//que sea tipo IPv4
        //1 nibble version
        printf("--INFORMACION NIVEL 3--\nversion = IPv4\n");
        paquete += ETH_TLEN;
        //1 nibble IHL
        printf("IHL = %d\n", ((*paquete)&0x0F) << 2);
        ihl=((*paquete)&0x0F) << 2;
        paquete += IP_IHL_LEN;

        //1 byte Tipo Servicio
        printf("tipo servicio = %d\n", *paquete);
        paquete += IP_SERVICE_TYPE_LEN;

        //2 bytes longitud total
        printf("longitud total = %d\n", ntohs( *(uint16_t*)paquete));
        paquete += IP_TOTAL_LEN;


        //2 bytes identificacion
        /*printf("\nidentificacion = ");
        for(i = 0; i < IP_ID_LEN; i++)
                printf("%d",paquete[i]<<8*(IP_ID_LEN-i-1));*/
        paquete += IP_ID_LEN;

        //3 bits flags y 13 bits posicion
        //printf("\nflags   %d\n",(ntohs((*(uint16_t*)paquete))&0xE000)>>13);
        printf("posicion = %d\n", (ntohs(*(uint16_t*) paquete)&0x1FFF) << 3);
        if (((((*paquete)&0x1F) << 8) + (paquete[1])) != 0) {
            printf("El paquete leido no es el primer fragmento\n");
            continuar = NO;
        }
        paquete += IP_POS_LEN;

        //1 byte tiempo de vida
        printf("tiempo de vida = %d\n", *paquete);
        paquete += IP_LIFE_LEN;

        //1 byte protocolo
        printf("protocolo = %d\n", *paquete);

        if (*paquete != 6 && *paquete != 17) {
            printf("El protocolo no es ni TPC ni UDP\n");
            continuar = NO;
        }
        if (*paquete == 17)
            udp = SI;
        paquete += IP_PROTOCOL_LEN;

        //2 byte checksum
        //printf("checksum = %d\n", ntohs( *(uint16_t*)paquete));

        paquete += IP_CHECKSUM_LEN;

        //4 bytes direccion de origen
        printf("\ndireccion origen = ");
        printf("%d", paquete[0]);


        flag = 0;
        if (paquete[0] == ipo_filtro[0])
            flag++;
        for (i = 1; i < IP_SRC_LEN; i++) {
            printf(".%d", paquete[i]);
            if (paquete[i] == ipo_filtro[i])
                flag++;

        }
        if (ipo_filtro[0] != 0 && flag != IP_SRC_LEN) {//si hay algo dentro del filtro y el flag no se ha cumplido para los 4 Bytes
            printf("\nEste campo no cumple el filtro ipo\n\n\n\n\n");
            return;
        }





        paquete += IP_SRC_LEN;

        //4 bytes direccion de destino
        printf("\ndireccion destino = ");
        printf("%d", paquete[0]);
        flag = 0;
        if (paquete[0] == ipd_filtro[0])
            flag++;

        for (i = 1; i < IP_DST_LEN; i++) {
            printf(".%d", paquete[i]);
            if (paquete[i] == ipd_filtro[i]) {
                flag++;
            }
        }
        if (ipd_filtro[0] != 0 && flag != IP_DST_LEN) {
            printf("\nEste campo no cumple el filtro ipd\n\n\n\n\n");
            return;
        }




        paquete += IP_DST_LEN+(ihl-20);
        //3 bytes opciones
        /*printf("\nopciones = ");
        for(i = 0; i < IP_OP_LEN; i++)
                printf("%d",paquete[i]<<8*(IP_OP_LEN-i-1));*/
        /*paquete += IP_OP_LEN;
		
        //relleno
        printf("\nrelleno = %X\n",*paquete);
        paquete += IP_RELL_LEN
         */
        if (continuar == SI) {
            //CAMPOS DE NIVEL 4
            //2 bytes puerto origen
            printf("\n\n--INFORMACION NIVEL 4--\nPuerto Origen= %d", ntohs(*(uint16_t*) paquete));
            if (ntohs(*(uint16_t*) paquete) != po_filtro && po_filtro != 0) {
                printf("\nEste campo no cumple el filtro po\n\n\n\n\n");
                return;
            }
            paquete += SRC_PORT_LEN;

            //2 bytes puerto destino
            printf("\nPuerto Destino= %d", ntohs(*(uint16_t*) paquete));
            if (ntohs(*(uint16_t*) paquete) != pd_filtro && pd_filtro != 0) {
                printf("\nEste campo no cumple el filtro pd\n\n\n\n\n");
                return;
            }

            paquete += DST_PORT_LEN;

            //longitud si es tipo udp
            if (udp == SI) {
                printf("\nLongitud= %d", ntohs(*(uint16_t*) paquete));
                paquete += UDP_LEN;
            }
            printf("\n");

        }
        printf("\n\n");
    } else
        printf("Este paquete no es IPv4\n\n");

    printf("\n\n\n\n\n\n");
	
	return;
	
}

