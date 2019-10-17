/***************************************************************************
 DisectorQUIC.c

 main y analizar_paquete()

 Compila: gcc -Wall -o disector disectorQUIC.c -lpcap
 Ejecuta: ./disector -f fichero.pcap
 		  ./disector -e conexion

 Autor: Victor Morales Gomez

 Toma como codigo de partida la practica de redes de comunicaciones de la UAM EPS.
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira, Javier Ramos
 2018 EPS-UAM

 Y pagina web de filtrado tcp/ip SNIFFEX-1.C

 Cambios:	
 El filtrado de paquetes se escribe directamente desde el terminal.
 Por ejemplo.
 ./disector -f quic.pcap -e "src or dst 192.168.0.1"

 Usaria como filtro src or dst 192.168.0.1 y filtraria los paquetes que tengan
 192.168.0.1 en ip dst o ip src.

 Para la estructura de datos se utiliza una tabla hash.
 El código de partida de esta tabla hash se puede consultar aqui:

 https://www.tutorialspoint.com/data_structures_algorithms/hash_table_program_in_c.htm

 Para evitar colisiones se ha añadido listas enlazadas.

 Se puede cambiar desde el terminal el número de paquetes necesarios para 
 la llamada a delete_past_session() y el puerto de captura QUIC.
 Esta funcion se encarga de limpiar la memoria de sesiones caducadas

 ./disector -f quic.pcap -e "udp" -v 30000 443
***************************************************************************/

#include "disector.h"
#include "hashtable.h"
#include <endian.h>
#include <time.h>
#include <limits.h>

int numpktout = 10000;
int quic_port = 443;


int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	
	int flag_e = 0;
	int flag_n = 0;
	int long_index = 0, retorno = 0;
	char opt;
	
	/* DECLARACION DE VARIABLES DE FILTRO */
	/* VER SNIFFEX-1.C */

	char filter_exp[] = "";		/* filter expression*/
	struct bpf_program fp;			/* compiled filter program (expression) */
	//bpf_u_int32 mask = 0;			/* subnet mask */
	bpf_u_int32 net = 0;			/* ip */


	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		//printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc == 1) {
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"e", required_argument, 0, 'e'},
		{"n",required_argument,0,'n'},
		{"p",required_argument,0,'p'},
		{"h", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long_only(argc, argv, "f:i:e:n:p:h", options, &long_index)) != -1) {
		switch (opt) {
		case 'i' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				//printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}
		
			if ( (descr = pcap_open_live(optarg, 1518, 0, 100, errbuf)) == NULL){
				//printf("Error: pcap_open_live(): Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}
			break;

		case 'f' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				//printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}

			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				//printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
				exit(ERROR);
			}

			break;

		case 'e' :
			//printf("Filtro introducido:%s \n",argv[4]);
			flag_e = 1;						
			break;

		case 'h' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-e ''filter_exp''] [-n num_pkts_delete] [-p quic port]\n", argv[0]);
			exit(ERROR);
			break;

		case 'n' :
			if(flag_e == 0){
				printf("Please enter a filter before variables:\n");
				printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-e ''filter_exp''] [-n num_pkts_delete] [-p quic port]\n", argv[0]);
				exit(ERROR);
			}
			//printf("Variables introducidas: num pkts delete= %s, quic port= %s\n",argv[6],argv[7]);
			numpktout = atoi(argv[6]);
			flag_n = 1;

			//printf("Num pkt %d\n",numpktout );
			//printf("flag_n %d\n",flag_n );
			//printf("quic port %d\n",quic_port );
			break;

		case 'p' :
			if(flag_e == 0){
				printf("Please enter a filter before variables:\n");
				printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-e ''filter_exp''] [-n num_pkts_delete] [-p quic port]\n", argv[0]);
				exit(ERROR);
			}
			//printf("Variables introducidas: num pkts delete= %s, quic port= %s\n",argv[6],argv[7]);
			if(flag_n == 0)
				quic_port = atoi(argv[6]);
			else
				quic_port = atoi(argv[8]);


			//printf("Num pkt %d\n",numpktout );
			//printf("quic port %d\n",quic_port );
			break;

		case '?' :
		default:
			//printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-e ''filter_exp'']: %d\n", argv[0], argc);
			exit(ERROR);
			break;
		}
	}

	if (!descr) {
		//printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	//printf("\n");

	if(argc == 5 && flag_e == 1){
		//printf("Se ha aplicado el filtro anterior.\n");
		if (pcap_compile(descr, &fp, argv[4], 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(descr));
		exit(EXIT_FAILURE);
		}
	}	
	else{
		//printf("No se aplica filtro.\n");
		if (pcap_compile(descr, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(descr));
		exit(EXIT_FAILURE);	
		}
	}

	/* apply the compiled filter */
	if (pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(descr));
		exit(EXIT_FAILURE);
	}

	/* Precarga de memoria*/
	
	load_mem();
	
	/* Que informacion se va a mostrar para cada sesion*/

	printf("1src_addr;2dst_addr;3src_port;4dst_port;");
	printf("5time_first_pkt;6time_last_pkt;7cid;8hostname;");
	printf("9ctos_ip_len_total;10ctos_ip_header_len_total;11ctos_udp_len_total;");
	printf("12ctos_udp_header_len_total;13ctos_quic_len_total;14ctos_quic_header_len_total;");
	printf("15stoc_ip_len_total;16stoc_ip_header_len_total;17stoc_udp_len_total;");
	printf("18stoc_udp_header_len_total;19stoc_quic_len_total;20stoc_quic_header_len_total;");
	printf("21ctos_first_pkn;22ctos_pkn_max;23ctos_pkn_total;24ctos_void;");
	printf("25stoc_first_pkn;26stoc_pkn_max;27stoc_pkn_total;28stoc_void;");
	printf("29time_first_chlo;30time_first_rej;31time_first_ack;32time_first_nack;");
	printf("33count_chlo;34count_rej;35count_ack;36count_nack;37version;38time_connection_close;39irtt;");
	printf("40rtt_burst;41total_throughput;42quic_throughput;43ctos_loss;44stoc_loss;45rttcalculated;46uaid;47aead\n");


	retorno=pcap_loop(descr,NO_LIMIT,analizar_paquete,NULL);
	switch(retorno)	{
		case OK:
			//printf("Traza leída\n");
			break;
		case PACK_ERR: 
			//printf("Error leyendo paquetes\n");
			break;
		case BREAKLOOP: 
			//printf("pcap_breakloop llamado\n");
			break;
	}
	//printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);


	// Mostrar las sesiones que queden con datos.
	display_all_sessions_final();

	return OK;
}

void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack)
{
	(void)user;
	//printf("*******************************************************\n");
	//printf("-------------------------------------------------------\n");
	//printf("Nuevo paquete capturado el %s\n", ctime((const time_t *) & (hdr->ts.tv_sec)));
	
	contador++;

	// Variables para bucles
	int i = 0;
	int j = 0;

	// Variables para cond logicas
	int offset = 0;		// tag para ver si tiene paquete ip 
	int Udp = 0;
	int Tcp = 0;	// Da warning porque esta comentada la parte de analizar tcp
	int quic = 0;
	int flag_offset = 0;
	int flag_cid = 0;
	int flag_data_len = 0;
	int tag_chlo = 0;
	int tag_rejection = 0;
	int tag_other = 0;
	int tag_ack = 0;
	int tag_nack = 0;
	int tag_cc = 0;
	int flag_reserved = 0;

	// Variables para guardar longitud de paquete
	u_int ip_size = 0;
	u_int udp_size = 8;

	// Variables para guardar en tabla
	char hostname[100] = {"NULL"};
	int key = 0;
	double timesec = 0;
	double timeus = 0;
	double time = 0;
	int src_addr[4] = {0,0,0,0};
	int dst_addr[4] = {0,0,0,0};
	int src_port = 0;
	int dst_port = 0;
	uint64_t cid = 0;
	int version = 0;
	int ip_len = 0;
	int ip_header_len = 0;
	int udp_len = 0;
	int udp_header_len = 0;
	int quic_len = 0;			// Si no viene en cabecera la calculo como udplen - udpheaderlen
	int quic_header_len = 0;	// hay que contar parametro a parametro cuanto mide
	int pkn = 0;
	int pkn_max = 0; 		// Identifica el máximo pkn posible para la sesión

	uint64_t Offset_final = 0;
	uint64_t Offset_inicio = 0;

	int flag_irtt = 0;
	uint64_t IRTT_inicio = 0;
	uint64_t irtt = 0;
	int flag_aead = 0;
	uint64_t AEAD_inicio = 0;
	uint64_t AEAD_final = 0;
	uint64_t avanzar_aead = 0;
	char aead[100] = {"NULL"};

	int flag_uaid = 0;
	uint64_t UAID_inicio = 0;
	uint64_t UAID_final = 0;
	uint64_t avanzar_uaid = 0;
	char uaid[100] = {"NULL"};

	int flag_icsl = 0;
	uint64_t ICSL_inicio = 0;
	int idle_connection_state = -1;

	timesec = hdr->ts.tv_sec;
	timeus = hdr->ts.tv_usec;
	time = timesec + timeus*0.000001;

	// Para eliminar sesiones antiguas invoco la funcion borrar_sesiones
	// Cada 10000 paquetes para dejar que no la llame continuamente
	if(contador%numpktout == 0){
		delete_past_sessions(time);
	}

	/*Para campos ETH se usa casting ya que siempre siguen el mismo orden */
	const struct sniff_ethernet *ethernet;
	ethernet = (struct sniff_ethernet*)(pack);

/*
	//printf("Direccion ETH destino= ");
	//printf("%02X", ethernet->ether_dhost[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		//printf("-%02X", ethernet->ether_dhost[i]);
	}

	//printf("\n");

	//printf("Direccion ETH origen = ");
	//printf("%02X", ethernet->ether_shost[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		//printf("-%02X", ethernet->ether_shost[i]);
	}

	//printf("\n");

	//printf("Tipo ETH= ");
	//printf("%02X", ethernet->ether_type);

	//printf("\n");
*/
	// Hay que comprobar que el paquete sea IP, si no se descarta.

	if(ethernet->ether_type != 8){
		//printf("No es un paquete IP, no se analiza");
		//printf("\n");
		return;
	}
	else{
		//printf("-------------------------------------------------------\n");
		//printf("Es un paquete IP, se analiza:\n");

	/*Para campos IP se usa casting ya que siempre siguen el mismo orden */
		const struct sniff_ip *ip;
		ip = (struct sniff_ip*)(pack + ETH_HLEN);
/*
		//printf("Version IP= ");
		//printf("%u", (((ip)->ip_vhl >> 4) & 0x0f));
		//printf("\n");
		//printf("IP Longitud de Cabecera= ");
*/		
		ip_size = 4*(ip->ip_vhl&0xf);
		ip_header_len = ip_size;
		////printf("ip header size%d\n",ip_size );
/*		//printf("%u Bytes", ip_size);
		//printf("\n");

		//printf("IP Longitud Total= ");
		//printf("%u Bytes", ntohs(ip->ip_len));
*/
		ip_len = ntohs(ip->ip_len);
		////printf("ip len: %d\n",ip_len );
/*
		//printf("\n");

		//printf("Posicion= ");
*/
		offset = 8*(ntohs((ip->ip_off))&0x1FFF);
/*		//printf("%u", offset);

		//printf("\n");

		if(offset != 0x00){

			//printf("No es el primer paquete del fragmento.\n");
			//printf("No se analizan los campos del siguiente nivel.");
			//printf("\n");
		}
		else{

			//printf("Es el primer paquete del fragmento.\n");
			//printf("Se analizan los campos del siguiente nivel.");
			//printf("\n");
		}

		//printf("Tiempo de Vida= ");
		//printf("%u", ip->ip_ttl);
		//printf("\n");

		//printf("Protocolo= ");
		//printf("%u", ip->ip_p);
		//printf("\n");
*/
		if(ip->ip_p == 17){			
			////printf("Es un paquete UDP\n");
			Udp = 1;
		}
		else if(ip->ip_p == 6){		
			////printf("Es un paquete TCP, no lo analizamos\n");
			Tcp = 1;
		}
		else{
			//printf("No es un paquete UDP, no lo analizamos\n");
		}

		//printf("Direccion IP Origen= ");
		//printf("%u", ip->ip_src[0]);
		src_addr[0] = ip->ip_src[0];
		for (i = 1; i <IP_ALEN; i++) {
			//printf(".%u", ip->ip_src[i]);
			src_addr[i] = ip->ip_src[i];
		}
		//printf("\n");

		//printf("Direccion IP Destino= ");
		//printf("%u", ip->ip_dst[0]);
	    dst_addr[0] = ip->ip_dst[0];
		for (j = 1; j <IP_ALEN; j++) {
			//printf(".%u", ip->ip_dst[j]);
	    	dst_addr[j] = ip->ip_dst[j];
		}	
		//printf("\n");

		if(Udp == 1 && offset == 0){ 
			//printf("-------------------------------------------------------");
			//printf("\n");

			/*Para campos UDP se usa casting ya que siempre siguen el mismo orden */
			const struct sniff_udp *udp;
			udp = (struct sniff_udp*)(pack + ETH_HLEN + ip_size);

			//printf("Es un paquete UDP, se analiza:");
			//printf("\n");		
			//printf("Puerto Origen= ");		
			//printf("%u", ntohs(udp->udp_sport));
			src_port = ntohs(udp->udp_sport);
			//printf("\n");

			if((ntohs(udp->udp_sport)) == quic_port){ // Miro el puerto para ver si es quic
				quic = 1;
			}
		
			//printf("Puerto Destino= ");
			//printf("%u", ntohs(udp->udp_dport));
			dst_port = ntohs(udp->udp_dport);
			//printf("\n");
			
			if((ntohs(udp->udp_dport)) == quic_port){
				quic = 1;
			}
/*
			//printf("Longitud= ");
					
			//printf("%u", ntohs(udp->udp_length));
			//printf("\n");
*/			

			udp_len = ntohs(udp->udp_length);
			////printf("udp len: %d\n",udp_len );
			udp_header_len = udp_size;
			////printf("udp header size %d\n",udp_header_len );


			//printf("-------------------------------------------------------");
			//printf("\n");
		
			if(quic == 1){

				//printf("Es un paquete QUIC, se analiza:\n");

	/*Para campos QUIC no se puede usar correctamente el casting por que no todos los campos aparecen siempre*/
				const struct sniff_quic *quic;
				quic = (struct sniff_quic*)(pack + ETH_HLEN + ip_size + udp_size);

				pack += ETH_HLEN + ip_size + udp_size;
				
				////printf("Flags= ");
				////printf("%02X", quic->quic_flags);
				////printf("\n");
				
				pack += QUIC_FLAG;
				quic_header_len += QUIC_FLAG;

				quic_len = udp_len - udp_header_len;

				// Si flag reserved es 1 , no se analiza el paquete por que no esta previsto que RESERVED sea distinto de 0
				if((quic->quic_flags&QUIC_RESERVED) != 0){
					flag_reserved = 1;
				}
				else{
					if((quic->quic_flags&QUIC_CONNECTION_ID) != 0){ // Si esta activado el flag de CID lo imprimimos
						
						////printf("CID= "); // Ojo hay que pasarlo a numero
						flag_cid = 1;
						cid = be64toh(* (uint64_t *) pack);
						////printf("%lu\n",cid);
						pack += QUIC_CID;
						quic_header_len += QUIC_CID;					
					}

					if((quic->quic_flags&QUIC_VERSION) != 0){
						
						////printf("Version[hex]= ");
						version = ((uint64_t)(pack[0] << 24 | pack[1] << 16 | pack[2] << 8 | pack[3]));

						////printf("%lX", version);

						if(version == 0x51303433){
							version = 43;
							////printf(" -> Q043");
						}
						else{
							version = -1;
							////printf("\nATENCION: VERSION DISTINTA DE Q043");
						}
					
						////printf("\n");
						pack += QUIC_VERSION_LEN;
						quic_header_len += QUIC_VERSION_LEN;
					}
						
					if(((quic->quic_flags&QUIC_NONCE) != 0) && (flag_cid == 0)){
					
						//printf("Este paquete contiene NONCE HASH\n");
						pack += QUIC_NONCE_LEN;
						quic_header_len += QUIC_NONCE_LEN;
					}
					
					if((quic->quic_flags&QUIC_PKN_SIZE) == 0x00){
						////printf("PKN num = 00b\n");
						//printf("PKN= ");
						pkn = (int)pack[0];
						//printf("%02X",pkn); // Default size 00c-> 8bits -> 1 byte
						//printf("\n");
						pack += QUIC_PKN_SIZE_1;
						quic_header_len += QUIC_PKN_SIZE_1;
						pkn_max = 255;
					}	
						
					else if((quic->quic_flags&QUIC_PKN_SIZE) == 0x10){
						////printf("PKN num = 01b\n");
						//printf("PKN 16= ");
						pkn = (int)(pack[0]<<8 | pack[1]);
						//printf("%d",pkn);
						//printf("\n");
						pack += QUIC_PKN_SIZE_2;
						quic_header_len += QUIC_PKN_SIZE_2;
						pkn_max = 65535;
					}
						
					else if((quic->quic_flags&QUIC_PKN_SIZE) == 0x20){
						////printf("PKN num = 10b\n");
						//printf("PKN 32= ");
						pkn = (int)(pack[0] << 24 | pack[1] << 16 | pack[2] << 8 | pack[3]);
						//printf("%d",pkn);
						//printf("\n");
						pack += QUIC_PKN_SIZE_4;
						quic_header_len += QUIC_PKN_SIZE_4;
						pkn_max = INT_MAX;		// Si se ven pkn tan grande habra que cambiar de int a double
					}
						
					else if((quic->quic_flags&QUIC_PKN_SIZE) == 0x30){
						pkn = be64toh(* (uint64_t *) pack);
						//printf("\n");
						pack += QUIC_PKN_SIZE_6;
						quic_header_len += QUIC_PKN_SIZE_6;
						pkn_max = INT_MAX; //281474976710655;
					}

						pack += QUIC_MESSAGE_AUTENTICATION_HASH; // asumo que hay message aut hash para ver si es cierto.

						if((pack[0] == 0x40) && (flag_cid == 1) && (ip_len > 1300) ){ // si habia cid y tiene 0x40 es ack
							tag_ack = 1;
							quic_header_len += QUIC_MESSAGE_AUTENTICATION_HASH;

							pack += QUIC_ACK_LEN;
							quic_header_len += QUIC_ACK_LEN;

							if(pack[0] == 0x06){	// Stop waiting
								pack += QUIC_ACK_LEN_STOP_WAITING;
								quic_header_len += QUIC_ACK_LEN_STOP_WAITING;
							}
							//printf("%02X ",pack[0]);
						}
						else if((pack[0] == 0x20) && (flag_cid == 1) && (ip_len > 1300) ){ // si habia cid y tiene 0x40 es nack

							//printf("Es NACK");
							tag_nack = 1;
							quic_header_len += QUIC_MESSAGE_AUTENTICATION_HASH;

							pack += QUIC_NACK_LEN; // Salto todos los campos de nack
							quic_header_len += QUIC_NACK_LEN;
							//printf("%02X ",pack[0]);
						}

						//detectar CC. Primero detectar ACK (en caso de CC no tienen pq ser > 1300) y luego CC
						if((pack[0] == 0x40) && (flag_cid == 1) ){ // si habia cid y tiene 0x40 es ack

							quic_header_len += QUIC_MESSAGE_AUTENTICATION_HASH;

							// Aqui se puede ver el server connection close

							pack += QUIC_ACK_LEN; // Salto todos los campos de ack
							quic_header_len += QUIC_ACK_LEN;

							// Deteccion de Connection close
							//printf("<%02x %02x> ",pack[0],pack[1] );
							if((pack[0] == 0x02)){
								tag_cc = 1;
								quic_header_len += QUIC_CC_LEN;

							}
							pack -= QUIC_ACK_LEN;
						}
						
						if(((pack[0]&QUIC_STREAM ) == 0x80) && (flag_cid == 1)){

							//printf("Es paquete STREAM SPECIAL FRAME TYPE\n");
							//printf("%02X\n",(pack[0]&QUIC_STREAM) );
							
							// Hay que comprobar el frame type
							
							if((pack[0]&QUIC_OFFSET) == 0x04){ // hay mas casos

								//printf("Tiene offset\n");
								flag_offset = 1;
							}

							if((pack[0]&QUIC_FLAG_DATA_LEN) == 0x20){

								//printf("Tiene data length\n");
								flag_data_len = 1;
							}
							if(flag_offset == 1){

								pack += QUIC_OFFSET_LEN;
								quic_header_len += QUIC_OFFSET_LEN;

							}

							pack += QUIC_FRAME_TYPE_LEN;
							quic_header_len += QUIC_FRAME_TYPE_LEN;
		
							pack += QUIC_STREAM_ID_LEN;
							quic_header_len += QUIC_STREAM_ID_LEN;

							if(flag_data_len == 1){
								//quic_len = (int)(pack[0]<<8 | pack[1]);
								////printf("Data length= %u\n",quic_len);
								//printf("Data length= %u\n",(int)(pack[0]<<8 | pack[1]));
								pack += QUIC_DATA_LEN;
								quic_header_len += QUIC_DATA_LEN;
							}

							uint64_t special_frame_tag = ((uint64_t)(pack[0] << 24 | pack[1] << 16 | pack[2] << 8 | pack[3]));
							//printf("TAG[hex]= %lX\n", special_frame_tag);

							if(special_frame_tag == 0x43484c4f){
								tag_chlo = 1;
								//printf("Es CHLO:\n");
								quic_header_len = quic_len;	// No hay payload
							}
							else if(special_frame_tag == 0x52454a00){
								tag_rejection = 1;
								//printf("Es REJECTION\n");
								quic_header_len = quic_len;	// No hay payload

							}
							else{
								tag_other = 1;
								//printf("No es CHLO ni REJECTION!!\n");
							}

							pack += QUIC_TAG_LEN;

							//printf("avanzar hex %02X\n",pack[0] );
							//printf("%02X\n",pack[1] );

							int tag = ntohs((int)(pack[0] << 8 | pack[1]));
							//printf("tag %d \n",tag );

							int avanzar = tag;	// hay #tag campos que avanzar, cada campo vale 8 bytes
							//printf("avanzar %d\n",avanzar );

							pack += QUIC_TAG_NUMBER_LEN + QUIC_PADDING_LEN;

							if(tag_rejection == 1){

								pack += avanzar*8;

							}
							else if(tag_chlo == 1){

								// Campo PAD
								pack += QUIC_TAG_PAD/2;
								uint64_t PAD_length = ((uint64_t)(ntohs(pack[0] << 8 | pack[1])&0x03ff));
								//printf("PAD length= %lu\n", PAD_length);
								//printf("PAD length[hex]= %lX\n", PAD_length);
								pack += QUIC_TAG_PAD/2;

								// Aqui empieza el campo SNI -> Mirar hostname

								// SNI sumar length para llegar a hostname
								//printf("SNI[hex]= ");
								//uint64_t sni = 0;
								pack += QUIC_TAG_SNI/2;

								uint64_t SNI_length = ((uint64_t)(ntohs(pack[0] << 8 | pack[1])&0x03ff));
								Offset_final = SNI_length;
								
								pack += QUIC_TAG_SNI/2;

								uint64_t tag_sni_len = SNI_length - PAD_length;

								if(SNI_length < PAD_length){
									tag_sni_len = 1; // evitar seg faut
									//printf("ERROR EN tag_sni_len\n");
								}

								for(j = 0;j< avanzar - 2; j++){

									Offset_inicio = Offset_final;
									Offset_final = ((uint64_t)(ntohs(pack[4] << 8 | pack[5])&0x03ff));

									//UAID
									if((pack[0] == 0x55) && (pack[1] == 0x41) && (pack[2] == 0x49) && (pack[3] == 0x44)){

										//printf("Entra a uaid\n");
										UAID_inicio = Offset_inicio;
										UAID_final = Offset_final;
										flag_uaid = 1;
										//printf("UAID_inicio %ld\n",UAID_inicio );
										//printf("UAID_final %ld\n",UAID_final );
									}
									//AEAD
									else if((pack[0] == 0x41) && (pack[1] == 0x45) && (pack[2] == 0x41) && (pack[3] == 0x44)){

										//printf("Entra a aead\n");
										AEAD_inicio = Offset_inicio;
										AEAD_final = Offset_final;
										flag_aead = 1;
										//printf("AEAD_inicio %ld\n",AEAD_inicio );
										//printf("AEAD_final %ld\n",AEAD_final );
									}
									//IRTT
									else if((pack[0] == 0x49) && (pack[1] == 0x52) && (pack[2] == 0x54) && (pack[3] == 0x54)){

										//printf("Entra a IRTT\n");
										IRTT_inicio = Offset_inicio;
										//IRTT_final = Offset_final;
										flag_irtt = 1;
										//printf("IRTT_inicio %ld\n",IRTT_inicio );
										//printf("IRTT_final %ld\n",IRTT_final );
									}
									//ICSL
									else if((pack[0] == 0x49) && (pack[1] == 0x43) && (pack[2] == 0x53) && (pack[3] == 0x4c)){

										//printf("Entra a ICSL\n");
										ICSL_inicio = Offset_inicio;
										//ICSL_final = Offset_final;
										flag_icsl = 1;
										//printf("ICSL_inicio %ld\n",ICSL_inicio );
										//printf("ICSL_final %ld\n",ICSL_final );
									}


									pack += 8;
								}
								pack += PAD_length;
								//printf("SNI length %d\n",SNI_length );
								//printf("PAD length %d\n",PAD_length );

								// captura del hostname
								for(i = 0; i<tag_sni_len; i++){
									hostname[i] = pack[i];
								}

								pack += tag_sni_len;

								// captura deñ uaid
								if(flag_uaid == 1){
									pack += UAID_inicio - SNI_length;
									avanzar_uaid = UAID_final - UAID_inicio;
									//printf("%ld\n",avanzar_uaid );
									for(i = 0; i<avanzar_uaid; i++){
										uaid[i] = pack[i];
										//printf("%c",pack[i] );
									}
									pack -= UAID_inicio - SNI_length;
								}

								// captura del aead y el irtt
								if(flag_aead == 1){
									pack += AEAD_inicio - SNI_length;
									avanzar_aead = AEAD_final - AEAD_inicio;
									for(i = 0; i<avanzar_aead; i++){
										aead[i] = pack[i];
										//printf("%c",pack[i] );
									}
									pack -= AEAD_inicio - SNI_length;
								}

								if(flag_irtt == 1){
									pack += IRTT_inicio - SNI_length;
									irtt = (uint64_t)(pack[3] << 24 | pack[2] << 16 | pack[1] << 8 | pack[0]);
									pack -= IRTT_inicio - SNI_length;
								}

								if(flag_icsl == 1){
									pack += ICSL_inicio - SNI_length;
									idle_connection_state = (int)(pack[3] << 24 | pack[2] << 16 | pack[1] << 8 | pack[0]);
									pack -= ICSL_inicio - SNI_length;
								}
							}

						}

					key =  src_addr[0]*1000+ src_addr[1];
					key +=  src_addr[2]*1000+ src_addr[3];

					key +=  dst_addr[0]*1000+ dst_addr[1];
					key +=  dst_addr[2]*1000+ dst_addr[3];

					key +=  src_port +  dst_port;
					//printf("Key: %d\n",key);

					//printf("\n%ld.",contador );
					insert(key,hostname,src_addr,dst_addr,src_port,dst_port,cid,pkn,pkn_max,time,ip_len,ip_header_len,udp_len,udp_header_len,quic_len,quic_header_len,tag_chlo,tag_rejection,tag_other,tag_ack,tag_nack,tag_cc,version,irtt,uaid,aead,idle_connection_state);
				}//Cierre de If reserved
				//printf("\n\n");		
			} // cierre de cond quic
		} // Cierre de cond udp
/*
			else if(Tcp == 1 && offset == 0){ // QUIC funciona por UDP, no analizaremos los paquetes TCP aun que si los detectaremos.
				return;
		
				//printf("-------------------------------------------------------");
				//printf("\n");

				const struct sniff_tcp *tcp;
				tcp = (struct sniff_tcp*)(pack + ETH_HLEN + ip_size);

				//printf("Es un paquete TCP, se analiza:");
		
				//printf("\n");
				//printf("Puerto Origen= ");
		
				//printf("%u", ntohs(tcp->th_sport));
		
				//printf("\n");

				//printf("Puerto Destino= ");
		
				//printf("%u", ntohs(tcp->th_dport));
				//printf("\n");
				
				//printf("Bandera SYN= ");
				if((tcp->th_flags&TH_SYN) != 0)
					//printf("1");
				else
					//printf("0");
					
				//printf("\n");
				
				//printf("Bandera FIN= ");
				if((tcp->th_flags&TH_FIN) != 0)
					//printf("1");
				else
					//printf("0");
				//printf("\n");
		
					// A PARTIR DE AQUI SERIAN OTROS CAMPOS TCP QUE NO PIDEN Y LUEGO DATOS
			}
*/
	}
}

