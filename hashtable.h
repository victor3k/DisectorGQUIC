/***************************************************************************
 hashtable.h

 Estructura de datos usada en disectorQUIC.c

 Hashtable + linked list

 Codigo base de la hashtable:
 https://www.tutorialspoint.com/data_structures_algorithms/hash_table_program_in_c.htm

***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define SIZE 20000

/*Definición de los campos de la estructura de sesión*/
typedef struct Session {
  int key;
  int src_addr[4];
  int dst_addr[4];
  int src_port;
  int dst_port;
  uint64_t cid;
  int version;

  char hostname[100];
  char uaid[100];
  char aead[100];

  double time_first_pkt;
  double time_last_pkt;

  int status;
  int idle_connection_state; //predet a -1 -> no se usa, 30 seg de timeout

  int ctos_pkn_first;
  int ctos_pkn_max;
  int ctos_pkn_total;
  int ctos_void;

  int stoc_pkn_first;
  int stoc_pkn_max;
  int stoc_pkn_total;
  int stoc_void;

  double ctos_ip_len_total;             // bytes de protocolo IP
  double ctos_ip_header_len_total;      // bytes utiles de protocolo IP -> total - cabecera
  double ctos_udp_len_total;            // bytes de protocolo UDP
  double ctos_udp_header_len_total;     // bytes utiles de protocolo UDP -> total - cabecera
  double ctos_quic_len_total;           // bytes de protocolo QUIC
  double ctos_quic_header_len_total;    // bytes utiles de protocolo QUIC -> total - cabecera 

  double stoc_ip_len_total;             // bytes de protocolo IP
  double stoc_ip_header_len_total;      // bytes utiles de protocolo IP -> total - cabecera
  double stoc_udp_len_total;            // bytes de protocolo UDP
  double stoc_udp_header_len_total;     // bytes utiles de protocolo UDP -> total - cabecera
  double stoc_quic_len_total;           // bytes de protocolo QUIC
  double stoc_quic_header_len_total;    // bytes utiles de protocolo QUIC -> total - cabecera 

  double time_first_chlo;
  double time_first_rej;
  double time_first_ack;
  double time_first_nack;

  int count_chlo;
  int count_rej;
  int count_ack;
  int count_nack;

  double time_connection_close; // si hay cc se guarda el time

  int irtt;

  double ctos_time_burst_start;
  double ctos_time_burst_end_aux;
  double ctos_time_burst_end;
  double stoc_time_burst_start;
  double stoc_time_burst_end_aux;
  double stoc_time_burst_end;

  double rtt_burst;

  double total_throughput;
  double quic_throughput;
  double pkt_loss;
  double rtt_calculated;

  struct Session* nextListSession;
   
}Session;

struct Session* hashArray[SIZE]; 
struct Session* dummyItem;
struct Session* item;

/*Funciones que se utilizan*/
void analize_time(struct Session* sesion, double time_new_pkt,int is_connection_close,int idle_connection_state,char hostname[100],char uaid[100]);
void analize_pkn(struct Session* sesion,int pkn,int flag,int pkn_max_possible);
void analize_length(struct Session* sesion,int ip_len,int ip_header_len,int udp_len,int udp_header_len,int quic_len,int quic_header_len,int flag);
void analize_special_pkt(struct Session* sesion,int is_chlo,int is_rej,int is_other,int is_ack,int is_nack,double time,int irtt,char aead[100]);
void analize_burst(struct Session* sesion, double time_new_pkt, double time_max_burst,int flag);
void qos_measurements(struct Session* sesion);
void print_session(struct Session* aux);

//  Funcion para calcular INDEX con la KEY
int hashCode(int key) {
   return key % SIZE;
}

// Funcion para borrar las sesiones caducadas
// Problema, no borra las sesiones en linked list
void delete_past_sessions(double time){

int i;

  for(i = 0; i<SIZE; i++){

    // Si ha pasado 1 minuto o mas desde la llegada del ultimo paquete, se borra la sesion
    if((hashArray[i]->time_last_pkt + 60 < time) && (hashArray[i]->time_last_pkt != -1)){

      qos_measurements(hashArray[i]);
      print_session(hashArray[i]);
      
      // borrar todos los datos de la sesion
      hashArray[i]->key = i;
      hashArray[i]->src_addr[0] = -1;
      hashArray[i]->src_addr[1] = -1;
      hashArray[i]->src_addr[2] = -1;
      hashArray[i]->src_addr[3] = -1;
      hashArray[i]->dst_addr[0] = -1;
      hashArray[i]->dst_addr[1] = -1;
      hashArray[i]->dst_addr[2] = -1;
      hashArray[i]->dst_addr[3] = -1;
      hashArray[i]->src_port = 0;
      hashArray[i]->dst_port = 0;
      hashArray[i]->cid = 0;

      strcpy(hashArray[i]->hostname,"NULL");
      strcpy(hashArray[i]->uaid,"NULL");
      strcpy(hashArray[i]->aead,"NULL");

      hashArray[i]->time_first_pkt = -1;
      hashArray[i]->time_last_pkt = -1;

      hashArray[i]->ctos_pkn_first = 0;
      hashArray[i]->ctos_pkn_max = 0;
      hashArray[i]->ctos_pkn_total = 0;
      hashArray[i]->ctos_void = 0;

      hashArray[i]->stoc_pkn_first = 0;
      hashArray[i]->stoc_pkn_max = 0;
      hashArray[i]->stoc_pkn_total = 0;
      hashArray[i]->stoc_void = 0;

      hashArray[i]->ctos_ip_len_total = 0;
      hashArray[i]->ctos_ip_header_len_total = 0;
      hashArray[i]->ctos_udp_len_total = 0;
      hashArray[i]->ctos_udp_header_len_total = 0;
      hashArray[i]->ctos_quic_len_total = 0;
      hashArray[i]->ctos_quic_header_len_total = 0;

      hashArray[i]->stoc_ip_len_total = 0;
      hashArray[i]->stoc_ip_header_len_total = 0;
      hashArray[i]->stoc_udp_len_total = 0;
      hashArray[i]->stoc_udp_header_len_total = 0;
      hashArray[i]->stoc_quic_len_total = 0;
      hashArray[i]->stoc_quic_header_len_total = 0;

      hashArray[i]->time_first_chlo = -1;
      hashArray[i]->time_first_rej = -1;
      hashArray[i]->time_first_ack = -1;
      hashArray[i]->time_first_nack = -1;

      hashArray[i]->count_chlo = 0;
      hashArray[i]->count_rej = 0;
      hashArray[i]->count_ack = 0;
      hashArray[i]->count_nack = 0;

      hashArray[i]->version = -1;
      hashArray[i]->time_connection_close = -1;
      hashArray[i]->irtt = -1;

      hashArray[i]->ctos_time_burst_start = 0;
      hashArray[i]->ctos_time_burst_end_aux = 0;
      hashArray[i]->ctos_time_burst_end = 0;
      hashArray[i]->stoc_time_burst_start = 0;
      hashArray[i]->stoc_time_burst_end_aux = 0;
      hashArray[i]->stoc_time_burst_end = 0;
      hashArray[i]->rtt_burst = 0;

      hashArray[i]->total_throughput = 0;
      hashArray[i]->quic_throughput = 0;
      hashArray[i]->pkt_loss = 0;
      hashArray[i]->rtt_calculated = 0;

      // El puntero a la siguiente estructura no se cambia.

    }
  }

}

// Funcion que carga la memoria antes de la captura de paquetes
void load_mem(){
	/* Precargar a 0 los registros de toda la tabla hash*/
	int i = 0;
    
  struct Session *item = (struct Session*) malloc(SIZE*sizeof(struct Session));

	for(i = 0;i< SIZE;i++){

		item->key = 0;
   	item->src_addr[0] = -1;
   	item->src_addr[1] = -1;
   	item->src_addr[2] = -1;
   	item->src_addr[3] = -1;
   	item->dst_addr[0] = -1;
   	item->dst_addr[1] = -1;
   	item->dst_addr[2] = -1;
   	item->dst_addr[3] = -1;
   	item->src_port = 0;
   	item->dst_port = 0;
   	item->cid = 0;
   	strcpy(item->hostname,"NULL");
    strcpy(item->uaid,"NULL");
    strcpy(item->aead,"NULL");

   	item->time_first_pkt = -1;
  	item->time_last_pkt = -1;

   	item->ctos_pkn_first = 0;
   	item->ctos_pkn_max = 0;
   	item->ctos_pkn_total = 0;
   	item->ctos_void = 0;

  	item->stoc_pkn_first = 0;
  	item->stoc_pkn_max = 0;
  	item->stoc_pkn_total = 0;
  	item->stoc_void = 0;

  	item->ctos_ip_len_total = 0;
  	item->ctos_ip_header_len_total = 0;
 		item->ctos_udp_len_total = 0;
  	item->ctos_udp_header_len_total = 0;
  	item->ctos_quic_len_total = 0;
  	item->ctos_quic_header_len_total = 0;

  	item->stoc_ip_len_total = 0;
  	item->stoc_ip_header_len_total = 0;
  	item->stoc_udp_len_total = 0;
  	item->stoc_udp_header_len_total = 0;
  	item->stoc_quic_len_total = 0;
  	item->stoc_quic_header_len_total = 0;

  	item->time_first_chlo = -1;
  	item->time_first_rej = -1;
  	item->time_first_ack = -1;
  	item->time_first_nack = -1;

  	item->count_chlo = 0;
  	item->count_rej = 0;
  	item->count_ack = 0;
  	item->count_nack = 0;

    item->version = -1;
    item->time_connection_close = -1;
    item->irtt = -1;

   	item->nextListSession = NULL;

    item->ctos_time_burst_start = 0;
    item->ctos_time_burst_end_aux = 0;
    item->ctos_time_burst_end = 0;
    item->stoc_time_burst_start = 0;
    item->stoc_time_burst_end_aux = 0;
    item->stoc_time_burst_end = 0;
    hashArray[i]->rtt_burst = 0;

    hashArray[i]->total_throughput = 0;
    hashArray[i]->quic_throughput = 0;
    hashArray[i]->pkt_loss = 0;
    hashArray[i]->rtt_calculated = 0;

		hashArray[i] = item;

    item ++;
	}
}


// Funcion que inserta la info de los paquetes en los campos que corresponde
void insert(int key,char hostname[100],int src_addr[4],int dst_addr[4],int src_port,int dst_port,uint64_t cid,
  int pkn,int pkn_max_possible,double time,int ip_len,int ip_header_len,int udp_len,int udp_header_len,int quic_len,
  int quic_header_len,int is_chlo,int is_rej,int is_other,int is_ack,int is_nack,int is_connection_close,int version,
  int irtt,char uaid[100],char aead[100],int idle_connection_state) {

  struct Session *aux;
  int hashIndex = hashCode(key);

  double time_max_burst = 1E-3; // tiempo maximo entre un paquete y otro del burst

//printf("time hash %lf",hashArray[hashIndex]->time_first_pkt );

if(hashArray[hashIndex]->time_first_pkt == -1){ // Si el hash esta vacio el elemento es el primero de la lista
    
    aux = hashArray[hashIndex];
   
    analize_time(aux,time,is_connection_close,idle_connection_state,hostname,uaid); // -1 de connection close y idle time

    aux->key = key;
    aux->src_addr[0] = src_addr[0];
    aux->src_addr[1] = src_addr[1];
    aux->src_addr[2] = src_addr[2];
    aux->src_addr[3] = src_addr[3];
    aux->dst_addr[0] = dst_addr[0];
    aux->dst_addr[1] = dst_addr[1];
    aux->dst_addr[2] = dst_addr[2];
    aux->dst_addr[3] = dst_addr[3];
    aux->src_port = src_port;
    aux->dst_port = dst_port;
    aux->cid = cid;
    aux->version = version;
    aux->nextListSession = NULL;

    analize_pkn(aux,pkn,0,pkn_max_possible);

    analize_length(aux,ip_len,ip_header_len,udp_len,udp_header_len,quic_len,quic_header_len,0);

    //printf("First session on the list.\n");

    analize_special_pkt(aux,is_chlo,is_rej,is_other,is_ack,is_nack,time,irtt,aead);
    
    analize_burst(aux, time, time_max_burst,0);

    hashArray[hashIndex] = aux;

    return;

  }

else{ // Si no esta vacio, hay elementos en la lista.

  for(aux = hashArray[hashIndex]; aux->nextListSession != NULL; aux = aux->nextListSession){

    //printf("Entra en el bucle ");
    
    if(aux->src_addr[0] == src_addr[0] && aux->src_addr[1] == src_addr[1] && aux->src_addr[2] == src_addr[2] && aux->src_addr[3] == src_addr[3] && aux->dst_addr[0] == dst_addr[0] && aux->dst_addr[1] == dst_addr[1] && aux->dst_addr[2] == dst_addr[2] && aux->dst_addr[3] == dst_addr[3]){
      analize_time(aux,time,is_connection_close,idle_connection_state,hostname,uaid);
      analize_pkn(aux,pkn,0,pkn_max_possible);
      analize_length(aux,ip_len,ip_header_len,udp_len,udp_header_len,quic_len,quic_header_len,0);
      analize_special_pkt(aux,is_chlo,is_rej,is_other,is_ack,is_nack,time,irtt,aead);
      analize_burst(aux, time, time_max_burst,0);

      return;
    }

    // Misma sesion vuelta
    else if(aux->dst_addr[0] == src_addr[0] && aux->dst_addr[1] == src_addr[1] && aux->dst_addr[2] == src_addr[2] && aux->dst_addr[3] == src_addr[3] && aux->src_addr[0] == dst_addr[0] && aux->src_addr[1] == dst_addr[1] && aux->src_addr[2] == dst_addr[2] && aux->src_addr[3] == dst_addr[3]){
      analize_time(aux,time,is_connection_close,idle_connection_state,hostname,uaid);
      analize_pkn(aux,pkn,1,pkn_max_possible);
      analize_length(aux,ip_len,ip_header_len,udp_len,udp_header_len,quic_len,quic_header_len,1);
      analize_special_pkt(aux,is_chlo,is_rej,is_other,is_ack,is_nack,time,irtt,aead);
      analize_burst(aux, time, time_max_burst,1);

      return;
    }
  }

  // ultimo elemento en lista

  if(aux->src_addr[0] == src_addr[0] && aux->src_addr[1] == src_addr[1] && aux->src_addr[2] == src_addr[2] && aux->src_addr[3] == src_addr[3] && aux->dst_addr[0] == dst_addr[0] && aux->dst_addr[1] == dst_addr[1] && aux->dst_addr[2] == dst_addr[2] && aux->dst_addr[3] == dst_addr[3]){
    analize_time(aux,time,is_connection_close,idle_connection_state,hostname,uaid);
    analize_pkn(aux,pkn,0,pkn_max_possible);
    analize_length(aux,ip_len,ip_header_len,udp_len,udp_header_len,quic_len,quic_header_len,0);
    analize_special_pkt(aux,is_chlo,is_rej,is_other,is_ack,is_nack,time,irtt,aead);
    analize_burst(aux, time, time_max_burst,0);
    
    return;
  }

  else if(aux->dst_addr[0] == src_addr[0] && aux->dst_addr[1] == src_addr[1] && aux->dst_addr[2] == src_addr[2] && aux->dst_addr[3] == src_addr[3] && aux->src_addr[0] == dst_addr[0] && aux->src_addr[1] == dst_addr[1] && aux->src_addr[2] == dst_addr[2] && aux->src_addr[3] == dst_addr[3]){
    analize_time(aux,time,is_connection_close,idle_connection_state,hostname,uaid);
    analize_pkn(aux,pkn,1,pkn_max_possible);
    analize_length(aux,ip_len,ip_header_len,udp_len,udp_header_len,quic_len,quic_header_len,1);    
    analize_special_pkt(aux,is_chlo,is_rej,is_other,is_ack,is_nack,time,irtt,aead);
    analize_burst(aux, time, time_max_burst,1);
    
    return;
  }

  else{
    //printf("Nuevo elemento en la lista ");
    struct Session *aux2 = (struct Session*) malloc(sizeof(struct Session));
    //struct Session *aux2;
    aux2->time_first_pkt = 0; // compruebo que sea un paquete mas "nuevo"
    aux2->time_last_pkt = 0;
    strcpy(aux2->hostname,"NULL");
    strcpy(aux2->uaid,"NULL");
    strcpy(aux2->aead,"NULL");

    analize_time(aux2,time,is_connection_close,idle_connection_state,hostname,uaid);

    aux2->key = key;
    aux2->src_addr[0] = src_addr[0];
    aux2->src_addr[1] = src_addr[1];
    aux2->src_addr[2] = src_addr[2];
    aux2->src_addr[3] = src_addr[3];
    aux2->dst_addr[0] = dst_addr[0];
    aux2->dst_addr[1] = dst_addr[1];
    aux2->dst_addr[2] = dst_addr[2];
    aux2->dst_addr[3] = dst_addr[3];
    aux2->src_port = src_port;
    aux2->dst_port = dst_port;
    aux2->cid = cid;

    aux2->time_first_pkt = -1;
    aux2->time_last_pkt = -1;

    aux2->ctos_pkn_first = 0;
    aux2->ctos_pkn_max = 0;
    aux2->ctos_pkn_total = 0;
    aux2->ctos_void = 0;

    aux2->stoc_pkn_first = 0;
    aux2->stoc_pkn_max = 0;
    aux2->stoc_pkn_total = 0;
    aux2->stoc_void = 0;

    aux2->ctos_ip_len_total = 0;
    aux2->ctos_ip_header_len_total = 0;
   	aux2->ctos_udp_len_total = 0;
    aux2->ctos_udp_header_len_total = 0;
    aux2->ctos_quic_len_total = 0;
    aux2->ctos_quic_header_len_total = 0;

    aux2->stoc_ip_len_total = 0;
    aux2->stoc_ip_header_len_total = 0;
    aux2->stoc_udp_len_total = 0;
    aux2->stoc_udp_header_len_total = 0;
    aux2->stoc_quic_len_total = 0;
    aux2->stoc_quic_header_len_total = 0;

    aux2->time_first_chlo = -1;
    aux2->time_first_rej = -1;
    aux2->time_first_ack = -1;
    aux2->time_first_nack = -1;
   	aux2->count_chlo = 0;
   	aux2->count_rej = 0;
   	aux2->count_ack = 0;
   	aux2->count_nack = 0;

    aux2->irtt = -1;

    aux2->version = version;
   	aux2->nextListSession = NULL;

    analize_pkn(aux2,pkn,0,pkn_max_possible);
    analize_length(aux2,ip_len,ip_header_len,udp_len,udp_header_len,quic_len,quic_header_len,0);
    
    analize_special_pkt(aux2,is_chlo,is_rej,is_other,is_ack,is_nack,time,irtt,aead);
    analize_burst(aux2, time, time_max_burst,0);

    aux->nextListSession = aux2;

    return;
  }
  
  }
}

// Funcion que calcula QoS de una sesion
void qos_measurements(struct Session* sesion){

  double time = sesion->time_last_pkt - sesion->time_first_pkt;

  sesion->total_throughput = (sesion->ctos_ip_len_total + sesion->stoc_ip_len_total)/time;
  sesion->quic_throughput = (sesion->ctos_quic_header_len_total + sesion->stoc_quic_header_len_total)/time;

  sesion->pkt_loss = (double)100*(sesion->ctos_void + sesion->stoc_void)/(sesion->ctos_pkn_total + sesion->stoc_pkn_total);

  if(sesion->time_first_rej != -1 && sesion->time_first_chlo != -1 && sesion->time_first_chlo < sesion->time_first_rej){
    sesion->rtt_calculated = sesion->time_first_rej - sesion->time_first_chlo;
  }
}

// Funcion que analiza los dos primeros burst para calcular rtt
void analize_burst(struct Session* sesion, double time_new_pkt,double time_max_burst,int flag){

  if(sesion->rtt_burst == -1){
    if(flag == 0){
      if(sesion->ctos_time_burst_start == 0){
        sesion->ctos_time_burst_start = time_new_pkt;
        sesion->ctos_time_burst_end_aux = time_new_pkt;

        //printf("Time ctos burst start and end_aux:%lf %lf\n",sesion->ctos_time_burst_start,sesion->ctos_time_burst_end_aux );
      }
      else if(sesion->ctos_time_burst_end_aux + time_max_burst >= time_new_pkt){
        sesion->ctos_time_burst_end_aux = time_new_pkt;

        //printf("New ctos time end_aux %lf\n",sesion->ctos_time_burst_end_aux );
      }
      else if(sesion->ctos_time_burst_end_aux + time_max_burst < time_new_pkt){
        sesion->ctos_time_burst_end = sesion->ctos_time_burst_end_aux;
        //printf("Ctos Time end %lf\n",sesion->ctos_time_burst_end );
      }
    }
    else if(flag == 1){
      if(sesion->stoc_time_burst_start == 0){
        sesion->stoc_time_burst_start = time_new_pkt;
        sesion->stoc_time_burst_end_aux = time_new_pkt;
        //printf("Time stoc burst start and end_aux:%lf %lf\n",sesion->stoc_time_burst_start,sesion->stoc_time_burst_end_aux );
      }
      else if(sesion->stoc_time_burst_end_aux + time_max_burst >= time_new_pkt){
        sesion->stoc_time_burst_end_aux = time_new_pkt;
        //printf("New stoc time end_aux %lf\n",sesion->stoc_time_burst_end_aux );
      }
      else if(sesion->stoc_time_burst_end_aux + time_max_burst < time_new_pkt){
        sesion->stoc_time_burst_end = sesion->stoc_time_burst_end_aux;
        //printf("stoc Time end %lf\n",sesion->stoc_time_burst_end );
      }
    }

    if(sesion->ctos_time_burst_end != 0 && sesion->stoc_time_burst_end != 0){
      sesion->rtt_burst = sesion->stoc_time_burst_end - sesion->ctos_time_burst_end;
      //printf("RTT burst %lf \n",sesion->rtt_burst );
    }
  }
}

// Funcion que carga la informacion de tiempo, tambien hostname y uaid por que suelen aparacer en el primer paquete
void analize_time(struct Session* sesion, double time_new_pkt,int is_connection_close,int idle_connection_state,char hostname[100],char uaid[100]){

  int timeout = 30;

  // 1. comprobar idle state de la sesion
  if(idle_connection_state != -1 && idle_connection_state != 30){
    sesion->idle_connection_state = idle_connection_state;
    timeout = idle_connection_state;
  }

  // 2. comprobar si es el primer paquete de la sesion
  if(sesion->time_first_pkt == -1){
    sesion->time_first_pkt = time_new_pkt;
    sesion->time_last_pkt = time_new_pkt;
    sesion->status = 1; // 1 -> open, 0 -> close
  }
  // 3. comprobar si el ultimo paquete ha llegado despues del timeout
  else if(sesion->time_last_pkt + timeout < time_new_pkt){   // si ha pasado el timeout
    sesion->time_last_pkt = time_new_pkt;
    sesion->time_connection_close = time_new_pkt;
    sesion->status = 0;
    delete_past_sessions(time_new_pkt);
  }
  // 4. comprobar si se ha mandado un connection close
  else if(is_connection_close == 1){
    //printf("Es CC\n");
    sesion->time_last_pkt = time_new_pkt;
    sesion->time_connection_close = time_new_pkt;
    sesion->status = 0;
    delete_past_sessions(time_new_pkt);
  }
  // 5. si no ha ocurrido nada de eso, la sesion sigue activa, se actualiza el last pkt
  else
    sesion->time_last_pkt = time_new_pkt;

  // AÑADIR HOSTNAME
  if(strcmp(sesion->hostname,"NULL") == 0){ // 1. comprobar que el hostname guardado sea NULL

    if(strcmp(hostname,"NULL") != 0){ // 2. comprobar que el nuevo hostname no sea NULL
      strcpy(sesion->hostname,hostname);
      //printf("CAMBIO DE HOSTNAME:%s\n",sesion->hostname );
    }
  }
  //añadir UAID
  if(strcmp(sesion->uaid,"NULL") == 0){ // 1. comprobar que el uaid guardado sea NULL

    if(strcmp(uaid,"NULL") != 0){ // 2. comprobar que el nuevo uaid no sea NULL
      strcpy(sesion->uaid,uaid);
      //printf("CAMBIO DE HOSTNAME:%s\n",sesion->hostname );
    }
  }
}

// Funcion que carga la informacion de los paquetes speciales
void analize_special_pkt(struct Session* sesion,int is_chlo,int is_rej,int is_other,int is_ack,int is_nack,double time,int irtt,char aead[100]){

  if(is_chlo == 1){
      if(sesion->count_chlo == 0){
        sesion->time_first_chlo = time;
        sesion->count_chlo = 1;
      }
      else
        sesion->count_chlo += 1;
    }
    if(is_rej == 1){
      if(sesion->count_rej == 0){
        sesion->time_first_rej = time;
        sesion->count_rej = 1;
      }
      else
        sesion->count_rej += 1;
    }
    if(is_ack == 1){
      if(sesion->count_ack == 0){
        sesion->time_first_ack = time;
        sesion->count_ack = 1;
      }
      else
        sesion->count_ack += 1;
    }
    if(is_nack == 1){
      if(sesion->count_nack == 0){
        sesion->time_first_nack = time;
        sesion->count_nack = 1;
      }
      else
        sesion->count_nack += 1;
    }
    if(irtt != 0){
      sesion->irtt = irtt;
    }
      // AÑADIR HOSTNAME
    if(strcmp(sesion->aead,"NULL") == 0){ // 1. comprobar que el hostname guardado sea NULL

      if(strcmp(aead,"NULL") != 0){ // 2. comprobar que el nuevo hostname no sea NULL
        strcpy(sesion->aead,aead);
      }
    }
    return;

}

// Funcion para analizar y guardar la longitud de datos de sesion
void analize_length(struct Session* sesion,int ip_len,int ip_header_len,int udp_len,int udp_header_len,int quic_len,int quic_header_len,int flag){

if(flag == 0){
  sesion->ctos_ip_len_total += ip_len;
  sesion->ctos_ip_header_len_total += ip_len - ip_header_len;
  sesion->ctos_udp_len_total += udp_len;
  sesion->ctos_udp_header_len_total += udp_len - udp_header_len;
  sesion->ctos_quic_len_total += quic_len;
  sesion->ctos_quic_header_len_total += quic_len - quic_header_len;
}
else if(flag == 1){
  sesion->stoc_ip_len_total += ip_len;
  sesion->stoc_ip_header_len_total += ip_len - ip_header_len;
  sesion->stoc_udp_len_total += udp_len;
  sesion->stoc_udp_header_len_total += udp_len - udp_header_len;
  sesion->stoc_quic_len_total += quic_len;
  sesion->stoc_quic_header_len_total += quic_len - quic_header_len;
}

  return;
}

// Funcion para analizar los pkn de la sesion. Ojo con que al llegar al pkn máximo vuelve a 1
void analize_pkn(struct Session* sesion,int pkn,int flag,int pkn_max_possible){

  // flag determina la direccion: 0 para stoc y 1 para stoc

  if(flag == 0){
    if(sesion->ctos_pkn_first == 0){
      sesion->ctos_pkn_first = pkn;
    }

    int pkn_expected = sesion->ctos_pkn_max + 1;
    if(pkn_expected >= pkn_max_possible){ // 255 -> 0 etc Da la vuelta
      pkn_expected = 0;
    }
    if(pkn_expected == pkn){
      sesion->ctos_pkn_max = pkn;
      sesion->ctos_pkn_total += 1;
    }
    else if(pkn_expected < pkn){
      sesion->ctos_pkn_max = pkn;
      sesion->ctos_pkn_total += 1;
      sesion->ctos_void += 1;
    }
    else if(pkn_expected > pkn){
      sesion->ctos_pkn_total += 1;
    }
  }
  else if(flag == 1){
    if(sesion->stoc_pkn_first == 0){
      sesion->stoc_pkn_first = pkn;
    }

    int pkn_expected = sesion->stoc_pkn_max + 1;
    if(pkn_expected >= pkn_max_possible){ // 255 -> 0 etc Da la vuelta
      pkn_expected = 0;
    }
    if(pkn_expected == pkn){
      sesion->stoc_pkn_max = pkn;
      sesion->stoc_pkn_total += 1;
    }
    else if(pkn_expected < pkn){
      sesion->stoc_pkn_max = pkn;
      sesion->stoc_pkn_total += 1;
      sesion->stoc_void += 1;
    }
    else if(pkn_expected > pkn){
      sesion->stoc_pkn_total += 1;
    }
  }

  return;
}

// Funcion para imprimir todas las sesiones con info
void display_all_sessions_final(){

  struct Session* aux;
  int i = 0;

  for(i = 0; i<SIZE; i++){

  	//printf("hashArray %lf\n",hashArray[i] );
    if(hashArray[i]->time_first_pkt != -1){

      for(aux = hashArray[i]; aux->nextListSession != NULL; aux = aux->nextListSession){
        
        //antes de imprimir se calculan las medidas QoS
        qos_measurements(aux);
        print_session(aux);
        

      }

      //antes de imprimir se calculan las medidas QoS
        qos_measurements(aux);
        print_session(aux);
    }    
  }

  //printf("\n*******************************************\n");
}

// Funcion para imprimir los datos de UNA sesion
void print_session(struct Session* aux){

//printf("Sesion %d - %d:\n", num_hash,num_list);
        //printf(" (%d,",aux->key); // print key
        printf("%d.%d.%d.%d;",aux->src_addr[0],aux->src_addr[1],aux->src_addr[2],aux->src_addr[3]); // print src-addr
        printf("%d.%d.%d.%d;",aux->dst_addr[0],aux->dst_addr[1],aux->dst_addr[2],aux->dst_addr[3]); // print dst-addr
        printf("%d;",aux->src_port); // print src-port
        printf("%d;",aux->dst_port); // print dst-port
        printf("%lf;",aux->time_first_pkt); // print time first pkt
        printf("%lf;",aux->time_last_pkt); // print time last pkt
        printf("%lu;",aux->cid); // print cid

        printf("%s;",aux->hostname );

        printf("%lf;",aux->ctos_ip_len_total );
        printf("%lf;",aux->ctos_ip_header_len_total );
        printf("%lf;",aux->ctos_udp_len_total );
        printf("%lf;",aux->ctos_udp_header_len_total );
        printf("%lf;",aux->ctos_quic_len_total );
        printf("%lf;",aux->ctos_quic_header_len_total );

        printf("%lf;",aux->stoc_ip_len_total );
        printf("%lf;",aux->stoc_ip_header_len_total );
        printf("%lf;",aux->stoc_udp_len_total );
        printf("%lf;",aux->stoc_udp_header_len_total );
        printf("%lf;",aux->stoc_quic_len_total );
        printf("%lf;",aux->stoc_quic_header_len_total );

        printf("%d;",aux->ctos_pkn_first);
        printf("%d;",aux->ctos_pkn_max);
        printf("%d;",aux->ctos_pkn_total);
        printf("%d;",aux->ctos_void);

        printf("%d;",aux->stoc_pkn_first);
        printf("%d;",aux->stoc_pkn_max);
        printf("%d;",aux->stoc_pkn_total);
        printf("%d;",aux->stoc_void);

        printf("%lf;",aux->time_first_chlo );
        printf("%lf;",aux->time_first_rej );
        printf("%lf;",aux->time_first_ack );
        printf("%lf;",aux->time_first_nack );
        printf("%d;",aux->count_chlo );
        printf("%d;",aux->count_rej );
        printf("%d;",aux->count_ack );
        printf("%d;",aux->count_nack );

        //printf("%d;",aux->version );
        if(aux->version == 43)
          printf("Q043;");
        else
          printf("NULL;");
        printf("%lf;",aux->time_connection_close );
        printf("%d;",aux->irtt );
        printf("%lf;",aux->rtt_burst );

        printf("%lf;",aux->total_throughput );
        printf("%lf;",aux->quic_throughput );
        printf("%lf;",aux->pkt_loss );
        printf("%lf;",aux->rtt_calculated );

        printf("%s;",aux->uaid );
        printf("%s",aux->aead );


        printf("\n");

}
