/***************************************************************************
 disector.h

 Variables globales y funciones usadas en disectorQUIC.c
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4			/* Tamanio de la direccion IP					*/
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define BREAKLOOP -2
#define NO_FILTER 0
#define NO_LIMIT -1

/* Constantes para QUIC */

#define QUIC_CID 8
#define QUIC_FLAG 1
#define QUIC_VERSION_LEN 4
#define QUIC_NONCE_LEN 32
#define QUIC_MESSAGE_AUTENTICATION_HASH 12
#define QUIC_PKN_SIZE_1 1
#define QUIC_PKN_SIZE_2 2
#define QUIC_PKN_SIZE_4 4
#define QUIC_PKN_SIZE_6 6
#define QUIC_ACK_LEN 6
#define QUIC_ACK_LEN_STOP_WAITING 2
#define QUIC_NACK_LEN 8
#define QUIC_CC_LEN 5

// REJECTION
#define QUIC_TAG_STK 8
#define QUIC_TAG_SNO 8
#define QUIC_TAG_PROF 8
#define QUIC_TAG_SCFG 8
#define QUIC_TAG_AEAD 8
#define QUIC_TAG_SCID 8
#define QUIC_TAG_PDMD 8
#define QUIC_TAG_PUBS 8
#define QUIC_TAG_KEXS 8
#define QUIC_TAG_OBIT 8
#define QUIC_TAG_EXPY 8
#define QUIC_TAG_PREJ 8
#define QUIC_TAG_STTL 8
#define QUIC_TAG_CSCT 8
#define QUIC_TAG_CRT 8

// CHLO
#define QUIC_FRAME_TYPE_LEN 1
#define QUIC_STREAM_ID_LEN 1
#define QUIC_OFFSET_LEN 2
#define QUIC_DATA_LEN 2
#define QUIC_TAG_LEN 4
#define QUIC_TAG_NUMBER_LEN 2
#define QUIC_PADDING_LEN 2
#define QUIC_TAG_PAD 8
#define QUIC_TAG_SNI 8
#define QUIC_TAG_VER 8
#define QUIC_TAG_CSS 8
#define QUIC_TAG_UAID 8
#define QUIC_TAG_TCID 8
#define QUIC_TAG_PDMD 8
#define QUIC_TAG_SMHL 8
#define QUIC_TAG_ICSL 8
#define QUIC_TAG_NONP 8
#define QUIC_TAG_MIDS 8
#define QUIC_TAG_SCLS 8
#define QUIC_TAG_CSCT 8
#define QUIC_TAG_COPT 8
#define QUIC_TAG_IRTT 8
#define QUIC_TAG_CFCW 8
#define QUIC_TAG_SFCW 8

// OFFSET
#define QUIC_TAG_STK 8
#define QUIC_TAG_SNO 8
#define QUIC_TAG_NONC 8
#define QUIC_TAG_AEAD 8
#define QUIC_TAG_SCID 8
#define QUIC_TAG_PUBS 8
#define QUIC_TAG_KEXS 8
#define QUIC_TAG_XLCT 8
#define QUIC_TAG_CCRT 8

void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack);

void handleSignal(int nsignal);

// CODIGO MODIFICADO DE TCPDUMP.ORG

#define ETHER_ADDR_LEN 6
/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		u_char ip_src[IP_ALEN];	/* source and dest address */
		u_char ip_dst[IP_ALEN]; 
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

struct sniff_udp {
		u_short udp_sport;	/* source port */
		u_short udp_dport;  /* destination port */
		u_short udp_length;  /* udp length */
		u_short udp_checksum;  /* checksum */
};

struct sniff_quic { // No es muy util pero ayuda a tener ordenadas las variables globales
	
		u_char quic_flags;
	#define QUIC_VERSION 0x01
	#define QUIC_RESET 0x02
	#define QUIC_NONCE 0x04
	#define QUIC_CONNECTION_ID 0x08
	#define QUIC_PKN_SIZE 0x30
	#define QUIC_MULTIPATH 0x40
	#define QUIC_RESERVED 0x80
	#define QUIC_FLAGS (QUIC_RESERVED|QUIC_MULTIPATH|QUIC_PKN_SIZE|QUIC_CONNECTION_ID|QUIC_NONCE|QUIC_RESET|QUIC_VERSION)
		u_char quic_cid[QUIC_CID]; // No se usa
		u_char quic_pkn;	// No se usa
	#define QUIC_STREAM 0x80
	#define QUIC_ACK 0x40
	#define QUIC_NACK 0x20
	#define QUIC_UNUSED 0x10
	#define QUIC_LARGEST_OBSERVED_LENGTH 0x0C
	#define QUIC_MISSING_PKT 0x03
	
	#define QUIC_SPECIAL_PKT (QUIC_STREAM|QUIC_ACK|QUIC_NACK|QUIC_UNUSED|QUIC_LARGEST_OBSERVED_LENGTH|QUIC_MISSING_PKT)

	#define QUIC_FIN 0x40
	#define QUIC_FLAG_DATA_LEN 0x20
	#define QUIC_OFFSET 0x1C
	#define QUIC_STREAM_LEN 0x03

	#define QUIC_STEAM_SPECIAL_PKT (QUIC_STREAM|QUIC_FIN|QUIC_FLAG_DATA_LEN|QUIC_OFFSET|QUIC_STREAM_LEN)

	};

pcap_t *descr = NULL;
uint64_t contador = 0;

void handleSignal(int nsignal)
{
	(void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

	printf("Control C pulsado\n");
	pcap_breakloop(descr);
}
