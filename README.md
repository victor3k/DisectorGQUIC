# DisectorGQUIC
Disector de protocolo QUIC para TFG
Compilar usando:
gcc -o disector disectorQUIC.c -lpcap -O3

Ejecutar usando:
./disector -f -e -v

> Display ayuda:
./disector -h

> Usando fichero Pcap:
./disector -f GQUIC.pcap

> Usando captura de red (se requerirán permisos de administrador):
./disector -i eth0

> Usando filtros pcap:
./disector -f traza.pcap -e "udp"

> Cambiar puerto QUIC o número de paquetes necesarios para lanzar rutina de borrado de sesiones caducadas. 
Los valores predeterminados son 443 y 10000 respectivamente.
Hay que usar previamente el filtro.
./disector -f traza.pcap -e "udp" -v 444 10001
