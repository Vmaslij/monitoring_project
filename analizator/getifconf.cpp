#include <linux/socket.h>
#include <linux/ioctl.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <csignal>
#include "analizator.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <chrono>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

using namespace std;

ofstream data, f1;
unsigned char* intfc;
__u8 buff[ETH_FRAME_LEN + 4];

struct ifparam {
    __u32 ip;	// IP адрес
    __u32 mask;	// маска подсети
    int mtu;	// размер MTU
    int index;	// индекс интерфейса
} ifp;

Analizator::Analizator()
{
    intfc = new unsigned char[256];
}

Analizator::~Analizator()
{
    delete intfc;
}


int Analizator::getifconf(__u8 *intf, struct ifparam *ifp, int mode)
{
    int fd;
    struct sockaddr_in s;
    struct ifreq ifr;

    memset((void *)&ifr, 0, sizeof(struct ifreq));
    if((fd = socket(AF_INET,SOCK_DGRAM,0)) < 0)	return (-1);

    sprintf(ifr.ifr_name,"%s",intf);

/*
 * Проверяем флаг режима. Если он установлен в 0, неразборчивый режим
 * необходимо отключить, поэтому сразу выполняется переход на метку setmode
 */
    if(!mode) goto setmode;

/*
 * Определяем IP адрес сетевого интерфейса
 */
    int f;
    if((f = ioctl(fd, SIOCGIFADDR, &ifr)) < 0) {
        perror("ioctl SIOCGIFADDR");
        return -1;
    }

    memset((void *)&s, 0, sizeof(struct sockaddr_in));
    memcpy((void *)&s, (void *)&ifr.ifr_addr, sizeof(struct sockaddr));
    memcpy((void *)&ifp->ip, (void *)&s.sin_addr.s_addr, sizeof(__u32));

/*
 * Определяем маску подсети
 */
    if(ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK");
        return -1;
    }

    memset((void *)&s, 0, sizeof(struct sockaddr_in));
    memcpy((void *)&s, (void *)&ifr.ifr_netmask, sizeof(struct sockaddr));
    memcpy((void *)&ifp->mask, (void *)&s.sin_addr.s_addr, sizeof(u_long));


/*
 * Определяем размер MTU
 */
    if(ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
        perror("ioctl SIOCGIFMTU");
        return -1;
    }
    ifp->mtu = ifr.ifr_mtu;

/*
 * Индекс интерфейса
 */
    if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        return -1;
    }
    ifp->index = ifr.ifr_ifindex;


/*
 * Устанавливаем заданный режим работы сетевого интерфейса
 */
    setmode:
/*
 * Получаем значение флагов
 */
    if(ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(fd);
        return -1;
    }

/*
 * В зависимости от значения третьего параметра функции, устанавливаем
 * или снимаем флаг неразборчивого режима
 */
    if(mode) ifr.ifr_flags |= IFF_PROMISC;
    else ifr.ifr_flags &= ~(IFF_PROMISC);


/*
 * Устанавливаем новое значение флагов интерфейса
 */
    if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(fd);
        return (-1);
    }

    return 0;
}

int Analizator::getsock_recv(int index)
{
    int sd; // дескриптор сокета
/*
 * При работе с пакетными сокетами для хранения адресной информации
 * сетевого интерфейса вместо структуры sockaddr_in используется структура
 * sockaddr_ll (см. <linux/if_packet.h>)
 */
    struct sockaddr_ll s_ll;

/*
 * Cоздаем пакетный сокет. Т.к. MAC-адреса мы тоже собираемся обрабатывать,
 * параметр type системного вызова socket принимает значение SOCK_RAW
 */
    sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sd < 0) return -1;

    memset((void *)&s_ll, 0, sizeof(struct sockaddr_ll));

/*
 * Заполним поля адресной структуры s_ll
 */
    s_ll.sll_family = PF_PACKET; // тип сокета
    s_ll.sll_protocol = htons(ETH_P_ALL); // тип принимаемого протокола
    s_ll.sll_ifindex = index; // индекс сетевого интерфейса

/*
 * Привязываем сокет к сетевому интерфейсу. В принципе, делать это не
 * обязательно, если на хосте активен только один сетевой интерфейс.
 * При наличии двух и более сетевых плат пакеты будут приниматься сразу со всех
 * активных интерфейсов, и если нас интересуют пакеты только из одного сегмента
 * сети, целесообразно выполнить привязку сокета к нужному интерфейсу
 */
    if(bind(sd, (struct sockaddr *)&s_ll, sizeof(struct sockaddr_ll)) < 0) {
        close(sd);
        return -1;
    }

    return sd;
}

void Analizator::stop_output(int signum)
{
    data.close();

    cout << intfc;
    cout << "              !!\n";
    cout << ifp.index << " - index, " << ifp.ip << " - ip, " << ifp.mtu << " - mtu, " << ifp.mask << " - mask\n";
    if(getifconf(intfc, &ifp, PROMISC_MODE_OFF) < 0) {
        perror("getifconf");
        exit(-1);
    }
    cout << "!!!\n";

    exit(0);
}

int Analizator::main_cycle(unsigned char* interface)
{
    __u32 num = 0;
    int eth0_if, rec = 0, ihl = 0;
    struct iphdr ip; // структура для хранения IP заголовка пакета
    struct udphdr udp;
    struct tcphdr tcp; // TCP заголовок
    struct icmphdr icmp;
    struct icmp_filter filt;
    struct ethhdr eth; // заголовок Ethernet-кадра
    static struct sigaction act;
    struct in_addr in;
    char mac_adr[256];

    signal(SIGTERM, stop_output);

    intfc = interface;
    cout << interface << "  210 " << intfc << "\n";

/*
 * Получаем параметры сетевого интерфейса eth0 и переводим его
 * в неразборчивый режим
 */
    if(getifconf(intfc, &ifp, PROMISC_MODE_ON) < 0) {
        perror("getifconf");
        return -1;
    }

/*
 * Отобразим полученные параметры сетевого интерфейса
 */
    in.s_addr = ifp.ip;
    data.open("logfile.txt", fstream::out);
    f1.open("tmp.txt");

    if(data.is_open() == 0)
    {
        perror("is_open");
        return 4;
    }
    data << "IP адрес - " << translate_to_ip(ifp.ip) << endl;
    data << "Маска подсети - " << translate_to_ip(ifp.mask) << endl;
    data << "MTU - " << ifp.mtu << endl;
    data << "Индекс - " << ifp.index << endl;

/*
 * Получим дескриптор пакетного сокета
 */
    if((eth0_if = getsock_recv(ifp.index)) < 0) {

        perror("getsock_recv");
        return -1;
    }

/*
 * Определим новый обработчик сигнала SIGINT - функцию mode_off
 */



//    act.sa_handler = mode_off();
//    sigfillset(&(act.sa_mask));
//    sigaction(SIGINT, &act, NULL);

/*
 * Запускаем бесконечный цикл приема пакетов
 */
    auto start = chrono::system_clock::now();
    for(;;) {
        memset(buff, 0, ETH_FRAME_LEN + 4);

        rec = recvfrom(eth0_if, (char *)buff, ifp.mtu + 18, 0, NULL, NULL);

        auto receive_time = chrono::system_clock::now();


        if(rec < 0 || (rec > (ETH_FRAME_LEN + 4))) {
            perror("recvfrom");
            return -1;
        }



        memcpy((void *)&eth, buff, ETH_HLEN);
        memcpy((void *)&ip, buff + ETH_HLEN, sizeof(struct iphdr));
        if((ip.version) != 4) continue;
        memcpy((void *)&tcp, buff + ETH_HLEN + ip.ihl * 4, sizeof(struct tcphdr));
        memcpy((void *)&udp, buff + ETH_HLEN + ip.ihl * 4, sizeof(struct udphdr));
        memcpy((void *)&icmp, buff + ETH_HLEN + ip.ihl * 4, sizeof(struct icmphdr));
/*
 * MAC-адреса отправителя и получателя
 */
        sprintf(mac_adr, "\n%u\n", num++);
        data << mac_adr;

        data << chrono::duration_cast<chrono::milliseconds>(receive_time-start).count() << endl;

        sprintf(mac_adr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x -> ",
               eth.h_source[0],eth.h_source[1],eth.h_source[2],
               eth.h_source[3],eth.h_source[4],eth.h_source[5]);
        data << mac_adr;

        sprintf(mac_adr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
               eth.h_dest[0],eth.h_dest[1],eth.h_dest[2],
               eth.h_dest[3],eth.h_dest[4],eth.h_dest[5]);
        data << mac_adr;

        data << "Длина заголовка - " << (ip.ihl * 4) << ",";
        data << "длина пакета - " << ntohs(ip.tot_len) << endl;

        if(ip.protocol == IPPROTO_UDP) {
            unsigned int src_port = ntohs(udp.source);
            unsigned int dst_port = ntohs(udp.dest);

            data << src_port << " " << translate_to_ip(ip.saddr) << " -> ";
            data << dst_port << " " << translate_to_ip(ip.daddr) << endl;

            if ((src_port == 53 || dst_port == 53) || (src_port == 5353 || dst_port == 5353))
                data << "DNS" << endl;
            else if (src_port == 22 || dst_port == 22)
                data << "SSH" << endl;
            else if ((src_port == 67 || dst_port == 67) || (src_port == 68 || dst_port == 68))
                data << "DHCP" << endl;
            else if (src_port == 143 || dst_port == 143)
                data << "IMAP4" << endl;
            else if ((src_port == 161 || dst_port == 161) || (src_port == 162 || dst_port == 162))
                data << "SNMP" << endl;
            else if (src_port == 443 || dst_port == 443)
                data << "HTTPS" << endl;
            else
                data << "UDP" << endl;
        }

        if(ip.protocol == IPPROTO_ICMP) {
            data << ntohs(icmp.type) << " " << translate_to_ip(ip.saddr) << " -> ";
            data << ntohs(icmp.code) << " " << translate_to_ip(ip.daddr) << endl;
            f1 << ntohs(filt.data) << endl;
            data << "ICMP" << endl;
        }
/*
 * Если транспортный протокол - TCP, отобразим IP адреса и порты
 * получателя и отправителя
 */
        if(ip.protocol == IPPROTO_TCP) {
            unsigned int src_port = ntohs(tcp.source);
            unsigned int dst_port = ntohs(tcp.dest);

            data << src_port << " " << translate_to_ip(ip.saddr) << " -> ";
            data << dst_port << " " << translate_to_ip(ip.daddr) << endl;

            if ((src_port == 53 || dst_port == 53) || (src_port == 5353 || dst_port == 5353))
                data << "DNS" << endl;
            else if (src_port == 80 || dst_port == 80)
                data << "HTTP" << endl;
            else if (src_port == 443 || dst_port == 443)
                data << "HTTPS" << endl;
            else if (src_port == 25 || dst_port == 25)
                data << "SMTP" << endl;
            else if ((src_port == 109 || dst_port == 109) || (src_port == 110 || dst_port == 110))
                data << "POP" << endl;
            else if ((src_port == 161 || dst_port == 161) || (src_port == 162 || dst_port == 162))
                data << "SNMP" << endl;
            else if (src_port == 23 || dst_port == 23)
                data << "Telnet" << endl;
            else if ((src_port == 20 || dst_port == 20) || (src_port == 21 || dst_port == 21))
                data << "FTP" << endl;
            else if (src_port == 22 || dst_port == 22)
                data << "Telnet" << endl;
            else
                data << "TCP" << endl;
        }
    }

    data.close();
    f1.close();

    return 0;
}

char *Analizator::translate_to_ip(__u32 ip_or_mask) {
    short Ip1,Ip2,Ip3,Ip4;
    static char IPAddr[256];

    Ip1=(short)( ip_or_mask>>24 ) & 0xff;
    Ip2=(short)( ip_or_mask>>16 ) & 0xff;
    Ip3=(short)( ip_or_mask>>8 ) & 0xff;
    Ip4=(short)( ip_or_mask&0xff );

    sprintf(IPAddr, "%i.%i.%i.%i", Ip4, Ip3, Ip2, Ip1);

    return IPAddr;
}
