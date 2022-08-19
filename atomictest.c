#include <stdio.h>              // printf()
#include <stdlib.h>             // malloc()
#include <unistd.h>             // close()
#include <string.h>             // strcpy, memset(), and memcpy()
#include <pthread.h>            // thread operations
#include <math.h>               // pow()
#include <time.h>               // sweep time measurement
#include <stdatomic.h>          // atomic flags
#include <semaphore.h>          // to pause and resume scan function
#include <fcntl.h>              // O_CREAT

#include <netdb.h>              // struct addrinfo
#include <sys/types.h>          // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>         // needed for socket()
#include <netinet/in.h>         // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h>         // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>          // inet_pton() and inet_ntop()
#include <sys/ioctl.h>          // macro ioctl is defined
#include <bits/ioctls.h>        // defines values for argument "request" of ioctl.
#include <net/if.h>             // struct ifreq
#include <linux/if_ether.h>     // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>    // struct sockaddr_ll (see man 7 packet)
#include <netinet/ip_icmp.h>    // ICMP ping request
#include <errno.h>              // errno, perror()

//* printf with arguements and newline
#define debug(format, ...) printf(format "\n", __VA_ARGS__)

// Define some constants.
#define ETH_HDRLEN      14      // Ethernet header length
#define IP4_HDRLEN      20      // IPv4 header length
#define ARP_HDRLEN      28      // ARP header length
#define ARPOP_REQUEST   1       // Taken from <linux/if_arp.h>
#define ARPOP_REPLY     2       // Taken from <linux/if_arp.h>
#define PING_SIZE       56      // Ping packet length
#define IP_LENGTH       32      // Ping packet length

//* ARP package structure
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

//* Ping packet structure
struct ping_pkt
{
    struct icmphdr hdr;
    char msg[PING_SIZE-sizeof(struct icmphdr)];
};

//* IP scanner structre
//? Arguements required for scanner thread
typedef struct ip_submask
{
    char **ip_adresses;
    int addres_count;
    uint8_t *mask_bits;
    char *src_ip;
}ips_t;


// Function prototypes
char *allocate_strmem (int); //* memory allocation - malloc + memset
uint8_t *allocate_ustrmem (int); //* memory allocation - malloc + memset
unsigned short checksum(void *b, int len); //* req for icmp pack
int send_arp(char *target, char *srcc_ip); //* send arp to dedicated ip
int send_ping_icmp(char *target_ip, struct timeval tv); //* send icmp pack (ping)
int read_file(ips_t *ips); //* read ip and subnet mask from file
int find_ip(char *buff); //* find this device's IP address
int config_user_ip(char *new_ip, char *submask); //* change user ip
char **alloc_string(int item, int maxchar); //* allocate memory for array of strings
uint32_t ips_get_u32(char *ips); //* convert IPv4 string to uint32_t var
int ips_get_string(char *ips, uint32_t ip_u32); //* convert uint32_t var to IPv4 string

//. Threads
void *rcv_arp(void *data);      //* receive arp requests
void *scan_ip(void *data);      //* scan devices

//. arp request recevied, wait for ICMP response
atomic_int is_found = 0;

//. receive IP messages until receive the 
//. ICMP response from ARP reply sender 
atomic_int is_responded = 0;

//. network interface string
char netw_if[24] = {0};

//. semaphore for scanning function
sem_t *sem;

int main(int argc, char *argv[]) {

    //* interface name required as an argument
    if( argc == 2 ) {
        strncpy(netw_if, argv[1], strlen(argv[1]));
    }
    else if( argc > 2 ) {
        printf("Too many arguments supplied.\n");
        exit(EXIT_FAILURE);
    }
    else {
        printf("One argument expected.\n");
        exit(EXIT_FAILURE);
    }

    //. receiver and scanner thread handlers
    pthread_t arp_rec_th, scan_th;
    ips_t ips; //. IP scanner structure
    const char *name = "/myexample"; //. semaphore name
    
    //* scanner will wait this semaphore
    //* if any ARP reply receive
    sem = sem_open(name, O_CREAT, 0600, 0);

    if(sem == SEM_FAILED) {
        debug("sem_create failed: %d", errno);
        exit(EXIT_FAILURE);
    }

    //. allocate memory for ips variables
    ips.ip_adresses = alloc_string(40, 50);
    ips.mask_bits = allocate_ustrmem(40);
    ips.src_ip = allocate_strmem(30);

    //! BU FONKSIYON HATALI
    find_ip(ips.src_ip);
    // strncpy(ips.src_ip, "192.168.5.11", strlen("192.168.5.11"));

    //* read IPv4 addreses in CIDR notation
    int res = read_file(&ips); 
    if(res < 0) {
        printf("Error in ip read\n");
        return 1;
    }
    else {
        ips.addres_count = res;
    }

    //* create required threads 
    pthread_create(&arp_rec_th, NULL, rcv_arp, "HELLLO");
    pthread_create(&scan_th, NULL, scan_ip, (void*)&ips);

    //* scan until ARP reply receives
    sem_post(sem);

    pause();
}

void *scan_ip(void *data) {
    
    ips_t *ips = (ips_t*)(data);

    //* Get uint32 value of source IP address
    uint32_t src_ip_u32 = ips_get_u32(ips->src_ip);

    //* sweep all IP addreses in the struct
    for (int i = 0; i < ips->addres_count; i++)
    {
        uint32_t sweep_ip_u = ips_get_u32(ips->ip_adresses[i]) + 1; //. min ip value
        int sweep_count = pow(2.0, IP_LENGTH - ips->mask_bits[i]) - 2; //* 0-255 discarded
        uint32_t max_sweep_ip = sweep_ip_u + sweep_count; //. max ip value

        //* if IP not in the interval, change IP 
        if(src_ip_u32 < sweep_ip_u || src_ip_u32 >= max_sweep_ip) {
            //! IP CHANGE NEEDED
            printf("src: %u\nmin: %u\nmax: %u\n", src_ip_u32, sweep_ip_u, max_sweep_ip);
            char neww_ip[24]; ips_get_string(neww_ip, max_sweep_ip - 1);
            printf("IP needs to change to: %s\n", neww_ip);
            
            //* if interface is wireless, do not change IP
            if(strstr(netw_if, "wlo1") != NULL) {
                printf("IP change too risky in this network\n");
                printf("Program will be terminated\n");
            }
            else {
                char submask[24];
                //* extract mask var from sweep count
                uint32_t mask_u = (0xffffffff - sweep_count) - 1;
                ips_get_string(submask, mask_u);
                config_user_ip(neww_ip, submask);
                memset(ips->src_ip, 0, 30);
                strncpy(ips->src_ip, neww_ip, strlen(neww_ip));
                src_ip_u32 = ips_get_u32(ips->src_ip);
            }
        }

        char sweep_ip_c[30]; //* arp buffer
        debug("Program will sweep %u IPs", sweep_count);

        //. start timer
        struct timespec begin, end;
        clock_gettime(CLOCK_REALTIME, &begin);
        while(sweep_ip_u < max_sweep_ip)
        {
            //. if ARP reply receive, wait for semaphore
            if(atomic_load(&is_found) == 1) {
                sem_wait((sem_t*)sem);
            }
            //. do not sweep source IP
            if(sweep_ip_u == src_ip_u32) {
                //! NOT SWEEP SOURCE IP
                sweep_ip_u++;
                continue;
            }
            ips_get_string(sweep_ip_c, sweep_ip_u);
            debug("ip swept: %s", sweep_ip_c);
            send_arp(sweep_ip_c, ips->src_ip);
            sweep_ip_u++;
        }
        clock_gettime(CLOCK_REALTIME, &end);
        long seconds = end.tv_sec - begin.tv_sec;
        long nanoseconds = end.tv_nsec - begin.tv_nsec;
        double elapsed = seconds + nanoseconds*1e-9;
        printf("All swept in: %.6f seconds.\n", elapsed);

        //* if any response is received, sweep source ip
        //. change ip and sweep the remaining ip
        if(strstr(netw_if, "wlo1") != NULL) {
            printf("IP change too risky in this network\n");
            printf("Program will be terminated\n");
        }
        else {
            char new_ip[24] = { 0 }, submaskk[24] = { 0 };
            ips_get_string(new_ip, max_sweep_ip - 2); //* olmaz bu        
            //* sweep count = total size of unmasked area - 2
            uint32_t mask_u = 0xffffffff - sweep_count - 1;
            ips_get_string(submaskk, mask_u);
            config_user_ip(new_ip, submaskk);
            send_arp(ips->src_ip, new_ip);
            debug("ip swept: %s", ips->src_ip);
            memset(ips->src_ip, 0, 30);
            strncpy(ips->src_ip, new_ip, strlen(new_ip));
        }
    }
    
}

char **alloc_string(int item, int maxchar) {
    char **string_arr = (char**)malloc(item * sizeof(char*));
    for (int i = 0; i < item + 1; i++)
    {
        string_arr[i] = (char*)malloc(maxchar);
    }
    return string_arr;
}

int read_file(ips_t *ips) {
    FILE *fp;
    fp = fopen("./config.txt", "r+");
    if(fp == NULL) {
        //* if file not exist, create new and exit
        fp = fopen("./config.txt", "w");
        printf("File created. Fill the file and try again\n");
        if(fp == NULL) {
            perror("fopen()");
            return -1;
        }
        fclose(fp);
        return -1;
    }
    else {
        int ctr = 0;
        while(!feof(fp)) {
            fscanf(fp, "%s\n", ips->ip_adresses[ctr]); //* scan one line
            char *ret = strchr(ips->ip_adresses[ctr], '/'); //* find slash
            sscanf(ret + 1, "%d", (int*)&(ips->mask_bits[ctr])); //* find int after slash
            *ret = 0; //* NULL TERMINATE TO HOLD IP
            ctr++;
        }
        if(ctr == 0) {
            printf("File is empty\n");
            return - 1;
        }
        fclose(fp);
        return ctr;
    }
}

// Calculating the checksum
unsigned short checksum(void *b, int len) {    
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;
 
    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int send_ping_icmp(char *target_ip, struct timeval tv) {

    struct ping_pkt pckt;   
    int sockfd, alen;
    struct sockaddr_in con_addr, rec_addr;
    alen = sizeof(con_addr);
    con_addr.sin_family = AF_INET;
    // con_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); //*ping local
    inet_pton(AF_INET, target_ip, &(con_addr.sin_addr));

    //* CHECKSUM PATLATAN BU
    bzero(&pckt, sizeof(pckt));

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0) {
        perror("socket()");
        return 1;
    }


    for (int i = 0; i < sizeof(pckt.msg); i++)
    {
        pckt.msg[i] = i;
    }

    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.id = getpid(); //* echo here
    pckt.hdr.un.echo.sequence = 1;
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error in setsockopt for timeout param of ICMP pack");
    }

    int res = sendto(sockfd, &pckt, sizeof(pckt),
     0, (struct sockaddr*)&con_addr, alen);

    if(res != -1) {
        printf("ICMP sent to the responder: %s\n", target_ip);

        int resrec = recvfrom(sockfd, &pckt, sizeof(pckt),
         0, (struct sockaddr*)&rec_addr, &alen);
        if(resrec != -1) {
            printf("Reply received from\n");
            printf("R:%s:%d\n", inet_ntoa(rec_addr.sin_addr), ntohs(rec_addr.sin_port));
            atomic_store(&is_found, 1);
            atomic_store(&is_responded, 1);
        }
        else {
            printf("Error in receiving\n");
            atomic_store(&is_found, 0);
            sem_post(sem);
            return 3;
        }
    }
    else {
        printf("Error in sending: %d\n", res);
        return 2;
    }
}

void* rcv_arp(void *data) {
 
    while (atomic_load(&is_responded) == 0)
    {
        int i, sd, status;
        uint8_t *ether_frame;
        arp_hdr *arphdr;
        
        // Allocate memory for various arrays.
        ether_frame = allocate_ustrmem (IP_MAXPACKET);
        
        // Submit request for a raw socket descriptor.
        if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
            perror ("socket() failed ");
            exit (EXIT_FAILURE);
        }
        
        // Listen for incoming ethernet frame from socket sd.
        // We expect an ARP ethernet frame of the form:
        //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
        //     + ethernet data (ARP header) (28 bytes)
        // Keep at it until we get an ARP reply.
        arphdr = (arp_hdr *) (ether_frame + 6 + 6 + 2);
        while (((((ether_frame[12]) << 8) + ether_frame[13]) != ETH_P_ARP) || (ntohs (arphdr->opcode) != ARPOP_REPLY)) {
            if ((status = recv (sd, ether_frame, IP_MAXPACKET, 0)) < 0) {
            if (errno == EINTR) {
                memset (ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
                continue;  // Something weird happened, but let's try again.
            } else {
                perror ("recv() failed:");
                exit (EXIT_FAILURE);
            }
            }
        }
        close (sd);
        
        // is_found = 1;
        atomic_store(&is_found, 1);

        // Print out contents of received ethernet frame.
        printf ("\nEthernet frame header:\n");
        printf ("Destination MAC (this node): ");
        for (i=0; i<5; i++) {
            printf ("%02x:", ether_frame[i]);
        }
        printf ("%02x\n", ether_frame[5]);
        printf ("Source MAC: ");
        for (i=0; i<5; i++) {
            printf ("%02x:", ether_frame[i+6]);
        }
        printf ("%02x\n", ether_frame[11]);
        // Next is ethernet type code (ETH_P_ARP for ARP).
        // http://www.iana.org/assignments/ethernet-numbers
        printf ("Ethernet type code (2054 = ARP): %u\n", ((ether_frame[12]) << 8) + ether_frame[13]);
        printf ("\nEthernet data (ARP header):\n");
        printf ("Hardware type (1 = ethernet (10 Mb)): %u\n", ntohs (arphdr->htype));
        printf ("Protocol type (2048 for IPv4 addresses): %u\n", ntohs (arphdr->ptype));
        printf ("Hardware (MAC) address length (bytes): %u\n", arphdr->hlen);
        printf ("Protocol (IPv4) address length (bytes): %u\n", arphdr->plen);
        printf ("Opcode (2 = ARP reply): %u\n", ntohs (arphdr->opcode));
        printf ("Sender hardware (MAC) address: ");
        for (i=0; i<5; i++) {
            printf ("%02x:", arphdr->sender_mac[i]);
        }
        printf ("%02x\n", arphdr->sender_mac[5]);
        char senderipv4[100];
        sprintf(senderipv4, "%u.%u.%u.%u", arphdr->sender_ip[0], arphdr->sender_ip[1], arphdr->sender_ip[2], arphdr->sender_ip[3]);
        printf ("Sender protocol (IPv4) address: %s\n", senderipv4);
        printf ("Target (this node) hardware (MAC) address: ");
        for (i=0; i<5; i++) {
            printf ("%02x:", arphdr->target_mac[i]);
        }
        printf ("%02x\n", arphdr->target_mac[5]);
        printf ("Target (this node) protocol (IPv4) address: %u.%u.%u.%u\n",
            arphdr->target_ip[0], arphdr->target_ip[1], arphdr->target_ip[2], arphdr->target_ip[3]);

        struct timeval tt;
        tt.tv_sec = 5;
        tt.tv_usec = 0;
        send_ping_icmp(senderipv4, tt);

        free (ether_frame);
    }

    exit(EXIT_SUCCESS);    
    
    return 0;
}
  
int send_arp(char *targett, char *srcc_ip) {
    int i, status, frame_length, sd, bytes;
    char *interface, *target, *src_ip;
    arp_hdr arphdr;
    uint8_t *src_mac, *dst_mac, *ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;

    // Allocate memory for various arrays.
    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
    ether_frame = allocate_ustrmem (IP_MAXPACKET);
    interface = allocate_strmem (40);
    target = allocate_strmem (40);
    src_ip = allocate_strmem (INET_ADDRSTRLEN);
    
    // Interface to send packet through.
    strcpy (interface, netw_if);
    
    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }
    
    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("ioctl() failed to get source MAC address ");
        return (EXIT_FAILURE);
    }
    close (sd);
    // Copy source MAC address.
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    //* hardcode
    // sscanf("00:15:5d:81:42:20", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&src_mac[0], &src_mac[1], &src_mac[2],&src_mac[3], &src_mac[4], &src_mac[5] );

    // Report source MAC address to stdout.
    //todo printf ("MAC address for interface %s is ", interface);
    // for (i=0; i<5; i++) {
    //     printf ("%02x:", src_mac[i]);
    // }
    // printf ("%02x\n", src_mac[5]);
    
    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (EXIT_FAILURE);
    }
    //todo printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
    
    //* Set destination MAC address: broadcast address
    memset (dst_mac, 0xff, 6 * sizeof (uint8_t));

    // Read from file
    // Source IPv4 address:  you need to fill this out
    strcpy (src_ip, srcc_ip);
    
    // Read from file
    // Destination URL or IPv4 address (must be a link-local node): you need to fill this out
    strcpy (target, targett);
    
    // Fill out hints for getaddrinfo().
    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
    
    // Source IP address
    if ((status = inet_pton (AF_INET, src_ip, &arphdr.sender_ip)) != 1) {
        fprintf (stderr, "inet_pton() failed for source IP address.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    
    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
        fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
        exit (EXIT_FAILURE);
    }
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    memcpy (&arphdr.target_ip, &ipv4->sin_addr, 4 * sizeof (uint8_t));
    freeaddrinfo (res);
    
    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;
    
    // ARP header
    
    // Hardware type (16 bits): 1 for ethernet
    arphdr.htype = htons (1);
    
    // Protocol type (16 bits): 2048 for IP
    arphdr.ptype = htons (ETH_P_IP);
    
    // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.hlen = 6;
    
    // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.plen = 4;
    
    // OpCode: 1 for ARP request
    arphdr.opcode = htons (ARPOP_REQUEST);
    
    // Sender hardware address (48 bits): MAC address
    memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));
    
    // Sender protocol address (32 bits)
    // See getaddrinfo() resolution of src_ip.
    
    // Target hardware address (48 bits): zero, since we don't know it yet.
    memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));
    
    // Target protocol address (32 bits)
    // See getaddrinfo() resolution of target.
    
    // Fill out ethernet frame header.
    
    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
    frame_length = 6 + 6 + 2 + ARP_HDRLEN;
    
    // Destination and Source MAC addresses
    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));
    
    // Next is ethernet type code (ETH_P_ARP for ARP).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    
    // Next is ethernet frame data (ARP header).
    
    // ARP header
    memcpy (ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof (uint8_t));
    
    // Submit request for a raw socket descriptor.
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }
    

    // Send ethernet frame to socket.
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
        perror ("sendto() failed");
        exit (EXIT_FAILURE);
    }
    
    // Close socket descriptor.
    close (sd);
    
    // Free allocated memory.
    free (src_mac);
    free (dst_mac);
    free (ether_frame);
    free (interface);
    free (target);
    free (src_ip);

    return 0;
}


// Allocate memory for an array of chars.
char *allocate_strmem (int len) {
    void *tmp;
    
    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit (EXIT_FAILURE);
    }
    
    tmp = (char *) malloc (len * sizeof (char));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

int find_ip(char *buff) {
    // unsigned char ip_address[15];
    int fd;
    struct ifreq ifr;

    /*AF_INET - to define network interface IPv4*/
    /*Creating soket for it.*/
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /*AF_INET - to define IPv4 Address type.*/
    ifr.ifr_addr.sa_family = AF_INET;

    /*eth0 - define the ifr_name - port name
    where network attached.*/
    memcpy(ifr.ifr_name, "wlo1", IFNAMSIZ - 1);

    /*Accessing network interface information by
    passing address using ioctl.*/
    ioctl(fd, SIOCGIFADDR, &ifr);
    /*closing fd*/
    close(fd);

    /*Extract IP Address*/
    strcpy(buff, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));

    printf("System IP Address is: %s\n", buff);
    
    return 0;
}

int config_user_ip(char *new_ip, char *submask) {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in inet_addr, subnet_mask;

    bzero(ifr.ifr_name, IFNAMSIZ);
    bzero((char*)&ifr.ifr_addr, IFNAMSIZ);
    bzero((char*)&ifr.ifr_netmask, IFNAMSIZ);

    //todo ismi argdan
    strncpy(ifr.ifr_name, netw_if, strlen(netw_if));

    inet_addr.sin_family = AF_INET;
    inet_pton(AF_INET, new_ip, &(inet_addr.sin_addr));

    subnet_mask.sin_family = AF_INET;
    inet_pton(AF_INET, submask, &(subnet_mask.sin_addr));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        perror("Error in socket()");
        exit(EXIT_FAILURE);
    }

    //* set ip address;
    memcpy(&(ifr.ifr_addr), &inet_addr, sizeof (struct sockaddr));
    if(ioctl(sockfd ,SIOCSIFADDR, &ifr) < 0) {
        perror("Error in ioctl() for IP");
        exit(EXIT_FAILURE);
    }

    //* set submask
    memcpy(&(ifr.ifr_addr), &subnet_mask, sizeof (struct sockaddr));
    if(ioctl(sockfd ,SIOCSIFNETMASK, &ifr) < 0) {
        perror("Error in ioctl() for submask");
        exit(EXIT_FAILURE);
    }

    debug("IP on %s changed to %s", netw_if, new_ip);

    close(sockfd);

    return 0;
}

// Allocate memory for an array of unsigned chars.
uint8_t *allocate_ustrmem (int len) {
    void *tmp;
    
    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit (EXIT_FAILURE);
    }
    
    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}


uint32_t ips_get_u32(char *ips) {
    uint32_t ip_u32;
    int bytes[4];
    sscanf(ips, "%d.%d.%d.%d", &bytes[3], &bytes[2], &bytes[1], &bytes[0]);
    ip_u32 = bytes[3] << 24 |
             bytes[2] << 16 |
             bytes[1] << 8  |
             bytes[0];
    return ip_u32;
}

int ips_get_string(char *ips, uint32_t ip_u32) {
    uint8_t *ptr = (uint8_t*)&ip_u32;
    // debug("result: %d.%d.%d.%d", *(ptr + 3), *(ptr + 2), *(ptr + 1), *ptr);
    sprintf(ips, "%d.%d.%d.%d", *(ptr + 3), *(ptr + 2), *(ptr + 1), *ptr);
    return 0;
}

