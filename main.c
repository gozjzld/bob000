#include <pcap.h>
#include <stdio.h>

     int main(int argc, char *argv[])
     {
        int ip_v[5];
        int j=0;
        pcap_t *handle;         /* Session handle */
        char *dev;          /* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
        struct bpf_program fp;      /* The compiled filter */
        // char filter_exp[] = "port 80";   /* The filter expression */
        char filter_exp[] = "port 80";  /* The filter expression */
        bpf_u_int32 mask;       /* Our netmask */
        bpf_u_int32 net;        /* Our IP */
        struct pcap_pkthdr *header; /* The header that pcap gives us */
        const u_char *packet;       /* The actual packet */

        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }
        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
        /* Compile and apply the filter */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        /* Grab a packet */
        //packet = pcap_next(handle, &header);
        //int is_success = pcap_next_ex(handle, &header, &packet);
        while(pcap_next_ex(handle, &header, &packet)) {
            /* Print its length */
            printf("Jacked a packet with length of [%d]\n", header->len);
            printf("Destination Mac : ");
            for (int i=0; i < 6 ; i++) {
                printf("%02x ", packet[i]);
            }
            printf("\nSource Mac : ");
            for (int i=6; i <12 ; i++){
                printf("%02x ", packet[i]);
            }

            printf("\nIP version is : ");

            if(packet[12] == 0x08){
                   printf("v4\n");
            }
            else
                printf("v6\n");             // Ethernet Header

            printf("Source IP : ");
            for (int i=26; i<30; i++){
                printf("%d ", packet[i]);
            }
            printf("\nDestination IP : ");
            for (int i=30; i<34; i++){
                printf("%d ", packet[i]);
            }
            printf("\nProtocol : %02x", packet[23]);
            if (packet[23]==0x06)
                printf("\n TCP Protocol");
            else
                printf("\n UDP Protocol");
            //if protocol==06 is tcp
            //if protocol==17 is udp        // IP Header

            printf("\nSource port : ");
            for (int i=34; i<36; i++){
                printf("%d", packet[i]);
            }
            printf("\nDestination port : ");
            for (int i=36; i<38; i++){
                printf("%d", packet[i]);    // TCP/UDP header?
            }
            printf("\n");
            for (int i=54; i < header->len; i++){
                printf("%c", packet[i]);    // data stream
            }
            printf("\n\n\n\n");
            /*
            printf("\n@@ Data @@\n");
            for (int i=54; header->len ; i++){
                printf("02x", packet[i]);
            }
            */
        }
        /* And close the session */
        pcap_close(handle);
        return(0);
     }
