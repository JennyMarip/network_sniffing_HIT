#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include "stdio.h"

#define MAXBYTE2CAPTURE 2048

int Count(int n){
    int i;
    if(n==0)
    {
        i=1;
        i++;
    }
    for(i=0;n!=0;i++)
    {
        n/=10;
    }
    return i;
}

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
//    FILE *fp;
//    char *path= "/usr/lab2/";
//    strcat(path,(char*)arg);
//    strcat(path,".txt");
//    printf("%s\n",path);
    for(int i=0;arg[i]!='\0';i++){
        if(arg[i]==' ')arg[i]='_';
    }
    char *tmp = NULL;
    if ((tmp = strstr(arg, "\n")))
    {
        *tmp = '\0';
    }//对传来的参数的一些调整
    char* dir="/usr/lab2/";
    char*path=(char*)malloc(strlen(dir)+strlen((char*)arg)+4);
    strcpy(path,dir);
    strcat(path,(char*)arg);
    strcat(path,".txt");//对文件路径的拼接操作
    FILE* fp;
    fp=fopen(path,"a");//打开文件
    printf("Received Packet Size: %d\n", pkthdr->len);
//    printf("Payload:\n");
//    for (int i = 0; i < pkthdr->len; i++) {
//        printf("%02x ",(int)packet[i]);
//        fflush(stdout);
//        if ((i % 16 == 0 && i != 0) || i == pkthdr->len - 1)
//            printf("\n");
//    }
    int src[4]={0,0,0,0};
    int desk[4]={0,0,0,0};
    for (int i=0;i<4;i++) {
        src[i] = (int)packet[i + 26];
        desk[i] = (int)packet[i + 30];
    }
    /** 解析源ip地址和目的ip地址 **/
    char src_str[16];
    char desk_str[16];
    memset(src_str,0,16);
    memset(desk_str,0,16);
    int index=0;
    for(int i=0;i<4;i++){
        if(i!=0){
            src_str[index]=  '.';
            index++;
        }
        int bit_len= Count(src[i]);
        int temp=src[i];
        for(int j=index+ bit_len-1;j>=index;j--){
            src_str[j]=temp%10+'0';
            temp/=10;
            if(temp==0)break;
        }
        index+= Count(src[i]);
    }
    src_str[index]='\0';
    index=0;
    for(int i=0;i<4;i++){
        if(i!=0){
            desk_str[index]=  '.';
            index++;
        }
        int bit_len= Count(desk[i]);
        int temp=desk[i];
        for(int j=index+ bit_len-1;j>=index;j--){
            desk_str[j]=temp%10+'0';
            temp/=10;
            if(temp==0)break;
        }
        index+= Count(desk[i]);
    }
    desk_str[index]='\0';
    printf("-------------------------\n");
    printf("源ip地址:%s\n",src_str);
    printf("目的ip地址:%s\n",desk_str);
    /** 解析源端口号和目的端口号 **/
    char src_port[6];
    char des_port[6];
    memset(src_port,0,6);
    memset(des_port,0,6);
    u_short source_port=(int)packet[35]+256*(int)packet[34];
    u_short desk_port=(int)packet[37]+256*(int)packet[36];
    int temp=source_port;
    for(int i= Count(source_port)-1;i>=0;i--){
        src_port[i]=temp%10+'0';
        temp/=10;
        if(temp==0)break;
    }
    src_port[Count(source_port)]='\0';
    temp=desk_port;
    for(int i= Count(desk_port)-1;i>=0;i--){
        des_port[i]=temp%10+'0';
        temp/=10;
        if(temp==0)break;
    }
    des_port[Count(desk_port)]='\0';
    printf("源端口号:%s\n",src_port);
    printf("目的端口号:%s\n",des_port);
    fputs("src ip:",fp);
    fputs(src_str,fp);
    fputs(" desk ip:",fp);
    fputs(desk_str,fp);
    fputs(" src port:",fp);
    fputs(src_port,fp);
    fputs(" desk port:",fp);
    fputs(des_port,fp);
    fputs("\n",fp);
    fclose(fp);
    return;
}

int main(int argc,char*argv[]) {
    int packet_num=0;//每一次的抓包数量
    if(argc==1){
        packet_num=10;//如果不制定,就默认为10
    }else{
        packet_num= atoi(argv[1]);
    }
    printf("开始进行网络嗅探...\n");
    fflush(stdout);
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    /* Get the name of the first device suitable for capture */
    device = pcap_lookupdev(errbuf);
    printf("Opening device %s\n", device);
    fflush(stdout);
    /* Open device in promiscuous mode */
    descr = pcap_open_live(device, MAXBYTE2CAPTURE, 1, 512, errbuf);
    while(1){
        printf("请设置网络数据报过滤条件(过滤条件需要满足BPF过滤语法):\n");
        fflush(stdout);
        char condition[100];
        memset(condition,0,100);
        fgets(condition,100,stdin);
        char *tmp = NULL;
        if ((tmp = strstr(condition, "\n"))){//消除换行符
            *tmp = '\0';
        }
        struct bpf_program filter;
        int a=pcap_compile(descr, &filter, condition, 1, 0);
        if(a==-1){
            printf("无效的过滤条件!\n");
            fflush(stdout);
            continue;
        }
        int b=pcap_setfilter(descr, &filter);//设置过滤条件
        if(b==-1){
            printf("无效的过滤条件!\n");
            fflush(stdout);
            continue;
        }
        /* 获取段前时间戳 */
        time_t cur_time;
        time(&cur_time);
        char* time_str=ctime(&cur_time);
        /* Loop forever & call processPacket() for every received packet */
        pcap_loop(descr, packet_num, processPacket, (u_char *)time_str);
    }
    return 0;
}