#include <stdio.h>
#include <winsock2.h>
#include "stdint.h"

#define MTU 5
#pragma comment(lib, "ws2_32.lib")


// receiver‘s mac address
unsigned char mac_address[6] = {0x13, 0x34, 0x56, 0x78, 0x9a, 0xbc};

// Code table, which is used by CRC32 algorithm to generate FCS
static const uint32_t crc32tab[] = {
        0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
        0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
        0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
        0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
        0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
        0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
        0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
        0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
        0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
        0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
        0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
        0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
        0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
        0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
        0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
        0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
        0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
        0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
        0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
        0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
        0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
        0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
        0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
        0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
        0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
        0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
        0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
        0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
        0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
        0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
        0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
        0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
        0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
        0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
        0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
        0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
        0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
        0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
        0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
        0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
        0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
        0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
        0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
        0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
        0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
        0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
        0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
        0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
        0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
        0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
        0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
        0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
        0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
        0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
        0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
        0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
        0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
        0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
        0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
        0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
        0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
        0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
        0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
        0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};


// CRC32 algorithm is used to generate FCS
uint32_t crc32(const unsigned char *buf, uint32_t size) {
    uint32_t i, crc;
    crc = 0xFFFFFFFF;
    for (i = 0; i < size; i++)
        crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

unsigned short getMF(unsigned short X_DF_MF_FragmentOffset) {
    unsigned short MF = X_DF_MF_FragmentOffset & 0x2000;
    MF = MF >> 13;
    return MF;
}

unsigned short getDF(unsigned short X_DF_MF_FragmentOffset) {
    unsigned short DF = X_DF_MF_FragmentOffset & 0x4000;
    DF = DF >> 14;
    return DF;
}

unsigned short getOffset(unsigned short X_DF_MF_FragmentOffset) {
    unsigned short Offset = X_DF_MF_FragmentOffset & 0x1FFF;
    return Offset;

}

void Connect(char dst[], char src[], unsigned short offset) {
    int j = 0;
    for (int i = offset; i < offset + strlen(src); ++i) {
        dst[i] = src[j++];
    }
    dst[offset + strlen(src)] = '\0';
}

unsigned int ReceiverAddress = 5678;


int getVersion(unsigned char *version_IHL) {
    return (int) (*version_IHL >> 4);
}

int getIHL(unsigned char *version_IHL) {
    return (int) (*version_IHL & 0x0F);
}

int getPriority(unsigned char DifferentiatedServices) {
    return (int) (DifferentiatedServices >> 5);
}

int getDelay(unsigned char DifferentiatedServices) {
    return (int) ((DifferentiatedServices & 0x1F) >> 4);
}

int getThroughput(unsigned char DifferentiatedServices) {
    return (int) ((DifferentiatedServices & 0x0F) >> 3);
}

int getReliability(unsigned char DifferentiatedServices) {
    return (int) ((DifferentiatedServices & 0x07) >> 2);
}

unsigned char *Packet;
unsigned char Version_IHL;
int Version, IHL;
unsigned char DifferentiatedServices;
int priority, delay, throughput, reliability;
unsigned short TotalLength;
unsigned short Identification, X_DF_MF_FragmentOffset;
unsigned char TimeToLive;
unsigned char Protocol;
short HeaderChecksum;
unsigned int SourceAddress;
unsigned int DestinationAddress;
unsigned char datagram[65516];


unsigned short calculateChecksum(const char *packet) {
    int i;
    unsigned short section;
    int headerChecksum = 0;
    for (i = 0; i < 10; i++) {
        if (i != 5) {
            memcpy(&section, packet + i * 2, 2);
            headerChecksum += section;
        }
    }
    return headerChecksum;
}


int main(int argc, char *argv[]) {
    WSADATA wsaData;
    WORD sockVersion = MAKEWORD(2, 2);
    if (WSAStartup(sockVersion, &wsaData) != 0) {
        return 0;
    }

    SOCKET serSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (serSocket == INVALID_SOCKET) {
        printf("socket error !");
        return 0;
    }

    struct sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(8888);
    serAddr.sin_addr.S_un.S_addr = INADDR_ANY;
    if (bind(serSocket, (struct sockaddr *) &serAddr, sizeof(serAddr)) == SOCKET_ERROR) {
        printf("bind error !");
        closesocket(serSocket);
        return 0;
    }

    struct sockaddr_in remoteAddr;
    int nAddrLen = sizeof(remoteAddr);
    int frame_right;
    int packet_right;
    char *sendData = "";
    unsigned short identification_last = 0;
    while (1) {
        frame_right = 1;
        packet_right = 0;
        unsigned char frame[255];
        while (1) {
            int ret = recvfrom(serSocket, frame, 255, 0,
                    (struct sockaddr *) &remoteAddr, &nAddrLen);
            if (ret > 0) {
                frame[ret] = 0x00;
                unsigned short len = strlen(frame);
                // printf("%s\n",frame);
                for (int i = 0; i < len; ++i) {
                    frame[i] -= 2;
                }
                unsigned int crc_code_test = crc32(frame, len - 4);
                unsigned char crc_code_test_binary[4];
                memcpy(&crc_code_test_binary, &crc_code_test, sizeof(crc_code_test));

                unsigned char crc_code_binary[4];
                crc_code_binary[3] = frame[len - 1];
                crc_code_binary[2] = frame[len - 2];
                crc_code_binary[1] = frame[len - 3];
                crc_code_binary[0] = frame[len - 4];

                unsigned int crc_code;
                memcpy(&crc_code, crc_code_binary, sizeof(crc_code_binary));


                unsigned char dst_mac_address[6];
                unsigned char src_mac_address[6];
                unsigned short type;
                memcpy(dst_mac_address, frame, 6);
                memcpy(src_mac_address, frame + 6, 6);
                memcpy(&type, frame + 12, 2);
                Packet = frame + 14;
                unsigned short TotalLength;
                memcpy(&TotalLength, Packet + 2, 2);
                Packet[TotalLength] = '\0';
                if (crc_code != crc_code_test) {
                    sendData = "Frame is damaged, please resend.";
                    frame_right = 0;
                    break;
                }
                int flag = 1;
                for (int i = 0; i < 6; i++)
                    if (dst_mac_address[i] != mac_address[i]) {
                        flag = 0;
                        break;
                    }
                if (!flag) {
                    sendData = "This is not a frame sent to the receiver,so dropped.";
                    frame_right = 0;
                    break;
                }
                if (/*TotalLength < 46 || */TotalLength > 1500) {
                    sendData = "Illegal data length.";
                    frame_right = 0;
                }


                char datagram_fragment[MTU + 1];
                if (frame_right) {
                    packet_right = 1;
                    memcpy(&Version_IHL, Packet, 1);
                    Version = getVersion(&Version_IHL);
                    IHL = getVersion(&Version_IHL);
                    memcpy(&DifferentiatedServices, Packet + 1, 1);
                    priority = getPriority(DifferentiatedServices);
                    delay = getDelay(DifferentiatedServices);
                    throughput = getThroughput(DifferentiatedServices);
                    reliability = getReliability(DifferentiatedServices);
                    memcpy(&Identification, Packet + 4, 2);
                    memcpy(&X_DF_MF_FragmentOffset, Packet + 6, 2);
                    memcpy(&TimeToLive, Packet + 8, 1);
                    memcpy(&Protocol, Packet + 9, 1);
                    memcpy(&HeaderChecksum, Packet + 10, 2);
                    memcpy(&SourceAddress, Packet + 12, 4);
                    memcpy(&DestinationAddress, Packet + 16, 4);
                    memcpy(datagram_fragment, Packet + 20, TotalLength - IHL * 4);
                    if (TimeToLive == 0) {
                        sendData = "The packet is out of age.";
                        packet_right = 0;
                        break;
                    }
                    if (HeaderChecksum + calculateChecksum(Packet) != 0xFFFF) {
                        sendData = "This packet is damaged, so dropped.";
                        packet_right = 0;
                        break;
                    }

                    if (DestinationAddress != ReceiverAddress) {
                        sendData = "This packet is not mine, so forwarding.";
                        packet_right = 0;
                        break;
                    }
                    if (Identification == identification_last) {
                        Connect(datagram, datagram_fragment,
                                getOffset(X_DF_MF_FragmentOffset));
                    }
                    identification_last = Identification;
                    if (!getMF(X_DF_MF_FragmentOffset)) {
                        identification_last += 1;
                        break;
                    }
                }
            }
        }
        if (packet_right) {
            printf("app1:\n");
            printf("%s\n", datagram);
        }
        if (packet_right) {
            printf("It's your turn to talk:\n");
            scanf("%s", sendData);
        }
        sendto(serSocket, sendData, strlen(sendData), 0, (struct sockaddr *) &remoteAddr, nAddrLen);
        // For code introduction, the application layer only reflects the protocol level
        // at receiving time, so socket is directly used for sending
    }
    closesocket(serSocket);
    WSACleanup();
    return 0;
}