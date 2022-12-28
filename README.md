# Computer Network Protocols From Scratch

This project implements the application layer, data link layer, network layer and physical layer protocols of computer networks from scratch, and simulates the physical layer with the help of sockets, and finally implements two applications that can send messages to each other.

## Application Layer

The application layer of the protocol is a chat application

## Network Layer

The network layer encapsulates information from the application layer in packets and passes them to the data link layer, while this network layer protocol implements fragmentation

```C
for (send_index = 0; send_index < datagram_len; send_index += MTU) {
            char datagram_fragment[MTU + 1];
            if (send_index + MTU >= datagram_len) {
                substr(datagram_fragment, datagram, send_index, datagram_len - send_index);
                X_DF_MF_FragmentOffset = setDF(0, X_DF_MF_FragmentOffset);
                X_DF_MF_FragmentOffset = setMF(0, X_DF_MF_FragmentOffset);
                setOffset(send_index, &X_DF_MF_FragmentOffset);
                TotalLength = strlen(datagram_fragment) + ihl * 4;
                connectVersionAndIHL(&Version_IHL, &version, &ihl);
                generateDifferentiatedServices(&DifferentiatedServices, 4, 0, 1, 0);
                packeting(Packet, &Version_IHL, &DifferentiatedServices, &TotalLength, &Identification,
                          &X_DF_MF_FragmentOffset, &TimeToLive, &Protocol, &HeaderChecksum, &SourceAddress,
                          &DestinationAddress, datagram_fragment, strlen(datagram_fragment));
                calculateChecksum(Packet);
            } else {
                substr(datagram_fragment, datagram, send_index, MTU);
                X_DF_MF_FragmentOffset = setDF(0, X_DF_MF_FragmentOffset);
                X_DF_MF_FragmentOffset = setMF(1, X_DF_MF_FragmentOffset);
                setOffset(send_index, &X_DF_MF_FragmentOffset);
                TotalLength = strlen(datagram_fragment) + ihl * 4;
                connectVersionAndIHL(&Version_IHL, &version, &ihl);
                generateDifferentiatedServices(&DifferentiatedServices, 4, 0, 1, 0);
                packeting(Packet, &Version_IHL, &DifferentiatedServices, &TotalLength,
                          &Identification, &X_DF_MF_FragmentOffset, &TimeToLive, &Protocol, &HeaderChecksum,
                          &SourceAddress, &DestinationAddress, datagram_fragment, strlen(datagram_fragment));
                calculateChecksum(Packet);
            }
```

This code is implementing the fragmentation of a datagram (a single message in a communication protocol) into smaller packets (also known as fragments) that can be transmitted over a network.

The loop iterates over the datagram, breaking it up into fragments of size `MTU` (Maximum Transmission Unit) and sending each fragment in turn. The `send_index` variable keeps track of the current position in the datagram.

The loop first checks if the current fragment is the last one by comparing `send_index + MTU` to the total length of the datagram. If it is the last fragment, it calls the `substr` function to extract the fragment from the datagram, sets the "More Fragments" (MF) and "Don't Fragment" (DF) flags in the "Fragment Offset" field of the packet header to 0, and sets the offset value to the current position in the datagram. It then sets the total length field in the packet header to the length of the fragment plus the Internet Header Length (IHL) field, and calls several other functions to fill in the rest of the packet header. Finally, it calls the `packeting` function to create the packet, and the `calculateChecksum` function to calculate and set the checksum for the packet.

If the current fragment is not the last one, the code follows a similar process, but sets the MF flag to 1 and the DF flag to 0 in the "Fragment Offset" field. This indicates to the receiver that there are more fragments to come and that the original datagram should not be reassembled until all fragments have been received.

## Data Link Layer

The data link layer is primarily a framing operation, encapsulating the packets from the network layer into frames and passing them to the "physical layer"

```c
// framing
unsigned short framing(unsigned char*dst,unsigned char* src,unsigned short type,char*payload,unsigned int payload_len,unsigned char *frame){
    memcpy(frame,dst,6);
    memcpy(frame+6,src,6);
    memcpy(frame+12,&type,sizeof(type));
    memcpy(frame+14,payload,payload_len);
    unsigned int crc_code = crc32(frame,14 + payload_len);
    memcpy(frame+14+payload_len,&crc_code,sizeof(crc_code));
    return 18 + payload_len;
}
```

The framing function appears to be used to create a frame for a message in a communications protocol. It takes in several arguments:

`dst` is a pointer to an unsigned char array that represents the destination address of the frame. It is copied into the frame at the beginning.
`src` is a pointer to an unsigned char array that represents the source address of the frame. It is copied into the frame after the destination address.
`type` is an unsigned short integer that represents the type of the frame. It is copied into the frame after the source address.
`payload` is a pointer to a char array that represents the payload of the frame. It is copied into the frame after the type field.
`payload_len` is an unsigned integer that represents the length of the payload. It is used to determine how much of the payload to copy into the frame.
`frame` is a pointer to an unsigned char array that will hold the complete frame.

The function first copies the destination, source, and type fields into the frame using memcpy. Then it copies payload_len bytes of the payload into the frame using memcpy.

Next, the function calculates a 32-bit Cyclic Redundancy Check (CRC) value for the frame using the crc32 function and stores it in the crc_code variable. The CRC is a checksum that can be used to detect errors in the frame.

Finally, the function copies the crc_code value into the frame using memcpy, and returns the length of the complete frame (which is 18 bytes for the fixed-length fields plus payload_len bytes for the payload).

## "Physical" Layer

The physical layer protocol uses sockets to emulate this, passing the frame to another application

```c
 if(WSAStartup(socketVersion, &wsaData) != 0)
    {
        return 0;
    }
    SOCKET sclient = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8888);
    sin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
```

The `WSAStartup` function initializes the Winsock library, which provides support for network programming in Windows. It takes as arguments the version of the Winsock specification that the program was designed for and a pointer to a `WSADATA` structure, which will be filled in with details about the specific Winsock implementation being used. If the function returns 0, it indicates that the initialization was successful.

The `socket` function creates a socket and returns a socket descriptor that can be used to identify the socket in subsequent function calls. It takes three arguments:

- `AF_INET` specifies that the socket is an IPv4 socket.
- `SOCK_DGRAM` specifies that the socket is a datagram socket, which is used for connectionless, unreliable communication.
- `IPPROTO_UDP` specifies that the socket should use the UDP protocol.

The `sockaddr_in` structure is used to store the address of the server that the socket will be connected to. It has several fields, including:

- `sin_family` specifies the address family, which should be set to `AF_INET` for an IPv4 address.
- `sin_port` specifies the port number that the server is listening on. It is stored in network byte order (i.e., big-endian), so the `htons` function is used to convert it from host byte order (which is typically little-endian on x86 architectures).
- `sin_addr` is a structure that contains the IP address of the server. The `inet_addr` function is used to convert the IP address from its string representation to a numerical representation that can be stored in the `sin_addr` field.

Finally, the `sin` structure is filled in with the values specified above and can be used to connect the socket to the server using the `connect` function or to send data to the server using the `sendto` function.

## Result

![result](https://raw.githubusercontent.com/FionaChan01/Computer-Network-Protocols-from-Scratch/main/image-20201210212641861.png)