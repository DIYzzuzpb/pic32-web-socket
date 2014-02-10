/**
 * HTTP WebSocket Implemenation for PIC32 TCP/IP Stack
 * This document partially implements the RFC6455
 * Author: Dmitriy Kuptsov
 * Email: dmitriy.kuptsov _(at)_ gmail.com
 * License: GNU/GPL 
 * THIS HEADER MUST BE PRESERVED 
 */

#ifndef __WEBSOCKET_API
#define __WEBSOCKET_API

#include "../include/TCPIPConfig.h"
#include "../include/TCPIP Stack/TCPIP.h"

#define WEB_SOCKET_COUNT (1u)

typedef BYTE WSOCKET;   //Socket descriptor

#define SOCKET_ERROR            (-1) //Socket error
#define SOCKET_CNXN_IN_PROGRESS (-2) //Socket connection state.
#define SOCKET_HS_DO            (-3) //Web socket handshake do in prgress.
#define SOCKET_HS_DONE          (-4) //Web scoket handshake done in progress.
#define SOCKET_HS_OPTIONS_DONE  (-5) //Web scoket handshake done in progress.
#define SOCKET_DISCONNECTED     (-6) //Socket disconnected

#define SOCKET_RECV_HEADER      (0)
#define SOCKET_RECV_HEADER_EXT  (1)
#define SOCKET_RECV_MASK        (2)
#define SOCKET_RECV_DATA        (3)

#define SOCKET_DATA_FRAME       (0)
#define SOCKET_PING_FRAME       (1)
#define SOCKET_PONG_FRAME       (2)


typedef enum
{
    SKT_CLOSED,   			// Socket closed state indicating a free descriptor
    SKT_CREATED, 			// Socket created state for TCP but the handshake was not completed
    SKT_TCP_PROGRESS,  		// TCP connection in progress state
	SKT_HANDSHAKE_DO,       // Web socket handshake do in progress
	SKT_HANDSHAKE_DONE,     // Web socket handshake done in progress
	SKT_HANDSHAKE_OPT_DONE, // Web socket handshake done in progress
    SKT_EST,  				// Web socket connection established and ready for use
    SKT_DISCONNECTED		// Web socket connection was closed
} WEB_SCK_STATE; // Web Socket states


struct WebSocket
{
    WEB_SCK_STATE  webSktState;   //Socket state
	WORD		   timer;         //timer
    TCP_SOCKET     SocketID;      // Socket ID
	DWORD	       mask;          //32 bit masking key
	DWORD		   secKey;	      //64 bit random key
	BYTE		   recvState;     //receive state
	DWORD          recvLen;       //data to be received
	DWORD          recvMask;      //received mask
	BOOL 	 	   isMaskSet;     //was there a mask bit set for current frame
	BYTE	       recvFrameType; //frame type awaiting in the buffer
}; // Web Socket structure

struct _WebSocketInfo 
{
	char * hostName;
	WORD   port;
	char * uri;
	BOOL   useSSL;
	BOOL   useMasking;
	BOOL   isHostIPAddress;
};

typedef struct _WebSocketInfo WebSocketInfo;


void WebSocketInit(void);
WSOCKET ws_socket( void );
int ws_connect( WSOCKET s, WebSocketInfo * info );
int ws_send( WSOCKET s, const char* buf, int len );
int ws_recv( WSOCKET s, char* buf, int len );
int ws_ping( WSOCKET s );
int ws_pong( WSOCKET s );
int ws_closesocket( WSOCKET s );

#endif //__WEBSOCKET_API