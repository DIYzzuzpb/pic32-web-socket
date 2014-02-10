/**
 * HTTP WebSocket Implemenation for PIC32
 * This document partially implements the RFC6455
 * Author: Dmitriy Kuptsov 
 * Email: dmitriy.kuptsov _(at)_ gmail.com 
 * License: GNU/GPL 
 * THIS HEADER MUST BE PRESERVED 
 */


#include "../include/WebSocket.h"

static BOOL HandlePossibleTCPDisconnection(WSOCKET s);

static struct WebSocket  WebSocketArray[WEB_SOCKET_COUNT];

void WebSocketInit(void)
{
	unsigned int s;
	struct WebSocket *socket;

	for ( s = 0; s < WEB_SOCKET_COUNT; s++ )
	{
		socket                = (struct WebSocket *)&WebSocketArray[s];
		socket->webSktState   = SKT_CLOSED;
	}
}


WSOCKET ws_socket( void )
{
	struct WebSocket *socket = WebSocketArray;
	WSOCKET s;

	for( s = 0; s < WEB_SOCKET_COUNT; s++,socket++ )
	{
		if( socket->webSktState != SKT_CLOSED ) //socket in use
			continue;
		socket->webSktState = SKT_CREATED;	
		socket->mask        = 0x0;
		socket->recvState   = SOCKET_RECV_HEADER;
		return s;
	}

	return INVALID_SOCKET;
}

int ws_connect( WSOCKET s, WebSocketInfo * info ) {
	struct WebSocket *  socket;
	DWORD               rLen;
	BYTE				buf[125];

	if( s >= WEB_SOCKET_COUNT )
		return SOCKET_ERROR;

	socket = &WebSocketArray[s];

	switch(socket->webSktState)
		{
		case SKT_CREATED:
			if (info->isHostIPAddress) {
				IP_ADDR remoteIP;
				StringToIPAddress(info->hostName, &remoteIP);
				socket->SocketID = TCPOpen(remoteIP.Val, TCP_OPEN_IP_ADDRESS, 
											info->port, TCP_PURPOSE_GENERIC_TCP_CLIENT);
			} else {
				socket->SocketID = TCPOpen((DWORD)info->hostName, TCP_OPEN_RAM_HOST, 
											info->port, TCP_PURPOSE_GENERIC_TCP_CLIENT);
			}
			if(socket->SocketID == INVALID_SOCKET)
				return SOCKET_ERROR;
			TCPWasReset(socket->SocketID);
			socket->webSktState = SKT_TCP_PROGRESS;
			return SOCKET_CNXN_IN_PROGRESS;
		case SKT_TCP_PROGRESS:
			if(HandlePossibleTCPDisconnection(s))
				return SOCKET_ERROR;
			if(!TCPIsConnected(socket->SocketID))
				return SOCKET_CNXN_IN_PROGRESS;
			socket->webSktState = SKT_HANDSHAKE_DO;
			return SOCKET_HS_DO; //now we can continue with the web socket handshake procedure
		case SKT_HANDSHAKE_DO:
			if(TCPIsPutReady(socket->SocketID) < 125u)
				break;
			TCPPutROMString(socket->SocketID, (ROM BYTE*)"GET ");
			TCPPutString(socket->SocketID, info->uri);
			TCPPutROMString(socket->SocketID, (ROM BYTE*)" HTTP/1.1\r\nHost: ");
			TCPPutString(socket->SocketID, info->hostName);
			TCPPutROMString(socket->SocketID, (ROM BYTE*)"\r\n");
			TCPPutROMString(socket->SocketID, (ROM BYTE*)"Connection: Upgrade\r\n");
			TCPPutROMString(socket->SocketID, (ROM BYTE*)"Upgrade: WebSocket\r\n");
			TCPPutROMString(socket->SocketID, (ROM BYTE*)"Sec-WebSocket-Key: dGh1IHNhbXBsZSBub25jZQ==\r\n");
			//SSL support not implemented
			if (info->useSSL) return SOCKET_ERROR;
			//TCPPutROMString(socket->SocketID, (ROM BYTE*)"Origin: wss://");
			TCPPutROMString(socket->SocketID, (ROM BYTE*)"Origin: ws://");
			TCPPutString(socket->SocketID, info->hostName);
			TCPPutROMString(socket->SocketID, (ROM BYTE*)"\r\n");
			TCPPutROMString(socket->SocketID, (ROM BYTE*)"Sec-WebSocket-Version: 13\r\n\r\n");
			TCPFlush(socket->SocketID);
			socket->webSktState = SKT_HANDSHAKE_DONE;
			socket->timer = TickGet();
			return SOCKET_HS_DONE;
		case SKT_HANDSHAKE_DONE:
			if(HandlePossibleTCPDisconnection(s))
				return SOCKET_ERROR;
			/* If we have waited for the server reply for too long*/
			/* reset the connection and return to initial state */
			if(TickGet() - socket->timer > 5*TICK_SECOND) {
				TCPDisconnect(socket->SocketID);
				socket->SocketID = INVALID_SOCKET;
				socket->webSktState = SKT_CLOSED;
				return SOCKET_ERROR;
			}
			socket->timer = TickGet();
			if(TCPFind(socket->SocketID, '\n', 0, FALSE) == 0xffff)
			{// First line isn't here yet
				if(TCPGetRxFIFOFree(socket->SocketID) == 0u)
				{// If the FIFO is full, we overflowed
					TCPDisconnect(socket->SocketID);
					socket->SocketID = INVALID_SOCKET;
					socket->webSktState = SKT_CLOSED;
				}
				return SOCKET_HS_DONE;
			}
			//Get the protocol version and response code
			rLen = TCPFind(socket->SocketID, ' ', 0, FALSE);
			TCPGetArray(socket->SocketID, NULL, rLen + 1);
			rLen = TCPFind(socket->SocketID, ' ', 0, FALSE);
			TCPGetArray(socket->SocketID, (BYTE *)buf, rLen + 1);
			//check if the response code is 101 otherwise close the connection
			if (memcmppgm2ram((char*)buf, (ROM char *)"101", 3) != 0) { //101
				//response was not HTTP/1.1 101
				//this is an error and we should close connection
				TCPDisconnect(socket->SocketID);
				socket->SocketID = INVALID_SOCKET;
				socket->webSktState = SKT_CLOSED;
				return SOCKET_ERROR;
			}
			//skip rest of the line
			rLen = TCPFind(socket->SocketID, '\n', 0, FALSE);
			TCPGetArray(socket->SocketID, NULL, rLen + 1);
			socket->webSktState = SKT_HANDSHAKE_OPT_DONE;
		case SKT_HANDSHAKE_OPT_DONE:
			if(TickGet() - socket->timer > 5*TICK_SECOND) {
				TCPDisconnect(socket->SocketID);
				socket->SocketID = INVALID_SOCKET;
				socket->webSktState = SKT_CLOSED;
				return SOCKET_ERROR;
			}
			socket->timer = TickGet();
			// now process all options that we have
			// simply trash them as parsing not supported yet
			while (1) {
				rLen = TCPFind(socket->SocketID, '\n', 0, FALSE);
				if(rLen == 0xffff)
				{// If not, make sure we can receive more data
					if(TCPGetRxFIFOFree(socket->SocketID) == 0u)
					{// If the FIFO is full, we overflowed
						TCPDisconnect(socket->SocketID);
						socket->SocketID = INVALID_SOCKET;
						socket->webSktState = SKT_CLOSED;
					}
					return SKT_HANDSHAKE_OPT_DONE;
				}
				//read the line and continue
				TCPGetArray(socket->SocketID, NULL, rLen + 1);
				// If a CRLF is immediate, then headers are done
				if(rLen == 1u)
				{
					socket->webSktState = SKT_EST;
					return 0;
				}
			}
		case SKT_EST:
			return 0;
		default:
			return SOCKET_ERROR;
		}
	return 0;
}

static BOOL HandlePossibleTCPDisconnection(WSOCKET s)
{
	struct WebSocket *socket;
	BYTE i;
	BOOL bSocketWasReset;

	socket = &WebSocketArray[s];

	// Nothing to do if disconnection has already been handled
	if(socket->webSktState == SKT_DISCONNECTED)
		return TRUE;

	// Find out if a disconnect has occurred
	bSocketWasReset = TCPWasReset(socket->SocketID);
			
	// If we get down here and the socket was reset, then this socket 
	// should be closed so that no more clients can connect to it.  However, 
	// we can't go to the WS SKT_CLOSED state directly since the user still 
	// has to call closesocket() with this s SOCKET descriptor first.
	if(bSocketWasReset)
	{
		TCPClose(socket->SocketID);
		socket->webSktState = SKT_CLOSED;
		socket->SocketID = INVALID_SOCKET;
		return TRUE;
	}

	return FALSE;
}

int ws_send( WSOCKET s, const char* buf, int len ) {
	struct WebSocket *  socket;
	int					i;

	if( s >= WEB_SOCKET_COUNT )
		return SOCKET_ERROR;

	socket = &WebSocketArray[s];

	if(socket->webSktState != SKT_EST)
		return SOCKET_ERROR;

	if(HandlePossibleTCPDisconnection(s))
		return SOCKET_ERROR;

	if(TCPIsPutReady(socket->SocketID) == 0u)
		return 0;

	if (TCPGetTxFIFOFree(socket->SocketID) < len)
		return 0;
		
	if(len == 0)
		return 0;

	if (len <= 125u) {
		BYTE control = 0x82;
		BYTE length  = 0x80 | len;
		if (!TCPPut(socket->SocketID, control))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, length))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, (socket->mask >> 24) & 0xFF))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, (socket->mask >> 16) & 0xFF))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, (socket->mask >> 8) & 0xFF))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, (socket->mask & 0xFF)))
			return SOCKET_ERROR;
		for (i = 0; i < len; i++) {
			//Do the masking first
			int j = i % 4;
			BYTE nextByte = buf[i];
			nextByte = ((nextByte) ^ (BYTE)(socket->mask << (j*8)));
			if (!TCPPut(socket->SocketID, nextByte))
				return SOCKET_ERROR;
		}
		TCPFlush(socket->SocketID);
		return len;
	} else if (len <= 1000u) { 
		BYTE control     = 0x82;
		BYTE length      = 0x80 | (BYTE)126;
		BYTE length_ext1 = (len >> 8) & 0xFF;
		BYTE length_ext2 = len & 0xFF;
		if (!TCPPut(socket->SocketID, control))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, length))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, length_ext1))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, length_ext2))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, (socket->mask >> 24) & 0xFF))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, (socket->mask >> 16) & 0xFF))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, (socket->mask >> 8) & 0xFF))
			return SOCKET_ERROR;
		if (!TCPPut(socket->SocketID, (socket->mask & 0xFF)))
			return SOCKET_ERROR;
		for (i = 0; i < len; i++) {
			int j = i % 4;
			BYTE nextByte = buf[i];
			nextByte = ((nextByte) ^ (BYTE)(socket->mask << (j*8)));
			if (!TCPPut(socket->SocketID, nextByte))
				return SOCKET_ERROR;
		}
		TCPFlush(socket->SocketID);
		return len;
	}
	//Frames larger than 1000Bytes are not supported yet
	return SOCKET_ERROR;
}
int ws_recv( WSOCKET s, char* buf, int len ) {
	struct WebSocket *  socket;
	WORD				rLen;
	BYTE				b;
	BYTE				control;
	BYTE				length;
	BOOL				maskSet;
	DWORD				mask;

	if( s >= WEB_SOCKET_COUNT )
		return SOCKET_ERROR;

	socket = &WebSocketArray[s];

	if(socket->webSktState != SKT_EST)
		return SOCKET_ERROR;

	if(HandlePossibleTCPDisconnection(s))
		return SOCKET_ERROR;

	if (socket->recvState == SOCKET_RECV_HEADER) {
		if (TCPIsGetReady(socket->SocketID) < 2) return 0;
		if (!TCPGet(socket->SocketID, &b))
			return SOCKET_ERROR;
		control = b;
		if (control & 0x80 != 0x80) {
			ws_closesocket(s);	
			 //Fragmentation not supported
			return 0;
		}
		if (control & 0x08 == 0x08) {
			ws_closesocket(s);	
			return 0;
		} else if (control & 0x09 == 0x09) {
			socket->recvFrameType = SOCKET_PING_FRAME;
		} else	if (control & 0x0A == 0x0A) {
			socket->recvFrameType = SOCKET_PONG_FRAME;
		} else {
			socket->recvFrameType = SOCKET_DATA_FRAME;
		}

		if (!TCPGet(socket->SocketID, &b))
			return SOCKET_ERROR;
		
		socket->recvLen = b & 0x7F;
		
		if (b & 0x80) socket->isMaskSet = TRUE;
		if (socket->recvLen == 0) {
			if (socket->recvFrameType == SOCKET_PING_FRAME) ws_pong(s);
			return 0;
		} else if (socket->recvLen <= 125u) {
			if (b & 0x80) socket->recvState = SOCKET_RECV_MASK;
			else          socket->recvState = SOCKET_RECV_DATA;
		} else if (socket->recvLen == 0x7E) {
			socket->recvState = SOCKET_RECV_HEADER_EXT;
		} else {
			//Frame is too large
			return SOCKET_ERROR;
		}
		return 0;
	}

	if (socket->recvState == SOCKET_RECV_HEADER_EXT) {
		if (TCPIsGetReady(socket->SocketID) < 2) return 0;
		if (!TCPGet(socket->SocketID, &b))
			return SOCKET_ERROR;
		socket->recvLen = (b << 8) & 0xFF00;
		if (!TCPGet(socket->SocketID, &b))
			return SOCKET_ERROR;
		socket->recvLen |= b;
		//If frame is too large close the socket
		if (socket->recvLen > 1000u) return SOCKET_ERROR; 
		if (socket->isMaskSet) socket->recvState = SOCKET_RECV_MASK;
		else                   socket->recvState = SOCKET_RECV_DATA;
		return 0;
	}
	
	if (socket->recvState == SOCKET_RECV_MASK) {
		if (TCPIsGetReady(socket->SocketID) < 4u) return 0;
		BYTE m;
		TCPGet(socket->SocketID, &m);
		mask = m << 24;
		TCPGet(socket->SocketID, &m);
		mask = mask | (m << 16);
		TCPGet(socket->SocketID, &m);
		mask = mask | (m << 8);
		TCPGet(socket->SocketID, &m);
		mask = mask | m;
		socket->recvMask = mask;
		socket->recvState == SOCKET_RECV_DATA;
		return 0;
	}
	if (socket->recvState == SOCKET_RECV_DATA) {
		int i = 0, j = 0;
		if (TCPIsGetReady(socket->SocketID) < socket->recvLen) return 0;
		if (socket->recvFrameType == SOCKET_PING_FRAME) {
			TCPGetArray(socket->SocketID, NULL, socket->recvLen);
			ws_pong(s);
			length = 0;
		} else if (socket->recvFrameType == SOCKET_PING_FRAME) {
			TCPGetArray(socket->SocketID, NULL, socket->recvLen);
			length = 0;
		} else {
			TCPGetArray(socket->SocketID, buf, socket->recvLen);
			if (socket->recvMask) {
				for (i = 0; i < length; i++) { 
					j = i % 4;
					buf[i] = buf[i] ^ (BYTE)(mask << (j*8));
				}
			}
			length = socket->recvLen;
		}
		socket->recvMask = 0;
		socket->recvState == SOCKET_RECV_HEADER;
		socket->recvLen = 0;
	}
	
	return length;
}

int ws_ping( WSOCKET s ) {
	struct WebSocket *  socket;

	if( s >= WEB_SOCKET_COUNT )
		return SOCKET_ERROR;

	socket = &WebSocketArray[s];

	if(socket->webSktState != SKT_EST)
		return SOCKET_ERROR;
	if(HandlePossibleTCPDisconnection(s))
		return SOCKET_ERROR;

	BYTE control = 0x80 | 0x09;
	BYTE length  = 0x80;
	if (!TCPPut(socket->SocketID, control)) return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, length)) return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, (socket->mask >> 24) & 0xFF)) return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, (socket->mask >> 16) & 0xFF)) return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, (socket->mask >> 8) & 0xFF )) return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, (socket->mask & 0xFF))) return SOCKET_ERROR;
	TCPFlush(socket->SocketID);
	return 0;
}

int ws_pong( WSOCKET s ) {
	struct WebSocket *  socket;

	if( s >= WEB_SOCKET_COUNT )
		return SOCKET_ERROR;

	socket = &WebSocketArray[s];

	if(socket->webSktState != SKT_EST)
		return SOCKET_ERROR;

	if(HandlePossibleTCPDisconnection(s))
		return SOCKET_ERROR;

	BYTE control = 0x80 | 0x0A;
	BYTE length  = 0x80;
	if (!TCPPut(socket->SocketID, control)) return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, length))	return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, (socket->mask >> 24) & 0xFF)) return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, (socket->mask >> 16) & 0xFF)) return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, (socket->mask >> 8) & 0xFF )) return SOCKET_ERROR;
	if (!TCPPut(socket->SocketID, (socket->mask & 0xFF))) return SOCKET_ERROR;
	TCPFlush(socket->SocketID);
	return 0;
}

int ws_closesocket( WSOCKET s ) {
	struct WebSocket *  socket;

	if( s >= WEB_SOCKET_COUNT )
		return SOCKET_ERROR;

	socket = &WebSocketArray[s];

	if(socket->webSktState != SKT_EST)
		return SOCKET_ERROR;

	if(HandlePossibleTCPDisconnection(s))
		return SOCKET_ERROR;

	BYTE control = 0x88;
	BYTE length  = 0x80;
	TCPPut(socket->SocketID, control);
	TCPPut(socket->SocketID, length);
	TCPPut(socket->SocketID, (socket->mask >> 24) & 0xFF);
	TCPPut(socket->SocketID, (socket->mask >> 16) & 0xFF);
	TCPPut(socket->SocketID, (socket->mask >> 8) & 0xFF );
	TCPPut(socket->SocketID, (socket->mask & 0xFF));

	TCPFlush(socket->SocketID);
	TCPDisconnect(socket->SocketID);
	socket->webSktState = SKT_CLOSED;
	socket->SocketID = INVALID_SOCKET;
	socket->mask   = 0x0;
	socket->secKey = 0x0;
	socket->timer  = 0x0;
	return 0;
}