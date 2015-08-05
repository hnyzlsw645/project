#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#include <WinSock.h>
#else   // WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif  // WIN32

#include "internal_structs.h"
#include "hsmsocket.h"
/*#include "hsmdefine.h"*/
#include "hsmapi_log.h"
#include "hsmapi_define.h"

static int g_firstsocket = 1;
extern void *g_handle;

#define SOCKET_MAXDATALEN   5*1024+128

int TCP_ConnectHsm( char *hostip, int hostport )
{
    int sockfd;

    struct sockaddr_in serv_addr;
    struct linger tcp_linger;
    int    rc = 0;

#ifdef TASS_DEBUG
    Log_Debug("%s", "Start...");
#endif

#ifdef WIN32
    if ( g_firstsocket )
    {
        // Socket≥ı ºªØ
        WSADATA  wsadata;
        WSAStartup(0x202, &wsadata);
        g_firstsocket = 0;
    }
#endif

    memset (&serv_addr, 0x00,sizeof (struct sockaddr_in));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr( hostip );
    serv_addr.sin_port = htons( hostport );

    if ( (sockfd = (int)socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        rc = HAR_SOCK_CONNECT;
        LOG_ERROR("%s, ERROR Create socket failed [%#X].",
                __func__,rc);
        return rc;
    }

    rc = connect( sockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in) );
    //if ( rc < 0 )
    if ( rc != 0 )
    {
        LOG_ERROR("%s, ERROR socket connect return [%d].",
                __func__, rc);
        //return HAR_SOCK_CONNECT;
        return -1;
    }

    tcp_linger.l_onoff    = 1; /* Linger On */
    tcp_linger.l_linger    = 0; /* 0 seconds */
    setsockopt( sockfd, SOL_SOCKET, SO_LINGER, (char *)&tcp_linger, sizeof(struct linger) );

    /*Log_Debug( "%s, DEBUG socket connect DONE sockfd=[%d].",
            __func__, sockfd);*/

#ifdef TASS_DEBUG
    Log_Debug("%s", "End.");
#endif
    return sockfd;
}

int TCP_DisconnectHsm( int sockfd )
{
    shutdown( sockfd, 2 );
#ifdef WIN32
    closesocket( sockfd );
#else   //WIN32
    close( sockfd );
#endif  //WIN32
    return 0;
}

int _SocketSendData( int sockfd, unsigned char *buffer, int *length, int timeout )
{
    int rc = -1;
    int len = -1;
    struct timeval stTimeOut;
    fd_set    stSockReady;

    FD_ZERO( &stSockReady);
    FD_SET(sockfd, &stSockReady);

#ifdef TASS_DEBUG
    Log_Debug("%s", "Start...");
    Log_Debug("sockfd = [%d]; buff_length = [%d]; timeout = [%d].", sockfd, *length, timeout);
#endif

    if (timeout> 0)
    {
        stTimeOut.tv_sec = timeout;
        stTimeOut.tv_usec = 0;

        select(sockfd+1, NULL, &stSockReady, NULL,&stTimeOut);
    }
    else
        select(sockfd+1, NULL, &stSockReady, NULL,NULL);

    if(!(FD_ISSET(sockfd,&stSockReady)))
        return HAR_SOCK_SELECT;
    else
    {
        char* p = (char*)buffer;

        do
        {
            len = send( sockfd, p, *length, 0 );
            if ( len <= 0 )
            {
                *length = len;
                LOG_ERROR( "%s, Error socket Send [%d].",
                        __func__, len);
                return HAR_SOCK_SELECT;
            }

            p = p + len;
            *length = *length - len;
        }while ( *length > 0 );

        *length = (int)((unsigned char*)p - buffer);

#ifdef TASS_DEBUG
        Log_Debug("%s", "End.");
#endif
        return 0;
    }
}

int _SocketReceiveData( int sockfd, unsigned char *buffer, int *length, int timeout )
{
    int    rc = -1;
    int    rcvlen = 0;
    int     rcvlen1 = 0;
    struct     timeval stTimeOut;
    fd_set    stSockReady;
    unsigned char *p = buffer;

    FD_ZERO(&stSockReady);
    FD_SET(sockfd, &stSockReady);

#ifdef TASS_DEBUG
    Log_Debug("%s", "Start...");
    Log_Debug("sockfd = [%d]; buff_length = [%d]; timeout = [%d].", sockfd, *length, timeout);
#endif

    if (timeout>0)
    {
        stTimeOut.tv_sec = timeout;
        stTimeOut.tv_usec = 0;
        rc = select(sockfd+1, &stSockReady, NULL,NULL,&stTimeOut);
    }
    else
        rc = select(sockfd+1, &stSockReady, NULL,NULL,NULL);

    if( !(FD_ISSET(sockfd,&stSockReady)) )
    {
        //LOG_ERROR("%s, ERROR FD_ISSET return [%d].", __func__,rc); 
        LOG_ERROR("ERROR FD_ISSET%s", ".");
        return -1;
    }
    else
    {
        int  ilen;

        rcvlen = recv(sockfd, (char*)p, 2, 0);
        if ( rcvlen != 2 )
        {
            LOG_ERROR("%s, ERROR sockfd[%d], recv return [%d].",
                    __func__, sockfd, rc);
            return HAR_SOCK_RECV;
        }

        ilen = p[0]*256 + p[1];
        if( ilen > SOCKET_MAXDATALEN ) 
            ilen = SOCKET_MAXDATALEN;
        p += 2;

        rcvlen = recv( sockfd, (char*)p, ilen, 0 );
        if ( ( rcvlen > 0 ) && ( rcvlen < ilen ) )
        {
            rcvlen1 = rcvlen;
            while ( rcvlen < ilen )
            {
                p += rcvlen1;
                rcvlen1 = recv( sockfd, (char*)p, ilen - rcvlen, 0 );

                if(rcvlen1 < 0)
                {
                    LOG_ERROR("%s, ERROR sockfd[%d] recv [%#X].",
                            __func__, sockfd, HAR_SOCK_RECV );
                    return HAR_SOCK_RECV;
                }

                rcvlen += rcvlen1;
            }

            *length = rcvlen + 2;
#ifdef TASS_DEBUG
    Log_Debug("%s", "End.");
#endif
            return 0;
        }
        else if ( rcvlen == ilen )
        {
            *length = rcvlen + 2;

#ifdef TASS_DEBUG
    Log_Debug("%s", "End.");
#endif

            return 0;
        }
        else
        {
            LOG_ERROR("%s, ERROR sockfd[%d] recv [%#X].",
                    __func__, sockfd, HAR_SOCK_RECV );
            return HAR_SOCK_RECV;
        }
    }
}

int TCP_CommunicateHsm( int sockfd,
    unsigned char *pucInput, int iInputLen,
    unsigned char *pucOutput, int *piOutputLen )
{
    unsigned char   cmd_buf[SOCKET_MAXDATALEN],*p;
    unsigned char   ret_buf[SOCKET_MAXDATALEN];

    int cmd_len=0, ret_len=0;
    int rv, tmplen, flg = 0;

#ifdef TASS_DEBUG
    Log_Debug("%s", "Start...");
    Log_Debug("sockfd = [%d]; iInputLen = [%d]; piOutputLen = [%d].", sockfd, iInputLen, *piOutputLen);
#endif

    memset( cmd_buf, 0x0, sizeof(cmd_buf) );
    memset( ret_buf, 0x0, sizeof(ret_buf) );

    for ( ;; )
    {
        if ( sockfd <= 0)
        {
            rv = -1;
            break;
        }

        // CMD: 2 Bytes Length + cmd
        p = cmd_buf;

        // 2 Bytes Length
        *p++ = iInputLen / 256;
        *p++ = iInputLen % 256;

        memcpy(p, pucInput, iInputLen);
        p += iInputLen;

        *p = 0;
        cmd_len = iInputLen+2;//(int)(p - cmd_buf);

        rv = _SocketSendData( sockfd, cmd_buf, &cmd_len, 1 );
        if ( rv != 0 )
            break;

        ret_len = sizeof(ret_buf);
        rv = _SocketReceiveData( sockfd, ret_buf, &ret_len, 60 );
        if ( rv != 0 )
            break;

        *(ret_buf+ret_len)=0;

        // Response: 2 Bytes Length + 2 bytes Response Code + 2 Bytes Error Code + n Bytes Response Message
        p = ret_buf;

        // 2 Bytes Length
        tmplen = p[0]*256 + p[1];
        if ( tmplen != ret_len-2 )
        {
            rv = -2;
            break;
        }
        p += 2;

        // n Bytes Response Message
        if ( pucOutput == NULL )
        {
            *piOutputLen = tmplen;
            break;
        }

        if ( *piOutputLen < tmplen )
        {
            rv = -3;
            break;
        }

        memcpy( pucOutput, (unsigned char *)p, tmplen );
        pucOutput[tmplen] = 0x0;
        *piOutputLen = tmplen;
        break;
    }

#ifdef TASS_DEBUG
    Log_Debug("%s", "End.");
#endif
    return rv;
}

int TCP_CommunicateHsm_ex( void *hSessionHandle,
        unsigned char *pucCmd, int iCmdLen,
        unsigned char *pucRsp, int *piRspLen)
{
    int cmd_len=0, ret_len=0;
    int rv, tmplen, flg = 0;
    int sockfd = 0;

    int iReBufferLen = SOCKET_MAXDATALEN;
    unsigned char pucReBuffer[SOCKET_MAXDATALEN] = {0};

    Sessionstruct* pSessionStruct = (Sessionstruct*)hSessionHandle;

    if( pSessionStruct == NULL ||  pSessionStruct->status != 1 )
    {
        return HAR_SESSIONHANDLE_INVALID;
    }

    if(pucRsp == NULL)
    {
        LOG_ERROR("pucRsp = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    sockfd = pSessionStruct->device->sockfd;

    rv = TCP_CommunicateHsm( sockfd,
            pucCmd, iCmdLen,
            pucReBuffer, &iReBufferLen );

    if(rv)
    {
        LOG_ERROR("TCP_CommunicateHsm return code = [%#010X], [%d].", rv, rv);
    }

    if((pucCmd[0] != pucReBuffer[0]) || (pucCmd[1] + 1 != pucReBuffer[1]))
    {
        LOG_ERROR("Recv code is error%s", ".");
        return HAR_MSG_RSPCODE;
    }

    if(*piRspLen < iReBufferLen)
    {
        LOG_ERROR("piRspLen = [%d], need buffer length = [%d].", *piRspLen, iReBufferLen);
        return HAR_MEM_LENLESS;
    }

    memcpy(pucRsp, pucReBuffer + 4, iReBufferLen - 4);
    *piRspLen = iReBufferLen - 4;

    /*** 2 Bytes Error Code ***/
    return (pucReBuffer[2] - '0') * 10 + (pucReBuffer[3] - '0');
}

