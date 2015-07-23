/*----------------------------------------------------------------------|
|    hsmapi_tcpcom.h                                                    |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口socket通讯模块。                    |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-26. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSM_API_TCPCOM__
#define __HSM_API_TCPCOM__

/***************************************************************************
* Subroutine: TCP_Init
* Function:   初始化windows环境的socket
* Input:
*   无
*
* Output:
*   无
*
* Return:       成功返回0
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int TCP_Init();

/***************************************************************************
* Subroutine: DisconnectTcpServer
* Function:   关闭socket连接
* Input:
*   @iSockfd  socket描述符
*
* Output:
*   无
*
* Return:       成功返回0
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int DisconnectTcpServer(int iSockfd);

/***************************************************************************
* Subroutine: ConnectTcpServer
* Function:   连接服务器
* Input:
*   @pcHostIp     服务器IP
*   @iPort        服务器端口
* Output:
*   @piSockfd   socket描述符指针
*
* Return:       成功返回0， 失败返回其他
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int ConnectTcpServer(char *pcHostIp, int iPort, int *piSockfd);

/***************************************************************************
* Subroutine: SetSocket
* Function:   设置socket属性
* Input:
*   @iSockfd     socket描述符
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:
* Date:         2015.05.29
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int SetSocket(int iSockfd);

/***************************************************************************
* Subroutine: HsmSendToSocket
* Function:   发送数据
* Input:
*   @iSockfd        socket描述符
*   @pucSendBuf     待发送数据缓冲区
*   @iSendBufLen    待发送的数据长度
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int HsmSendToSocket(int iSockfd, unsigned char *pucSendBuf, int iSendBufLen);

/***************************************************************************
* Subroutine: HsmReceiveFromSocket
* Function:   接收数据
* Input:
*   @iSockfd         socket描述符
* Output:
*   @pucRspBuf       响应报文缓存区
*   @piRspBufLen     响应报文长度
*
* Return:       成功返回0， 失败返回其他
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int HsmReceiveFromSocket(int iSockfd, unsigned char *pucRspBuf, int *piRspBufLen);

/***************************************************************************
* Subroutine: PackMsgHead
* Function:   拼接消息头
* Input:
*   @iMsgHeadLen   消息头长度
*   @pucCmdBuf     命令代码 + 数据元素
*   @iCmdBufLen    命令代码 + 数据元素的长度
* Output:
*   @pucDstBuf     TCP命令报文
*   @piDstBufLen   TCP命令报文长度
*
* Return:       成功返回0， 失败返回其他
* Description: 拼接报文长度以及消息头
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int PackMsgHead(int iMsgHeadLen, unsigned char *pucCmdBuf, int iCmdBufLen, unsigned char *pucDstBuf, unsigned int *piDstBufLen);

/***************************************************************************
* Subroutine: ParseMsgHead_Print
* Function:   解析响应报文
* Input:
*   @iMsgHeadLen    消息头长度
*   @pucCmd         命令代码
*   @pucRspBuf      响应报文
*   @iRspBufLen     响应报文长度
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:  该函数只用于信函打印
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int ParseMsgHead_Print(int iMsgHeadLen, unsigned char *pucCmd, unsigned char *pucRspBuf, int iRspBufLen);

/***************************************************************************
* Subroutine: ParseMsgHead
* Function:   解析响应报文
* Input:
*   @iMsgHeadLen    消息头长度
*   @pucCmd         命令代码
*   @pucRspBuf      响应报文
*   @iCmdBufLen     响应报文长度
* Output:
*   @pucDstBuf      数据元素
*   @piDstBufLen    数据元素的长度
*
* Return:       成功返回0， 失败返回其他
* Description:
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int ParseMsgHead(int iMsgHeadLen, unsigned char *pucCmd, unsigned char *pucRspBuf, int iRspBufLen, unsigned char *pucDstBuf, int *piDstBufLen);

/***************************************************************************
* Subroutine: HsmCmd_TCP
* Function:   与加密机通讯
* Input:
*   @iMsgHeadLen    消息头长度
*   @iSockfd        socket描述符
*   @pucCmd         发送的报文
*   @iCmdLen        发送的报文长度
* Output:
*   @pucRsp         响应报文缓存区
*   @piRspLen       响应报文长度
*
* Return:       成功返回0， 失败返回其他
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int HsmCmd_TCP(int iMsgHeadLen, int iSockfd, unsigned char *pucCmd, int iCmdLen, unsigned char *pucRsp, int *piRspLen);

/***************************************************************************
* Subroutine: TCP_CommunicateHsm_ex
* Function:   通用通讯接口(会话句柄形式)
* Input:
*    @hSessionHandle    会话句柄
*    @pucCmd            命令报文
*    @iCmdLen           命令报文长度
*    @pucRsp            响应报文
*    @piRspLen          响应报文长度
* Output:
*    无
*
* Return:       0 for success, other is error
* Description:  对响应报文中的状态码进行了解析，并输出有效的响应报文
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
int TCP_CommunicateHsm_ex(void *hSessionHandle, unsigned char *pucCmd, int iCmdLen, unsigned char *pucRsp, int *piRspLen);



#endif /*** __HSM_API_TCPCOM__ ***/
