/*----------------------------------------------------------------------|
|    hsmapi_tcpcom.h                                                    |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310������ӿ�socketͨѶģ�顣                    |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-26. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSM_API_TCPCOM__
#define __HSM_API_TCPCOM__

/***************************************************************************
* Subroutine: TCP_Init
* Function:   ��ʼ��windows������socket
* Input:
*   ��
*
* Output:
*   ��
*
* Return:       �ɹ�����0
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int TCP_Init();

/***************************************************************************
* Subroutine: DisconnectTcpServer
* Function:   �ر�socket����
* Input:
*   @iSockfd  socket������
*
* Output:
*   ��
*
* Return:       �ɹ�����0
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int DisconnectTcpServer(int iSockfd);

/***************************************************************************
* Subroutine: ConnectTcpServer
* Function:   ���ӷ�����
* Input:
*   @pcHostIp     ������IP
*   @iPort        �������˿�
* Output:
*   @piSockfd   socket������ָ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int ConnectTcpServer(char *pcHostIp, int iPort, int *piSockfd);

/***************************************************************************
* Subroutine: SetSocket
* Function:   ����socket����
* Input:
*   @iSockfd     socket������
* Output:
*   ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:
* Date:         2015.05.29
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int SetSocket(int iSockfd);

/***************************************************************************
* Subroutine: HsmSendToSocket
* Function:   ��������
* Input:
*   @iSockfd        socket������
*   @pucSendBuf     ���������ݻ�����
*   @iSendBufLen    �����͵����ݳ���
* Output:
*   ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int HsmSendToSocket(int iSockfd, unsigned char *pucSendBuf, int iSendBufLen);

/***************************************************************************
* Subroutine: HsmReceiveFromSocket
* Function:   ��������
* Input:
*   @iSockfd         socket������
* Output:
*   @pucRspBuf       ��Ӧ���Ļ�����
*   @piRspBufLen     ��Ӧ���ĳ���
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int HsmReceiveFromSocket(int iSockfd, unsigned char *pucRspBuf, int *piRspBufLen);

/***************************************************************************
* Subroutine: PackMsgHead
* Function:   ƴ����Ϣͷ
* Input:
*   @iMsgHeadLen   ��Ϣͷ����
*   @pucCmdBuf     ������� + ����Ԫ��
*   @iCmdBufLen    ������� + ����Ԫ�صĳ���
* Output:
*   @pucDstBuf     TCP�����
*   @piDstBufLen   TCP����ĳ���
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description: ƴ�ӱ��ĳ����Լ���Ϣͷ
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int PackMsgHead(int iMsgHeadLen, unsigned char *pucCmdBuf, int iCmdBufLen, unsigned char *pucDstBuf, unsigned int *piDstBufLen);

/***************************************************************************
* Subroutine: ParseMsgHead_Print
* Function:   ������Ӧ����
* Input:
*   @iMsgHeadLen    ��Ϣͷ����
*   @pucCmd         �������
*   @pucRspBuf      ��Ӧ����
*   @iRspBufLen     ��Ӧ���ĳ���
* Output:
*   ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:  �ú���ֻ�����ź���ӡ
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int ParseMsgHead_Print(int iMsgHeadLen, unsigned char *pucCmd, unsigned char *pucRspBuf, int iRspBufLen);

/***************************************************************************
* Subroutine: ParseMsgHead
* Function:   ������Ӧ����
* Input:
*   @iMsgHeadLen    ��Ϣͷ����
*   @pucCmd         �������
*   @pucRspBuf      ��Ӧ����
*   @iCmdBufLen     ��Ӧ���ĳ���
* Output:
*   @pucDstBuf      ����Ԫ��
*   @piDstBufLen    ����Ԫ�صĳ���
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int ParseMsgHead(int iMsgHeadLen, unsigned char *pucCmd, unsigned char *pucRspBuf, int iRspBufLen, unsigned char *pucDstBuf, int *piDstBufLen);

/***************************************************************************
* Subroutine: HsmCmd_TCP
* Function:   ����ܻ�ͨѶ
* Input:
*   @iMsgHeadLen    ��Ϣͷ����
*   @iSockfd        socket������
*   @pucCmd         ���͵ı���
*   @iCmdLen        ���͵ı��ĳ���
* Output:
*   @pucRsp         ��Ӧ���Ļ�����
*   @piRspLen       ��Ӧ���ĳ���
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int HsmCmd_TCP(int iMsgHeadLen, int iSockfd, unsigned char *pucCmd, int iCmdLen, unsigned char *pucRsp, int *piRspLen);

/***************************************************************************
* Subroutine: TCP_CommunicateHsm_ex
* Function:   ͨ��ͨѶ�ӿ�(�Ự�����ʽ)
* Input:
*    @hSessionHandle    �Ự���
*    @pucCmd            �����
*    @iCmdLen           ����ĳ���
*    @pucRsp            ��Ӧ����
*    @piRspLen          ��Ӧ���ĳ���
* Output:
*    ��
*
* Return:       0 for success, other is error
* Description:  ����Ӧ�����е�״̬������˽������������Ч����Ӧ����
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
int TCP_CommunicateHsm_ex(void *hSessionHandle, unsigned char *pucCmd, int iCmdLen, unsigned char *pucRsp, int *piRspLen);



#endif /*** __HSM_API_TCPCOM__ ***/
