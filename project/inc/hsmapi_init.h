/*----------------------------------------------------------------------|
|    hsmapi_init.c                                                      |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian.                                        |
|    Description:  SJJ1310������ӿڳ�ʼ��ģ��                          |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-29. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSM_API_INIT_H_
#define __HSM_API_INIT_H_

/***************************************************************************
* Subroutine: IsIpv4Address
* Function:   �ж�IP�Ϸ���
* Input:
*    @pcIp    IP��ַ
* Output:
*    ��
*
* Return:       ����0 IP��ַ�Ϸ������������Ƿ�
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
int IsIpv4Address(const char *pcIp);

/***************************************************************************
* Subroutine: GetKeyValue
* Function:   ����ָ���ļ�����ȡ�����ļ��еļ�ֵ
* Input:
*    @pcFileName       �����ļ�·��
*    @pcKeyName        ����
* Output:
*    @pcKeyValue       ��ֵ
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
int GetKeyValue(char *pcFileName, char *pcKeyName, char *pcKeyValue);

/***************************************************************************
* Subroutine: Tass_HsmApiInit
* Function:   ͨ���ӿ�ָ��������Ϣ�ķ�ʽ��ʼ���ӿ�
* Input:
*    @pcConfigFilePath      �����ļ�·��
* Output:
*    ��
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
//int Tass_HsmApiInit(char *pcConfigFilePath);

/***************************************************************************
* Subroutine: Tass_HsmApiInitByContent
* Function:   ͨ���ӿ�ָ��������Ϣ�ķ�ʽ��ʼ���ӿ�
* Input:
*    @pcIp            �����IP
*    @uiPort          ������˿�
*    @uiTimeOut       socket��ȡ��ʱʱ�䣬��λ��
*    @pcLogPath       ��־���·��
* Output:
*    ��
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
int Tass_HsmApiInitByContent(char *pcIp, unsigned int uiPort, unsigned int uiTimeOut, char *pcLogPath);

#endif /*** __HSM_API_INIT_H_ ***/


