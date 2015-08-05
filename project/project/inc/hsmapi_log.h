/*----------------------------------------------------------------------|
|    hsmapi_log.h -   The header file of hsmapi_log.c                   |
|    Version :     1.0                                                  |
|    Author:       by lcj.                                              |
|    Description:                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-25. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSMAPI_LOG_H__
#define __HSMAPI_LOG_H__

#define LOG_ERROR_LEVEL 0
#define LOG_TRACE_LEVEL 1


#define LINE_LEN 16

#ifdef __cplusplus
extern "C" {
#endif
/***************************************************************************
* Subroutine: Log_GetFileLength
* Function:   ��ȡ��־�ļ���С
* Input:
*   @pcFileName   �ļ�����
* Output:
*   ��
*
* Return:       �����ļ��ֽ���
* Description:
* Date:         2015.05.25
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
unsigned long Log_GetFileLength(char *pcFileName);


/***************************************************************************
* Subroutine: Log_GetTime
* Function:   ��ȡϵͳ��ǰʱ��
* Input:
*    @pcBuffer        �洢ʱ���ַ���������
*    @iBufferLen      �洢ʱ���ַ����ĳ���
*    @pcFormat        ʱ���ʽ
* Output:
*   ��
*
* Return:       ϵͳ��ǰʱ��
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
char *Log_GetTime(char *pcBuffer, int iBufferLen, const char *pcFormat);

/***************************************************************************
* Subroutine: Log_HexDumpBuffer
* Function:   ����־��Ϣ��ʮ������д���ļ�
* Input:
*    @fp            �ļ�������
*    @buffer        ��־��Ϣ
*    @len           ��־��Ϣ����
* Output:
*   ��
*
* Return:       �ɹ�����0 ��ʧ�ܷ�������
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Log_HexDumpBuffer(FILE *fp, unsigned char *buffer, int length);

/***************************************************************************
* Subroutine: Log_HexDumpOneLine
* Function:   ����־��Ϣ��ʮ������д���ļ�(д��һ��)
* Input:
*    @fp            �ļ�������
*    @buffer        ��־��Ϣ
*    @len           ��־��Ϣ����
*    @line          ������־��Ϣ��ӡ������
* Output:
*   ��
*
* Return:       �ɹ�����0 ��ʧ�ܷ�������
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Log_HexDumpOneLine(FILE *fp, unsigned char *buffer, int *len, int *line);

/***************************************************************************
* Subroutine: Log_ErrorMessage
* Function:   ��ӡ������־
* Input:
*   @iLine          ��־��Ϣ���ڴ��������
*   @pcFuncName     ��־��Ϣ���ڵĺ�����
*   @pcFormat       Ҫ��ӡ����־��Ϣ
* Output:
*   ��
*
* Return:       ��
* Description:
* Date:         2015.05.25
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
void Log_ErrorMessage(int iLine, const char *pcFuncName, const char *pcFormat, ...);

/***************************************************************************
* Subroutine: Log_TraceMessage
* Function:   ��ӡ����
* Input:
*   @pcTitle          ����
*   @pucBuffer        �������Ϣ
*   @iBufferLen       �������Ϣ���ֽ���
* Output:
*   ��
*
* Return:       ��
* Description:
* Date:         2015.05.25
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
void Log_TraceMessage(char *pcTitle, unsigned char *pucBuffer, int iBufferLen);

#define LOG_ERROR(format, ...) Log_ErrorMessage(__LINE__, __FUNCTION__, format, __VA_ARGS__)
#define LOG_TRACE(title, buffer, len) Log_TraceMessage(title, buffer, len)


#ifdef __cplusplus
}
#endif

#endif /*__HSMAPI_LOG_H__*/

