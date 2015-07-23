/*----------------------------------------------------------------------|
|    hsmapi_log.c                                                       |
|    Version :     1.0                                                  |
|    Author:       by Luo Cangjian.                                              |
|    Description:  SJJ1310������ӿ���־ģ��                            |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-22. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#ifdef    WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "hsmapi_log.h"

#define LEN_MAX_FNAME           FILENAME_MAX

char g_TraceFile[] = "trace.log";
char g_ErrorFile[] = "TassHsmApi.log";
extern char g_szLogPath[LEN_MAX_FNAME];
extern int  g_iLogLevel;

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
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
unsigned long Log_GetFileLength(char *pcFileName)
{
    long    start, end;

#ifdef    WIN32
    HFILE    handle;
#else
    int     handle;
#endif

#ifdef    WIN32
    handle = _lopen(pcFileName, OF_READ);
    start = _llseek(handle, 0L, SEEK_SET);
    end = _llseek(handle, 0L, SEEK_END);
    _lclose(handle);
#else
    handle = open(pcFileName, O_RDONLY);
    start = lseek(handle,0L,SEEK_SET);
    end = lseek(handle, 0L, SEEK_END);
    close(handle);
#endif

    return (end - start);
}


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
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
char *Log_GetTime(char *pcBuffer, int iBufferLen, const char *pcFormat)
{
    time_t        clock;

    clock = time((time_t *)0);
    strftime(pcBuffer, iBufferLen, pcFormat, localtime(&clock));

    return pcBuffer;
}


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
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Log_HexDumpBuffer(FILE *fp, unsigned char *buffer, int length)
{
    int line = 0, len = length;

    for(line = 0; line < length / LINE_LEN + ((length % LINE_LEN) ? 1 : 0); ++line)
    {
        Log_HexDumpOneLine(fp, buffer, &len, &line);
        buffer += LINE_LEN;
    }

    return 0;
}

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
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Log_HexDumpOneLine(FILE *fp, unsigned char *buffer, int *len, int *line)
{
    register int i;

    fprintf(fp, "0x%06x [ ", *line);

    for(i = 0;i < LINE_LEN; i++, (*len)--)
    {
        (*len) > 0 ? fprintf(fp, "%02x ", buffer[i]) : fprintf(fp,"   ");
    }

    (*len) += LINE_LEN;
    fprintf(fp, "] [");

    for (i = 0; i < LINE_LEN; i++, (*len)--)
    {
        if(*len > 0)
        {
            isprint(buffer[i]) ? fputc(buffer[i], fp) : fputc('.', fp);
        }
        else
        {
            fputc(' ', fp);
        }
    }

    fprintf(fp,"]\n");

    return 0;
}

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
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
void Log_ErrorMessage(int iLine, const char *pcFuncName, const char *pcFormat, ...)
{
    FILE    *fp;
    int    iLen;

#ifdef    WIN32
#ifndef _MBCS
    TCHAR   szPath[LEN_MAX_FNAME];
#endif
    char    szBackupLogFile[LEN_MAX_FNAME];
    char    szWorkingLogFile[LEN_MAX_FNAME], *tmpin;
#else
    char    szWorkingLogFile[LEN_MAX_FNAME];
    char    szBackupLogFile[LEN_MAX_FNAME];
#endif
    char    buffer[2048];
    char    szDate[9 + 2], szTime[9];

#ifdef    WIN32
#ifdef _MBCS
    rv = GetEnvironmentVariable("TASSDBGENV", szWorkingLogFile, LEN_MAX_FNAME);
    if (rv == 0)
    {
        GetModuleFileName(NULL, szWorkingLogFile, LEN_MAX_FNAME);
    }
#else
    if(strlen(g_szLogPath) == 0)
    {
        strcpy(szWorkingLogFile, ".\\");
    }
    else
    {
        strcpy(szWorkingLogFile, g_szLogPath);
    }
#endif
    tmpin = strrchr(szWorkingLogFile, '\\');
    if(NULL == tmpin)
    {
        return;
    }

    *(tmpin + 1) = 0x00;
#else

    if(getenv("TASSDBGENV") != NULL)
    {
        strcpy(szWorkingLogFile, getenv("TASSDBGENV"));
    }
    else if(strlen(g_szLogPath) == 0)
    {
        strcpy(szWorkingLogFile, "./");
    }
    else
    {
        strcpy(szWorkingLogFile, g_szLogPath);
    }
#endif
#ifdef    WIN32
    strcpy(szBackupLogFile, szWorkingLogFile);
    strcat(szWorkingLogFile, g_ErrorFile);
#else    /** Unix **/

    iLen = strlen(szWorkingLogFile);
    if(szWorkingLogFile[iLen - 1] !=  '/')
    {
        strcat(szWorkingLogFile, "/");
    }

    strcpy(szBackupLogFile, szWorkingLogFile);
    strcat(szWorkingLogFile, g_ErrorFile);
#endif

    if(Log_GetFileLength(szWorkingLogFile) > 32 * 1024 * 1024)
    {
        Log_GetTime(szTime,9,"%H:%M:%S");

        strcat(szBackupLogFile, g_ErrorFile);
        strcat(szBackupLogFile, szTime);

        remove(szBackupLogFile);
        rename(szWorkingLogFile, szBackupLogFile);
    }

    fp = fopen(szWorkingLogFile, "a");
    if(fp != NULL)
    {
        va_list Args;
        va_start(Args, pcFormat);
        vsprintf(buffer, pcFormat, Args);
        va_end(Args);

        Log_GetTime(szDate, 9 + 2, "%Y-%m-%d");
        Log_GetTime(szTime, 9, "%H:%M:%S");

#ifdef    WIN32
        fprintf(fp, "<%s %s> %s\n", szDate, szTime, buffer);
#else
        if(pcFuncName)
        {
            fprintf(fp, "<%s %s> [%d] [%d] %s - %s\n", szDate, szTime, getpid(), iLine, pcFuncName, buffer);
        }
        else
        {
            fprintf(fp, "<%s %s> [%d] %s\n", szDate, szTime, getpid(), buffer);
        }
#endif
    }

    if(fp)
    {
        fclose(fp);
    }

    return;
}

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
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
void Log_TraceMessage(char *pcTitle, unsigned char *pucBuffer, int iBufferLen)
{
    FILE    *fp;
    int    len;

#ifdef    WIN32
#ifndef _MBCS
    TCHAR   szPath[LEN_MAX_FNAME];
#endif
    char    szBackupLogFile[LEN_MAX_FNAME];
    char    szWorkingLogFile[LEN_MAX_FNAME], *tmpin;
#else
    char    szWorkingLogFile[LEN_MAX_FNAME];
    char    szBackupLogFile[LEN_MAX_FNAME];
#endif
    char    szDate[9 + 2], szTime[9];

    if (g_iLogLevel < LOG_TRACE_LEVEL)
    {
        return;
    }

#ifdef    WIN32
#ifdef _MBCS
    rv = GetEnvironmentVariable("TASSDBGENV", szWorkingLogFile, LEN_MAX_FNAME);
    if (rv == 0)
    {
        GetModuleFileName(NULL, szWorkingLogFile, LEN_MAX_FNAME);
    }
#else
    if(strlen(g_szLogPath) < 1)
    {
        strcpy(szWorkingLogFile, ".\\");
    }
    else
    {
        strcpy(szWorkingLogFile, g_szLogPath);
    }
#endif

    /*** �����־·����Ч�ԣ������Ч�򷵻� ***/
    tmpin = strrchr(szWorkingLogFile, '\\');
    if(NULL == tmpin)
    {
        return;
    }
    *(tmpin + 1) = 0x00;
#else
    if(getenv("TASSDBGENV") != NULL)
    {
        strcpy(szWorkingLogFile, getenv("TASSDBGENV"));
    }
    else if(strlen(g_szLogPath) == 0)
    {
        strcpy(szWorkingLogFile, "./");
    }
    else
    {
        strcpy(szWorkingLogFile, g_szLogPath);
    }

#endif
#ifdef    WIN32
    strcpy(szBackupLogFile, szWorkingLogFile);
    strcat(szWorkingLogFile, g_TraceFile);
#else
    len = strlen(szWorkingLogFile);

    if (szWorkingLogFile[len - 1] != '/')
    {
        strcat(szWorkingLogFile, "/");
    }

    strcpy(szBackupLogFile, szWorkingLogFile);
    strcat(szWorkingLogFile, g_TraceFile);
#endif

    if(Log_GetFileLength(szWorkingLogFile) > 32 * 1024 * 1024)
    {
        Log_GetTime(szTime, 9, "%H:%M:%S");

        strcat(szBackupLogFile, g_TraceFile);
        strcat(szBackupLogFile, szTime);

        remove(szBackupLogFile);
        rename(szWorkingLogFile, szBackupLogFile);
    }

    fp = fopen(szWorkingLogFile, "a");

    if(fp != NULL)
    {
        Log_GetTime(szDate, 9+2, "%Y-%m-%d");
        Log_GetTime(szTime, 9, "%H:%M:%S");

#ifdef    WIN32
        fprintf(fp,"\n<%s %s> %s [len = %d]\n", szDate, szTime, pcTitle, iBufferLen);
        Log_HexDumpBuffer(fp, pucBuffer, iBufferLen);
#else
        fprintf(fp,"\n<%s %s> [%d] %s [len = %d]\n", szDate, szTime, getpid(), pcTitle, iBufferLen);
        Log_HexDumpBuffer(fp, pucBuffer, iBufferLen);
#endif
    }

    if(fp)
    {
        fclose(fp);
    }

    return;
}





