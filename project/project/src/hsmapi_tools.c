/*----------------------------------------------------------------------|
|    hsmapi_tools.c                                                     |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310������ӿڹ��ߺ���                            |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-21. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "hsmapi_log.h"
#include "hsmapi_define.h"
#include "hsmapi_tools.h"
#include "hsmapi_der.h"
/***************************************************************************
* Subroutine: Tools_CheckNum
* Function:   �ж�һ���ַ����ǲ��Ǵ����ֵ��ַ���
* Input:
*   @pcInData   pcInData
*
* Output:
*   ��
*
* Return:       0:�������ַ���   -1:���Ǵ������ַ���
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckNum(char *pcInData)
{
    unsigned int i;

    for(i = 0; i < strlen(pcInData); i++)
    {
        if(!isdigit(pcInData[i]))
        {
            return -1;
        }
    }

    return 0;
}

/***************************************************************************
* Subroutine: Tools_CheckHex
* Function:   �ж�һ���ַ����ǲ��Ǵ����ֵ��ַ���
* Input:
*   @pcInData   ��������ַ���
*
* Output:
*   ��
*
* Return:       0:ʮ�������ַ���   -1:����ʮ�������ַ���
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckHex(char *pcInData)
{
    unsigned int i = 0;

    for(i = 0; i < strlen(pcInData); i++)
    {
        if(!isxdigit(pcInData[i]))
        {
            return -1;
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Toos_CheckKeyType
* Function:   �ж϶Գ���Կ�����Ƿ�Ϸ�
* Input:
*   @pcKeyType   ��Կ����
*
* Output:
*   ��
*
* Return:       0:��Կ���ͺϷ�     ����������ʶ���ͷǷ�
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Toos_CheckKeyType(char *pcKeyType)
{
    if(pcKeyType == NULL || strlen(pcKeyType) != 3)
    {
        return HAR_PARAM_KEY_TYPE;
    }

    if(strcmp(pcKeyType, KEY_TYPE_KEKZMK)
            && strcmp(pcKeyType, KEY_TYPE_ZPK)
            && strcmp(pcKeyType, KEY_TYPE_PVKTPK)
            && strcmp(pcKeyType, KEY_TYPE_CVK)
            && strcmp(pcKeyType, KEY_TYPE_TAK)
            && strcmp(pcKeyType, KEY_TYPE_ZAK)
            && strcmp(pcKeyType, KEY_TYPE_BDK)
            && strcmp(pcKeyType, KEY_TYPE_MDKMKAC)
            && strcmp(pcKeyType, KEY_TYPE_MKSMI)
            && strcmp(pcKeyType, KEY_TYPE_MKDAK)
            && strcmp(pcKeyType, KEY_TYPE_MKDN)
            && strcmp(pcKeyType, KEY_TYPE_DEKZEK)
            && strcmp(pcKeyType, KEY_TYPE_TEK)
            && strcmp(pcKeyType, KEY_TYPE_HMAC)
            && strcmp(pcKeyType, KEY_TYPE_KMC))
    {
        return HAR_PARAM_KEY_TYPE;
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_ConvertHexBuf2Int
* Function:   ��ָ�����ȵ�ʮ�������ַ�������תΪint����
* Input:
*   @pucBuffer   �����������
*   @iLen        ָ���ĳ���
* Output:
*   ��
*
* Return:       ת�������������
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertHexBuf2Int(unsigned char *pucBuffer, int iBufferLen)
{
    register unsigned int  rv = 0, i;
    register unsigned char *ptr;

    ptr = pucBuffer;

    for(i = 0; i < (unsigned int)iBufferLen; i++, ptr++)
    {
        rv = rv * 16 + (((*ptr = toupper(*ptr)) > '9') ? (*ptr - 'A' + 10) : (*ptr - '0'));
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tools_ConvertDecBuf2Int
* Function:   ��ָ�����ȵ�ʮ�����ַ�������ת��Ϊ����
* Input:
*   @pucBuffer   �����������
*   @iLen        ָ���ĳ���
* Output:
*   ��
*
* Return:       ת�������������
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertDecBuf2Int(unsigned char *pucBuffer, int iBufferLen)
{
    register unsigned int  rv = 0, i;
    register unsigned char *ptr;

    ptr = pucBuffer;

    for(i = 0; i < (unsigned int)iBufferLen; i++, ptr++)
    {
        rv = rv * 10 + (*ptr - '0');
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tools_ConvertUint2Ucbuf
* Function:   ��4�ֽڵ�intת��Ϊunsigned char ���͵�����
* Input:
*   @uiInData   �����������
* Output:
*   @pucOutBuf  ת���������
*
* Return:
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertUint2Ucbuf(unsigned int uiInData, unsigned char *pucOutBuf)
{
    *pucOutBuf ++= (uiInData >> 24) & 0xff;
    *pucOutBuf ++= (uiInData >> 16) & 0xff;
    *pucOutBuf ++= (uiInData >> 8) & 0xff;
    *pucOutBuf ++= uiInData & 0xff;

    return 0;
}

/***************************************************************************
* Subroutine: Tools_AddFieldPan
* Function:   ���ݼ���˺��Ƿ�ʮ�������ݣ�����PIN��ʽ��ӵ��������
* Input:
*   @iPinFmt  PIN���ʽ
*   @pcPan    PAN��
* Output:
*   @pucDst   �����
*
* Return:       �ɹ��򷵻���Ч��PAN���ȣ����򷵻� HAR_PARAM_PAN
* Description:  pinfmt=4, panΪ18N��pinfmt=0��panΪ��Ϊ��ɢ���ӵ���16N��������panΪ12N
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldPan(int iPinFmt, char *pcPan, unsigned char *pucDst)
{
    int rv;
    int iPanLen = strlen(pcPan);

    rv = Tools_CheckNum(pcPan);
    if (rv)
    {
        return HAR_PARAM_PAN;
    }

    /*** panΪ��Ϊ��ɢ���ӵ�����PIN BLOCK�޹� ***/
    if (iPinFmt == PANFMT_DISPER)
    {
        if (iPanLen >= 16)
        {
            memcpy(pucDst, &pcPan[iPanLen - 16], 16);
        }
        else
        {
            memset(pucDst, '0', 16 - iPanLen);
            memcpy(&pucDst[16 - iPanLen], pcPan, iPanLen);
        }
        return 16;
    }

    /*** PIN Format4: �ʺ��򳤶ȱ���Ϊ18�ֽ� ***/
    /*** �����ʺ�������18�����֣�������Ҷ��벢�����X��F ***/
    if (iPinFmt == PANFMT_PIN4)
    {
        if (iPanLen < 18)
        {
            memset(pucDst, 'F', 18);
            memcpy(&pucDst[18 - iPanLen], pcPan, iPanLen);
        }
        else
        {
            memcpy(pucDst, pcPan, 18);
        }

        return 18;
    }

    /*** ����CVVʱ���˺ų��Ȳ��� ***/
    if (iPinFmt == PANFMT_CVV)
    {
        memcpy(pucDst, pcPan, iPanLen);
        return iPanLen;
    }

    /*** ������PIN�����ʽ������LMK����PINʱ��ȡ�˺�����12λ ***/
    memset(pucDst, '0', 12);
    if (iPanLen < 12)
    {
        memcpy(&pucDst[12 - iPanLen], pcPan, iPanLen);
    }
    else
    {
        memcpy(pucDst, pcPan, 12);
    }

    return 12;
}

/***************************************************************************
* Subroutine: Tools_AddFieldKey
* Function:    ����Կ��������Կ������ӵ����������
* Input:
*   @iKeyIdx       ��Կ����
*   @pcKeyCipher   ��Կ����
* Output:
*   @pucDst        �����
*
* Return:       �ɹ�������ӵ����ݳ��ȣ����򷵻� HAR_PARAM_VALUE
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldKey(int iKeyIdx, char *pcKeyCipher, unsigned char *pucDst)
{
    int iKeyCipherLen;

    if(pcKeyCipher == NULL || pcKeyCipher[0] == 0x00)
    {
        if (iKeyIdx <= 0)
        {
            return HAR_PARAM_VALUE;
        }

        TASS_SPRINTF(pucDst, 6, "K%04d", iKeyIdx);
        return 5;
    }

    if(iKeyIdx == 0)
    {
        iKeyCipherLen = Tools_GetFieldKeyLength(pcKeyCipher);
        memcpy(pucDst, pcKeyCipher, iKeyCipherLen);
        return iKeyCipherLen;
    }

    if(iKeyIdx < 0)
    {
        return HAR_PARAM_VALUE;
    }

    TASS_SPRINTF(pucDst, 6, "K%04d", iKeyIdx);
    return 5;
}

/***************************************************************************
* Subroutine: Tools_AddFieldSavedKey
* Function:    ��Ҫ�浽�ڲ�����Կ��������Կ��ʶ��ӵ����������
* Input:
*   @iKeyIdx       ��Կ����
*   @pcKeyLabel    ��Կ��ǩ
* Output:
*   @pucDst        �����
*
* Return:       �ɹ�������ӵ����ݳ��ȣ����򷵻� HAR_PARAM_VALUE
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldSavedKey(int iKeyIdx, char *pcKeyLabel, unsigned char *pucDst)
{
    int iKeyLabelLen;

    if(iKeyIdx <= 0)
    {
        return 0;
    }

    /*** ��Կ����, 4N ***/
    TASS_SPRINTF(pucDst, 6, "K%04d", iKeyIdx);
    pucDst += 5;

    /*** ��Կ��ǩ����, 2N ***/
    if(pcKeyLabel)
    {
        iKeyLabelLen = strlen(pcKeyLabel);
        if(iKeyLabelLen > 16)
        {
            return HAR_PARAM_VALUE;
        }
    }
    else
    {
        iKeyLabelLen = 0;
    }

    TASS_SPRINTF(pucDst, 3, "%02d", iKeyLabelLen);
    pucDst += 2;

    /*** ��Կ��ǩ, nA ***/
    memcpy(pucDst, pcKeyLabel, iKeyLabelLen);

    return iKeyLabelLen + 5 + 2;
}

/***************************************************************************
* Subroutine: Tools_AddFieldDeriveData
* Function:    �����Կ��ɢ��������ɢ�������������
* Input:
*   @iMode          0-ÿ����ɢ����8�ֽڣ�1-ÿ����ɢ����16�ֽ�
*   @iDeriveNum     ��ɢ����
*   @pcDeriveData   ��ɢ����
* Output:
*   @pucDst        �����
*
* Return:       �ɹ�������ӵ����ݳ��ȣ����򷵻� HAR_PARAM_DERIVE_DATA
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldDeriveData(int iMode, int iDeriveNum, char *pcDeriveData, unsigned char *pucDst)
{
    unsigned int uiDeriveDataLen = 0;
    unsigned char *p = pucDst;

    TASS_SPRINTF(p, 3, "%02d", iDeriveNum);
    p += 2;

    if (iMode == 0)
    {
        uiDeriveDataLen = iDeriveNum * 16;
    }
    else
    {
        uiDeriveDataLen = iDeriveNum * 32;
    }

    if(strlen(pcDeriveData) != uiDeriveDataLen)
    {
        return HAR_PARAM_DERIVE_DATA;
    }

    memcpy(p, pcDeriveData, uiDeriveDataLen);

    return uiDeriveDataLen + 2;
}

/***************************************************************************
* Subroutine: Tools_AddFieldSessionData
* Function:    ��ӻỰ��Կģʽ�ͻỰ��Կ�������������
* Input:
*   @iMode          �Ự��Կ����ģʽ
*   @pcSessData     �Ự��Կ����
* Output:
*   @pucDst        �����
*
* Return:       �ɹ��򷵻���Ч��������ݳ���
*               ʧ�ܷ��� HAR_PARAM_SESSION_KEY_DATA
*                       ��HAR_PARAM_SESSION_KEY_MODE
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldSessionData(int iMode, char *pcSessData, unsigned char *pucDst)
{
    unsigned int uiSessDataLen = 0;
    unsigned char *p = pucDst;

    TASS_SPRINTF(p, 3, "%02d", iMode);
    p += 2;

    if(iMode == 0 || iMode == 3 || iMode == 4)
    {
        uiSessDataLen = 0;
    }
    else if( iMode == 1 )
    {
        uiSessDataLen = 16;
    }
    else if(iMode ==2 || iMode == 5)
    {
        uiSessDataLen = 32;
    }
    else
    {
        return HAR_PARAM_SESSION_KEY_MODE;
    }

    if(uiSessDataLen > 0)
    {
        if (strlen(pcSessData) != uiSessDataLen)
        {
            return HAR_PARAM_SESSION_KEY_DATA;
        }
    }

    memcpy(p, pcSessData, uiSessDataLen);

    return 2 + uiSessDataLen;
}

/***************************************************************************
* Subroutine: Tools_GetFieldKeyLength
* Function:   ��ȡ��Կ����
* Input:
*   @pcKeyCipher   ��Կ����
* Output:
*   ��
*
* Return:       ��Կ���ĳ��ȣ������㷨��ʶ��
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_GetFieldKeyLength(char *pcKeyCipher)
{
    char ch = pcKeyCipher[0];

    if (ch == 'X' || ch == 'U' || ch == 'P' || ch == 'R' || ch == 'L')
    {
        return 32+1;
    }

    if (ch == 'Y' || ch == 'T')
    {
        return 48 + 1;
    }

    if (ch == 'Z')
    {
        return 16 + 1;
    }

    return 16;
}

/***************************************************************************
* Subroutine: Tools_GetFieldDerBufLength
* Function:   ��ȡDER��������ݳ���
* Input:
*   @pucDst          ��������
* Output:
*   ��
*
* Return:       �ɹ��򷵻���Ч���ݳ���
*               ʧ�ܷ��� HAR_DER_DECODE
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_GetFieldDerBufLength(unsigned char *pucDst)
{
    if(pucDst[0] != 0x30)
    {
        return HAR_DER_DECODE;
    }

    if(pucDst[1] == 0x81)
    {
        return pucDst[2] + 3;
    }

    if(pucDst[1] == 0x82)
    {
        return pucDst[2] * 256 + pucDst[3] + 4;
    }

    if(pucDst[1] == 0x59)
    {
        return pucDst[1] + 2;
    }

    return HAR_DER_DECODE;
}

/***************************************************************************
* Subroutine: Tools_PrintBuf
* Function:   ��ʮ�����ƴ�ӡ������
* Input:
*   @pucDst   ����ӡ������
* Output:
*   ��
*
* Return:
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
void Tools_PrintBuf(char *pcTitle, unsigned char *pucBuf, int iBufLen)
{
    int i;

    printf("%s[%d]:\n", pcTitle, iBufLen);

    for(i = 0; i < iBufLen; i++)
    {
        printf("%02X", pucBuf[i]);
        if ( i % 32 == 31)
        {
            printf("\n");
        }
    }

    printf("\n");

    return;
}

/***************************************************************************
* Subroutine: Tools_ConvertToupper
* Function:   ��Сд���ַ�ת��Ϊ��д
* Input:
*   @pcInData   ��������ַ���
* Output:
*   ��
*
* Return:
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
void Tools_ConvertToupper(char *pcInData)
{
    int i;
    for(i = 0; i < strlen(pcInData); i++)
    {
        pcInData[i] = toupper(pcInData[i]);
    }
}

/***************************************************************************
* Subroutine: Tools_ConvertByte2HexStr
* Function:   ���ֽ�����ת��Ϊʮ�������ַ���
* Input:
*   @pucInBuf    �������ֽ�����
*   @iInBufLen   ����������ݵ��ֽ���
* Output:
*   @pcOutBuf    ת�����ʮ�������ַ���
*
* Return:       �ɹ�����ʮ�������ַ������ȣ� ʧ�ܷ���-1
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertByte2HexStr(unsigned char *pucInBuf, int iInBufLen, char *pcOutBuf)
{
    int rv = HAR_OK;
    unsigned char ch;
    register int i, active = 0;

    iInBufLen *= 2;

    for(i = 0; i < iInBufLen; i++)
    {
        ch = *pucInBuf;
        if (active)
        {
            (*pcOutBuf = (ch & 0x0F)) < 10 ? (*pcOutBuf += '0') : (*pcOutBuf += ('A' - 10));
            pucInBuf++;
        }
        else
        {
            (*pcOutBuf = (ch & 0xF0) >> 4) < 10 ? (*pcOutBuf += '0') : (*pcOutBuf += ('A' - 10));
        }

        active ^= 1;

        if (!isxdigit(*pcOutBuf))
        {
            rv = -1;
            break;
        }

        pcOutBuf++;
    }

    *pcOutBuf = 0x00;

    return iInBufLen;
}

/***************************************************************************
* Subroutine: Tools_ConvertHexStr2Byte
* Function:   ��ʮ�������ַ���ת��Ϊ�ֽ�����
* Input:
*   @pcInBuf    ��������ַ���
*   @iInBufLen  ��������ַ�������
* Output:
*   @pucOutBuf  ������ֽ�����
*
* Return:
* Description: �ɹ�����ת������ֽ����� ʧ�ܷ���-1
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertHexStr2Byte(char *pcInBuf, int iInBufLen, unsigned char *pucOutBuf)
{
    int              rv = HAR_OK;
    int              len = iInBufLen / 2;
    register int     iActive = 0;
    char             cCharIn;
    unsigned char    cCharOut;

    if(iInBufLen % 2 != 0)
    {
        return -1;
    }

    rv = Tools_CheckHex(pcInBuf);
    if(rv)
    {
        return -1;
    }

    for( ; iInBufLen > 0; iInBufLen--, pcInBuf++)
    {
        cCharIn = *pcInBuf;

        if(cCharIn > '9')
        {
            cCharIn += 9;
        }

        cCharOut = *pucOutBuf;
        if(iActive)
        {
            *pucOutBuf++ = (unsigned char)((cCharOut & 0xF0) | (cCharIn & 0x0F));
        }
        else
        {
            *pucOutBuf = (unsigned char)((cCharOut & 0x0F) | ((cCharIn & 0x0F) << 4));
        }
        iActive ^= 1;
    }

    return len;
}

/***************************************************************************
* Subroutine: Tools_Padding_0
* Function:   ��ǿ�����0x80
* Input:
*   @pcInData    ��������ַ�����ʮ�����ƣ�
* Output:
*   @pcOutData   ���������
*
* Return:       �ɹ�����0�� ʧ�ܷ���-1
* Description:  ���������Ϊ16�ı�����ʮ�����ƣ�
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_Padding_0(char *pcInData, char *pcOutData/*out*/)
{
    int iInDataLen = 0;
    int iResidue = 0;
    char pcPaddingData[16 + 1] = "8000000000000000";

    if(pcInData == NULL || pcOutData == NULL)
    {
        return -1;
    }

    iInDataLen = strlen(pcInData);
    if(iInDataLen % 2 != 0)
    {
        return -1;
    }

    iResidue = 16 - iInDataLen % 16;
    if(iResidue != 16)
    {
        strcpy(pcOutData, pcInData);
        strncat(pcOutData + iInDataLen, pcPaddingData, iResidue);
    }
    else
    {
        strcpy(pcOutData, pcInData);
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CycleXorHexStr
* Function:   ��ʮ�������ַ�����ָ�����鳤��ѭ�����
* Input:
*   @iMode       ����ģʽ�� 0-��8�ֽ����   1-��16�ֽ����
*   @pcInData    ��������ַ���
* Output:
*   @pcOutData   ���������
*
* Return:       �ɹ�����0�� ʧ�ܷ���-1
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CycleXorHexStr(int iMode, char *pcInData, char *pcOutData/*out*/)
{
    int rv = HAR_OK;
    int i, j;
    int iBlockNum = 0;
    int iBlockLen = 0;
    unsigned char pucData[256] = {0};
    unsigned char pucResult[16] = {0};
    unsigned char pucNextDataBlock[16] = {0};
    int iInDataLen = strlen(pcInData);

    if(pcInData == NULL || pcOutData == NULL || iInDataLen > 512)
    {
        return -1;
    }

    switch(iMode)
    {
        case 0:
            iBlockLen = 8;
            break;
        case 1:
            iBlockLen = 16;
            break;
        default:
            return -1;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, iInDataLen, pucData);
    if(iInDataLen == -1 || iInDataLen % iBlockLen != 0)
    {
        return -1;
    }

    iBlockNum = iInDataLen / iBlockLen;

    for(i = 0; i < iBlockNum; i++)
    {
        memcpy(pucNextDataBlock, pucData + i * iBlockLen, iBlockLen);
        for(j = 0; j < iBlockLen; j++)
        {
            pucResult[j] ^= pucNextDataBlock[j];
        }
    }

    rv = Tools_ConvertByte2HexStr(pucResult, iBlockLen, pcOutData);
    if(rv == -1)
    {
        return rv;
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CycleXorHexStr
* Function:   �Զ��������ݰ�ָ�����鳤��ѭ�����
* Input:
*   @iMode       ����ģʽ�� 0-��8�ֽ����   1-��16�ֽ����
*   @pucInData   ��������ֽ�����
*   @iInDataLen  ��������ֽ����鳤��
* Output:
*   @pucOutData   ���������
*
* Return:       �ɹ�����0�� ʧ�ܷ���-1
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CycleXorByteArray(int iMode, unsigned char *pucInData, int iInDataLen, unsigned char *pucOutData/*out*/)
{
    int rv = HAR_OK;
    int i, j;
    int iBlockNum = 0;
    int iBlockLen = 0;
    unsigned char pucResult[16] = {0};
    unsigned char pucNextDataBlock[16] = {0};

    if(pucInData == NULL || pucOutData == NULL)
    {
        return -1;
    }

    switch(iMode)
    {
        case 0:
            iBlockLen = 8;
            break;
        case 1:
            iBlockLen = 16;
            break;
        default:
            return -1;
    }

    if(iInDataLen % iBlockLen != 0)
    {
        return -1;
    }

    iBlockNum = iInDataLen / iBlockLen;

    for(i = 0; i < iBlockNum; i++)
    {
        memcpy(pucNextDataBlock, pucInData + i * iBlockLen, iBlockLen);
        for(j = 0; j < iBlockLen; j++)
        {
            pucResult[j] ^= pucNextDataBlock[j];
        }
    }

    memcpy(pucOutData, pucResult, iBlockLen);

    return rv;
}

/***************************************************************************
* Subroutine: Tools_GenDeriveData
* Function:   �����ɢ����
* Input:
*   @pcInData    ����������ݣ�Ҫ�󳤶�Ϊ16H
* Output:
*   @pcOutData   �����ķ�ɢ���� 32H
*
* Return:       �ɹ�����0�� ʧ�ܷ���-1
* Description:  ���ڼ��㽫ʮ�����Ƶ����ݽ���ȡ����Ȼ��ԭ������ȡ��������ݽ���ƴ�ӣ�
*               �γ�һ����ɢ���ӡ�
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_GenDeriveData(char *pcInData, char *pcOutData/*out*/)
{
    int iInDataLen = strlen(pcInData);
    int rv = HAR_OK;
    char pcTmpData[32 + 1] = {0};
    char pcNotData[16 + 1] = {0};

    if( pcInData == NULL || strlen(pcInData) != 16 || pcOutData == NULL )
    {
        return -1;
    }

    strcpy(pcTmpData, pcInData);
    strcat(pcTmpData, "FFFFFFFFFFFFFFFF");

    /*** ��8�ֽ���� ***/
    rv = Tools_CycleXorHexStr(1, pcTmpData, pcNotData/*out*/);
    if(rv == -1)
    {
        return rv;
    }

    strcpy(pcOutData, pcInData);
    strcat(pcOutData, pcNotData);

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckSchemeValidity
* Function:   ����㷨��ʶ��Ч��
* Input:
*   @cScheme  �㷨��ʶ
* Output:
*   ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:  ��ʱ��֧��AES�㷨
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckSchemeValidity(char cScheme)
{
    switch(cScheme)
    {
        case 'Z':
        case 'U':
        case 'T':
        case 'X':
        case 'Y':
        case 'P':
        case 'R':
            break;
        default:
            return HAR_PARAM_KEY_SCHEME;
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity
* Function:   �����Կ��Ϣ��Ч��
* Input:
*   @iKeyIdx            ��Կ����
*   @pcKeyCipherByLmk   ��Կ����
* Output:
*   @pcOutData          ��������Կ���ģ����㷨��ʶ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:  ��ʱ��֧��AES�㷨
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity(int iKeyIdx, char *pcKeyCipherByLmk, char *pcOutData)
{
    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) != 16
                && strlen(pcKeyCipherByLmk) != 17
                && strlen(pcKeyCipherByLmk) != 33
                && strlen(pcKeyCipherByLmk) != 49)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) == 16)
        {
            strcpy(pcOutData, "Z");
            strcat(pcOutData, pcKeyCipherByLmk);
        }
        else
        {
            strcpy(pcOutData, pcKeyCipherByLmk);
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity_1
* Function:   �����Կ��Ϣ��Ч��
* Input:
*   @iKeyIdx            ��Կ����
*   @pcKeyCipherByLmk   ��Կ����
* Output:
*   ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:  ����Կ����ֵΪ0ʱ����Կ���ĳ����Ƿ�Ϊ16,33��49,��������򱨴�
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity_1(int iKeyIdx, char *pcKeyCipherByLmk)
{
    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) != 16 && strlen(pcKeyCipherByLmk) != 33 && strlen(pcKeyCipherByLmk) != 49)
        {
            return HAR_PARAM_KEY_CIPHER;
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity_2
* Function:   �����Կ��Ϣ��Ч��
* Input:
*   @iKeyIdx            ��Կ����
*   @pcKeyCipherByLmk   ��Կ����
* Output:
*   ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:  ����Կ����ֵΪ0ʱ����Կ���ĳ����Ƿ�Ϊ17,33��49,��������򱨴�
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity_2(int iKeyIdx, char *pcKeyCipherByLmk)
{
    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) != 17 && strlen(pcKeyCipherByLmk) != 33 && strlen(pcKeyCipherByLmk) != 49)
        {
            return HAR_PARAM_KEY_CIPHER;
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity_3
* Function:   �����Կ��Ϣ��Ч��
* Input:
*   @iKeyIdx            ��Կ����
*   @pcKeyCipherByLmk   ��Կ����
* Output:
*   @pcOutData          ��������Կ���ģ����㷨��ʶ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:  ��Կ���ĳ���ֻ֧��32��33H��������Ϊ32Hʱ��������㷨��ʶX
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity_3(int iKeyIdx, char *pcKeyCipherByLmk, char *pcOutData)
{
    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) != 32 && strlen(pcKeyCipherByLmk) != 33)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) == 32)
        {
            strcpy(pcOutData, "X");
            strcat(pcOutData + 1, pcKeyCipherByLmk);
        }
        else
        {
            strcpy(pcOutData, pcKeyCipherByLmk);
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckSessionKeyDataValidity
* Function:   ���Ự��Կ����ģʽ�����ݵ���Ч��
* Input:
*   @iSessionKeyMode           �Ự��Կ����ģʽ
*   @pcSessionKeyData          �Ự��Կ����
* Output:
*   ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckSessionKeyDataValidity(int iSessionKeyMode, char *pcSessionKeyData)
{
    if(iSessionKeyMode != 0
            && iSessionKeyMode != 1
            && iSessionKeyMode != 2
            && iSessionKeyMode != 3
            && iSessionKeyMode != 4
            && iSessionKeyMode != 5)
    {
        LOG_ERROR("Parameter iSessionKeyMode = [%d] is invalid. It must be 00, 01, 02, 03, 04 or 05.",
                iSessionKeyMode);
        return HAR_PARAM_SESSION_KEY_MODE;
    }

    if(iSessionKeyMode == 0 || iSessionKeyMode == 3 || iSessionKeyMode == 4)
    {
        return HAR_OK;
    }

    if(pcSessionKeyData == NULL)
    {
        LOG_ERROR("Parameter pcSessionKeyData = [%s] is invalid.", "NULL");
        return HAR_PARAM_SESSION_KEY_DATA;
    }

    if(iSessionKeyMode == 1)
    {
        if(strlen(pcSessionKeyData) != 16)
        {
            LOG_ERROR("Parameter pcSessionKeyData length = [%d] is invalid. It must be 16 characters.",
                    strlen(pcSessionKeyData));
            return HAR_PARAM_SESSION_KEY_DATA;
        }
    }
    else
    {
        if(strlen(pcSessionKeyData) != 32)
        {
            LOG_ERROR("Parameter pcSessionKeyData length = [%d] is invalid. It must be 32 characters.",
                    strlen(pcSessionKeyData));
            return HAR_PARAM_SESSION_KEY_DATA;
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckPaddingModeValidity
* Function:   ����������ģʽ����Ч��
* Input:
*   @iPaddingMode           �������ģʽ
* Output:
*   ��
*
* Return:       �ɹ�����0�� ʧ�ܷ�������
* Description:
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckPaddingModeValidity(int iPaddingMode)
{
    switch(iPaddingMode)
    {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 10:
        case 11:
            return HAR_OK;
        default:
            return HAR_PARAM_PADDING_MODE;
    }

    return HAR_OK;
}

/***************************************************************************
 * * Subroutine: Tools_Der
 * * Function:   ��RSA��Կ��ģ��ָ��������DER����
 * * Input:
 * *   @N           ģ
 * *   @E           ָ����ʮ�����ƣ�
 * * Output:
 * *   @pubkeyDer   ��Կ
 * *   @pubkeyDerLen��Կ����
 * *
 * * Return:       �ɹ�����0�� ʧ�ܷ�������
 * * Description:
 * *
 * * Date:         2015.06.08
 * * Author:       Luo Cangjian
 * * ModifyRecord:
 * * *************************************************************************/
int Tools_Der(char *N, char *E, unsigned char *pubkeyDer,int *pubkeyDerLen)
{
   int rv = HAR_OK;
   unsigned char modulus[512] = {0};
   unsigned char pubExp[12] = {0};
   //int pubkeyDerLen = 512 + 32;

    int modulusLen = Tools_ConvertHexStr2Byte(N, strlen(N), modulus);
    if(modulusLen == -1)
    {
        printf("Tools_ConvertHexStr2Byte error\n");
    }

    int pubExpLen = Tools_ConvertHexStr2Byte(E, strlen(E), pubExp);
    if(pubExpLen == -1)
    {
        printf("Tools_ConvertHexStr2Byte error\n");
    }

    rv = Der_Pubkey_Pkcs1(
            modulus,
            modulusLen,
            pubExp,
            pubExpLen,
            pubkeyDer,
            pubkeyDerLen);
    if(rv)
    {
        printf("der coding return code = [%#010X].\n", rv);
    }
  return rv;
}

/***************************************************************************
 * Subroutine: Tools_DDer
 * Function:   ��Der����Ĺ�Կ���룬����ģ��ָ��
 * Input:
 *   @pubkeyDer      Der����
 *   @pubkeyDerLen   Der��
 * Output
 *   @ppmodulus      ģ
 *   @modulusLen     ģ��
 *   @pppubExp       ָ��
 *   @pubExpLen      ָ������
 * Output:
 *   @pubkeyDer   ��Կ
 *
 * Return:       �ɹ�����0�� ʧ�ܷ�������
 * Description:
 *
 * Date:         2015.06.08
 * Author:       Luo Cangjian
 * ModifyRecord:
 * *************************************************************************/
int Tools_DDer(unsigned char *pubkeyDer, unsigned char *ppmodulus,
               int *modulusLen, unsigned char *pppubExp, int *pubExpLen)
{
     int rv = HAR_OK;
     int len = Tools_ConvertHexStr2Byte(pubkeyDer, strlen(pubkeyDer), pubkeyDer);
     
     unsigned char *pM = NULL;
     unsigned char *pE = NULL;
    
     rv = DDer_Pubkey_Pkcs1(
			pubkeyDer, len,
			&pM, &modulusLen,
                        &pE, &pubExpLen   
			);
//printf("*****%s\n",pM);
//Tools_PrintBuf("++++",pM,modulusLen);
//Tools_PrintBuf("++++",pE,pubExpLen);

modulusLen = Tools_ConvertByte2HexStr(pM,modulusLen,ppmodulus);
pubExpLen = Tools_ConvertByte2HexStr(pE,pubExpLen,pppubExp);
//printf("_+_+_+_+:%s\n",ppmodulus);
//printf("_+_+_+_+:%s\n",pppubExp);
   return rv;
}

/***************************************************************************
* Subroutine: Tools_ReadBuf
* Function:   ��ʮ�����ƶ�ȡ����������
* Input:
*   @pucDst   ����ȡ������
* Output:
*   @BufData  ��ȡ�������ݣ�ʮ�����ƣ�
* 
* Return:     ����BufData�ĳ���
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ReadBuf(unsigned char *pucBuf, int iBufLen, unsigned char *BufData/*out*/)
{
    Tools_ConvertByte2HexStr(pucBuf,iBufLen,BufData);
    return strlen(BufData);
}


