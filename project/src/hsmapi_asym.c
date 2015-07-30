/*----------------------------------------------------------------------|
|    hsmapi_asym.c                                                      |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310������ӿڷǶԳ��㷨���������              |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-04. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#endif

#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmapi_init.h"
#include "hsmapi_asym.h"

/*
 * HSM_SM2_GenerateNewKeyPair, ����һ���µ�SM2��Կ��
 * iKeyIndex            IN        Ҫ������SM2��Կ������<=0��=9999ʱ��ʶ���洢
 * pcKeyLabel           IN        SM2��Կ��ǩ������iKeyIndex>0��!=9999ʱ��Ч;
 * pucDerPublicKey      OUT       �����ɵ�SM2��Կ��DER����
 * piDerPublicKeyLen    OUT       �����ɵ�SM2��Կ����
 * pucPrivateKey_Lmk    OUT       LMK�¼��ܵ�SM2˽Կ����
 * piPrivateKeyLen_Lmk  OUT       LMK�¼��ܵ�SM2˽Կ���ĳ���
 */
int HSM_SM2_GenerateNewKeyPair(
    void *hSessionHandle,  int iKeyIndex, char *pcKeyLabel,
    unsigned char *pucDerPublicKey, int *piDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int *piPrivateKeyLen_Lmk )
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 512;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[512] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "E7" ***/
    *p ++ = 'E';
    *p ++ = '7';

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** �ڲ��洢����Կ, ��Կ��������ǩ���ȡ���ǩ ***/
    rv = Tools_AddFieldSavedKey(iKeyIndex, pcKeyLabel, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ��Կ, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    if(piDerPublicKeyLen)
    {
        *piDerPublicKeyLen = len;
    }
    if(pucDerPublicKey)
    {
        memcpy(pucDerPublicKey, p, len);
    }
    p += len;

    /*** ˽Կ����, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    if (piPrivateKeyLen_Lmk)
    {
        *piPrivateKeyLen_Lmk = len;
    }
    p += 4;

    /*** LMK���ܵ�˽Կ����, nB ***/
    if (pucPrivateKey_Lmk)
    {
        memcpy(pucPrivateKey_Lmk, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_LoadKeyPair, װ��һ��SM2��Կ�Ե�������ڴ洢
 * iKeyIndex            IN        Ҫ�����SM2��Կ����
 * pcKeyLabel           IN        Ҫ�����SM2��Կ��ǩ
 * pucDerPublicKey      IN        Ҫ�����SM2��Կ��DER����
 * piDerPublicKeyLen    IN        Ҫ�����SM2��Կ����
 * pucPrivateKey_Lmk    IN        LMK�¼��ܵ�SM2˽Կ����
 * piPrivateKeyLen_Lmk  IN        LMK�¼��ܵ�SM2˽Կ���ĳ���
 */
int HSM_SM2_LoadKeyPair(
    int iKeyIndex, char *pcKeyLabel,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk)
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "E1" ***/
    *p ++ = 'E';
    *p ++ = '1';

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** ��Կ, nB ***/
    memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
    p += iDerPublicKeyLen;

    /*** ˽Կ����, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
    p += 4;

    /*** LMK���ܵ�˽Կ����, nB ***/
    memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
    p += iPrivateKeyLen_Lmk;

    /*** ��Կ����, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iKeyIndex);
    p += 4;

    /*** ��ǩ����, 2N ***/
    if (!pcKeyLabel)
    {
        len = 0;
    }
    else
    {
        len = strlen(pcKeyLabel);
    }

    TASS_SPRINTF((char*)p, 3, "%02d", len);
    p += 2;

    /*** ��ǩ, 0-16A ***/
    memcpy(p, pcKeyLabel, len);
    p += len;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/*
 * HSM_SM2_GetPublicKey, ��ȡһ��SM2��Կ�Ĺ�Կ
 * iKeyIndex            IN        Ҫ������Կ��SM2��Կ����
 * pucDerPublicKey      OUT       ������SM2��Կ��DER����
 * piDerPublicKeyLen    OUT       ������SM2��Կ����
 */
int HSM_SM2_GetPublicKey( int iKeyIndex, unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "E2" ***/
    *p ++ = 'E';
    *p ++ = '2';

    /*** ��Կ����, K+4N ***/
    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ��Կ, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    if (piDerPublicKeyLen)
    {
        *piDerPublicKeyLen = len;
    }
    if (pucDerPublicKey)
    {
        memcpy(pucDerPublicKey, p, len);
    }

    return rv;
}

/*
 * HSM_SM2_EncryptData, SM2��Կ��������
 * iKeyIndex            IN        SM2��Կ������<=0��=9999ʱ����2��������Ч
 * pucDerPublicKey      IN        DER�����SM2��Կ����iKeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen     IN        DER�����SM2��Կ���ȣ���iKeyIndex=9999ʱ��Ч
 * pucInput             IN        Ҫ���ܵ��������ݣ����֧��136�ֽڵļ�������
 * iInputLength         IN        Ҫ���ܵ��������ݳ��ȣ����136
 * pucOutput            OUT       ���ܺ���������
 * piOutputLength       OUT       ���ܺ��������ݳ���
 */
int HSM_SM2_EncryptData(void *hSessionHandle,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 1900 + 128;
    unsigned char aucCmd[1900 + 256] = {0};
    unsigned char aucRsp[1900 + 128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1900)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1900.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E3" ***/
    *p ++ = 'E';
    *p ++ = '3';

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** ���ݿ鳤��, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** ���ݿ�, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ��Կ����, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    /*** ��ԿDER���� ***/
    if (iKeyIndex == 9999)
    {
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;
    }

    /*** ���ı����ʽ, 1N, 0 �C ���Ĵ���hash���������� ***/
    *p ++ = '0';

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ���ĳ���, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piOutputLength)
    {
        *piOutputLength = len;
    }

    /*** ��������, nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_DecryptData, SM2˽Կ��������
 * iKeyIndex            IN        SM2��Կ������<=0��=9999ʱ����2��������Ч
 * pucPrivateKey_Lmk    IN        LMK���ܵ�SM2˽Կ����iSm2KeyIndex=9999ʱ��Ч
 * iPrivateKeyLen_Lmk   IN        LMK���ܵ�SM2˽Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucInput             IN        Ҫ���ܵ���������
 * iInputLength         IN        Ҫ���ܵ��������ݳ���
 * pucOutput            OUT       ���ܺ���������
 * piOutputLength       OUT       ���ܺ��������ݳ���
 */
int HSM_SM2_DecryptData(void *hSessionHandle,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 1996 + 128;
    unsigned char aucCmd[1996 + 256] = {0};
    unsigned char aucRsp[1996 + 128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1996)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1996.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E4" ***/
    *p ++ = 'E';
    *p ++ = '4';

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** ���ı����ʽ, 1N, 0 �C ���Ĵ���hash���������У� ***/
    *p ++ = '0';

    /*** ���ݿ鳤��, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** ���ݿ�, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ��Կ����, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** ˽Կ����, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK���ܵ�����˽Կ����, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ������ݳ���, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piOutputLength)
    {
        *piOutputLength = len;
    }

    /*** �������, nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_GenerateSignature, SM2˽Կ�����ݽ�������ǩ��
 * iKeyIndex            IN        SM2��Կ������<=0��=9999ʱ����4��������Ч
 * pucDerPublicKey      IN        DER�����SM2��Կ����iKeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen     IN        DER�����SM2��Կ���ȣ���iKeyIndex=9999ʱ��Ч
 * pucPrivateKey_Lmk    IN        LMK���ܵ�SM2˽Կ����iSm2KeyIndex=9999ʱ��Ч
 * iPrivateKeyLen_Lmk   IN        LMK���ܵ�SM2˽Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucUserId            IN        �û���ʶ
 * iUserIdLength        IN        �û���ʶ����
 * pucInput             IN        ��ǩ������������
 * iInputLength         IN        ��ǩ�����������ݳ���
 * pucSignature         OUT       ���������ǩ��
 * piSignatureLength    OUT       ���������ǩ������
 */
int HSM_SM2_GenerateSignature(
    int iKeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucUserId, int iUserIdLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1984 + 256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E5" ***/
    *p ++ = 'E';
    *p ++ = '5';

    /*** HASH�㷨��ʶ, 2N, 20 �C SM3 ***/
    *p ++ = '2';
    *p ++ = '0';

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** �û���ʶ����, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iUserIdLength);
    p += 4;

    /*** �û���ʶ, nB ***/
    memcpy(p, pucUserId, iUserIdLength);
    p += iUserIdLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ���ݿ鳤��, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** ���ݿ�, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ��Կ����, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** DER�����SM2��Կ, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;

        /*** ˽Կ����, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK���ܵ�����˽Կ����, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    /*** ǩ�������ʽ, 1N, 0 �C ǩ��ֵ���ݴ���r��s���У� ***/
    *p ++ = '0';

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ����ǩ������, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piSignatureLength)
    {
        *piSignatureLength = len;
    }

    /*** �������, nB ***/
    if(pucSignature)
    {
        memcpy(pucSignature, p, len);
    }

    return HAR_OK;
}

int HSM_SM2_VerifySignature(
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucUserId, int iUserIdLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature, int iSignatureLength )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 8;
    unsigned char aucCmd[1984 + 512] = {0};
    unsigned char aucRsp[8] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E6" ***/
    *p ++ = 'E';
    *p ++ = '6';

    /*** HASH�㷨��ʶ, 2N, 20 �C SM3 ***/
    *p ++ = '2';
    *p ++ = '0';

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** �û���ʶ����, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iUserIdLength);
    p += 4;

    /*** �û���ʶ, nB ***/
    memcpy(p, pucUserId, iUserIdLength);
    p += iUserIdLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ǩ�������ʽ, 1N, 0 �C ǩ��ֵ���ݴ���r��s���У� ***/
    *p ++ = '0';

    /*** ����ǩ��ǩ������, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iSignatureLength);
    p += 4;

    /*** ����ǩ��ǩ��, nB ***/
    memcpy(p, pucSignature, iSignatureLength);
    p += iSignatureLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ���ݿ鳤��, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** ���ݿ�, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ��Կ����, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** DER�����SM2��Կ, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/*
 * HSM_SM2_ExportByTK, ������Կ��KEK/MDK���ɷ�ɢ�ɲ���ɢ����������һ��SM2��Կ��
 * iMode                IN        0�CECB, 1�CCBC
 * pcTkType             IN        "000"�CKEK;  "109"�CMDK;
 * iTkIndex             IN        <=0, ʹ��pcTk_Lmk����������ʹ������ָ������Կ
 * pcTk_Lmk             IN        ��iTkIndex<=0ʱ��Ч
 * iTkDeriveNumber      IN        ������Կ�ķ�ɢ����
 * pcTkDeriveData       IN        ������Կ�ķ�ɢ���ӣ�ÿ��32H
 * iSm2KeyIndex         IN        Ҫ��������SM2��Կ������<=0��=9999ʱ����4��������Ч
 * pucDerPublicKey      IN        DER�����SM2��Կ����iSm2KeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen     IN        DER�����SM2��Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucPrivateKey_Lmk    IN        LMK���ܵ�SM2˽Կ����iSm2KeyIndex=9999ʱ��Ч
 * iPrivateKeyLen_Lmk   IN        LMK���ܵ�SM2˽Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucPrivateKey_Tk     OUT       ������Կ���ܵ�SM2˽Կ����
 * piPrivateKeyLen_Tk   OUT       ������Կ���ܵ�SM2˽Կ���ĳ���
 */
int HSM_SM2_ExportByTK(
    void *hSessionHandle,
    int iMode, char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iSm2KeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucPrivateKey_Tk, int *piPrivateKeyLen_Tk/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TT" ***/
    *p ++ = 'T';
    *p ++ = 'T';

    /*** �����㷨ģʽ, 2N, 00 �C ECB, 01 �C CBC ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** ������Կ����, 3H, "000"�CKEK;  "109"�CMDK ***/
    memcpy(p, pcTkType, 3);
    p += 3;

    /*** ������Կ ***/
    rv = Tools_AddFieldKey(iTkIndex, pcTk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iTkIndex = [%d] is invalid.", iTkIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ������Կ��ɢ��������ɢ����, 2H+n*32H ***/
    rv = Tools_AddFieldDeriveData(1, iTkDeriveNumber, pcTkDeriveData, (char*)p);
    if (rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("Parameter: pcTkDeriveData's length = [%d] is invalid.", strlen(pcTkDeriveData));
        return HAR_PARAM_DERIVE_DATA;
    }
    p += rv;

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** ��Կ����, 4N ***/
    if(iSm2KeyIndex <= 0)
    {
        iSm2KeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iSm2KeyIndex);
    p += 4;

    if(iSm2KeyIndex == 9999)
    {
        /*** DER�����SM2��Կ, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;

        /*** ˽Կ����, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK���ܵ�����˽Կ����, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ��Կ�� ASN.1 ��ʽDER ����, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    p += len;

    /*** ������Կ���ܵ�˽Կ����d���ĳ���, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKeyLen_Tk)
    {
        *piPrivateKeyLen_Tk = len;
    }

    /*** ������Կ���ܵ�˽Կ����d����, nB ***/
    if(pucPrivateKey_Tk)
    {
        memcpy(pucPrivateKey_Tk, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_ImportByTK, ������Կ��KEK/MDK���ɷ�ɢ�ɲ���ɢ����������һ��SM2��Կ��
 * iMode                   IN        0�CECB, 1�CCBC
 * pcTkType                IN        "000"�CKEK;  "109"�CMDK;
 * iTkIndex                IN        <=0, ʹ��pcTk_Lmk����������ʹ������ָ������Կ
 * pcTk_Lmk                IN        ��iTkIndex<=0ʱ��Ч
 * iTkDeriveNumber         IN        ������Կ�ķ�ɢ����
 * pcTkDeriveData          IN        ������Կ�ķ�ɢ���ӣ�ÿ��32H
 * iSm2KeyIndex            IN        Ҫ��������SM2��Կ������<=0��=9999ʱ����4��������Ч
 * pucDerPublicKey         IN        DER�����SM2��Կ����iSm2KeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen        IN        DER�����SM2��Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucPrivateKey_Lmk       IN        LMK���ܵ�SM2˽Կ����iSm2KeyIndex=9999ʱ��Ч
 * iPrivateKeyLen_Lmk      IN        LMK���ܵ�SM2˽Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucPrivateKey_Tk        OUT       ������Կ���ܵ�SM2˽Կ����
 * piPrivateKeyLen_Tk      OUT       ������Կ���ܵ�SM2˽Կ���ĳ���
 */
int HSM_SM2_ImportByTK(
    int iMode, char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iSm2KeyIndex, char *pcSm2KeyLabel,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Tk, int iPrivateKeyLen_Tk,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TU" ***/
    *p ++ = 'T';
    *p ++ = 'U';

    /*** �����㷨ģʽ, 2N, 00 �C ECB, 01 �C CBC ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** ������Կ����, 3H, "000"�CKEK;  "109"�CMDK ***/
    memcpy(p, pcTkType, 3);
    p += 3;

    /*** ������Կ ***/
    rv = Tools_AddFieldKey(iTkIndex, pcTk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iTkIndex = %d is invalid.", iTkIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ������Կ��ɢ��������ɢ����, 2H+n*32H ***/
    rv = Tools_AddFieldDeriveData(1, iTkDeriveNumber, pcTkDeriveData, p);
    if (rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("Parameter: pcTkDeriveData's length = [%d] is invalid.", strlen(pcTkDeriveData));
        return HAR_PARAM_DERIVE_DATA;
    }
    p += rv;

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** ��Կ����, 4N ***/
    if (iSm2KeyIndex <= 0)
    {
        iSm2KeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iSm2KeyIndex);
    p += 4;

    /*** DER�����SM2��Կ, nB ***/
    memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
    p += iDerPublicKeyLen;

    /*** ������Կ���ܵ�SM2˽Կ����d���ĳ���, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Tk);
    p += 4;

    /*** ������Կ���ܵ�SM2˽Կ����d����, nB ***/
    memcpy(p, pucPrivateKey_Tk, iPrivateKeyLen_Tk);
    p += iPrivateKeyLen_Tk;

    if(iSm2KeyIndex != 9999)
    {
        /*** ��ǩ���ȣ�2N ***/
        if (!pcSm2KeyLabel)
        {
            len = 0;
        }
        else
        {
            len = strlen(pcSm2KeyLabel);
        }

        TASS_SPRINTF((char*)p, 3, "%02d", len);
        p += 2;

        /*** ��Կ��ǩ��nA ***/
        memcpy(p, pcSm2KeyLabel, len);
        p += len;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK���ܵ�˽Կ���ĳ���, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKeyLen_Lmk)
    {
        *piPrivateKeyLen_Lmk = len;
    }

    /*** LMK���ܵ�˽Կ����, nB ***/
    if(pucPrivateKey_Lmk)
    {
        memcpy(pucPrivateKey_Lmk, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_GeneratePublicKeyMac, ����Ȩ������ΪSM2��Կ������ԿMAC
 * pucDerPublicKey      IN        Ҫ����MAC��SM2��Կ��DER����
 * iDerPublicKeyLen     IN        Ҫ����MAC��SM2��Կ����
 * pucAuthData          IN        ��Կ�������ݣ����ܴ�';'�ַ�
 * iAuthDataLen         IN        ��Կ�������ݳ���
 * pucMac               OUT       SM2��Կ��MACֵ
 * piMacLen             OUT       SM2��Կ��MACֵ����
 */
int HSM_SM2_GeneratePublicKeyMac(
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac/*out*/, int *piMacLen/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TQ" ***/
    *p ++ = 'T';
    *p ++ = 'Q';

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** DER�����SM2��Կ, nB ***/
    memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
    p += iDerPublicKeyLen;

    /*** ���ڼ��㹫ԿMAC�Ķ�������ݣ����ܰ����ַ���;����, nB ***/
    memcpy(p, pucAuthData, iAuthDataLen);
    p += iAuthDataLen;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%#010X].", rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ʹ��LMK����Թ�Կ����֤���ݼ����MAC��4B ***/
    if(piMacLen)
    {
        *piMacLen = 4;
    }

    if(pucMac)
    {
        memcpy(pucMac, p, 4);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_ExportSymmetricKey, ��SM2��Կ���ܱ�������һ���Գ���Կ
 * pcKeyType            IN        ��������Կ����Կ���ͣ�"000"�CKEK; 00A�CDEK; "109"�CMDK;
 * iKeyIndex            IN        ��������Կ��������<=0, ʹ��pcKey_Lmk����������ʹ������ָ������Կ
 * pcKey_Lmk            IN        LMK���ܵı�������Կ�����ġ���iKeyIndex<=0ʱ��Ч
 * iKeyDeriveNumber     IN        ��������Կ�ķ�ɢ����
 * pcKeyDeriveData      IN        ��������Կ�ķ�ɢ���ӣ�ÿ��32H
 * iSm2KeyIndex         IN        ��Ϊ������Կ��SM2��Կ������<=0��=9999ʱ��ʶʹ��pucDerPublicKey����
 * pucDerPublicKey      IN        ��Ϊ������Կ��DER�����SM2��Կ������iSm2KeyIndex<=0��=9999ʱ��Ч
 * iDerPublicKeyLen     IN        ��Ϊ������Կ��DER�����SM2��Կ���ȣ�����iSm2KeyIndex<=0��=9999ʱ��Ч
 * pucAuthData          IN        ��Ϊ������Կ�Ĺ�Կ�������ݣ����ܴ�';'�ַ�
 * iAuthDataLen         IN        ��Ϊ������Կ�Ĺ�Կ�������ݳ���
 * pucMac               IN        ��Ϊ������Կ��SM2��Կ��MACֵ
 * iMacLen              IN        ��Ϊ������Կ��SM2��Կ��MACֵ����
 * pucCipherKey         OUT       SM2��Կ���ܵı�������Կ����
 * piCipherKeyLen       OUT       SM2��Կ���ܵı�������Կ���ĳ���
 * pcKeyCv              OUT       ��������Կ��У��ֵ
 */
int HSM_SM2_ExportSymmetricKey(
    char *pcKeyType, int iKeyIndex, char *pcKey_Lmk,
    int iKeyDeriveNumber, char *pcKeyDeriveData,
    int iSm2KeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac,
    unsigned char *pucCipherKey/*out*/, int *piCipherKeyLen/*out*/,
    char *pcKeyCv/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TX" ***/
    *p ++ = 'T';
    *p ++ = 'X';

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** ��������Կ����Կ���ͣ�"000"�CKEK; 00A�CDEK; "109"�CMDK; ***/
    memcpy(p, pcKeyType, 3);
    p += 3;

    /*** ��������Կ ***/
    rv = Tools_AddFieldKey(iKeyIndex, pcKey_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iKeyIndex = [%d] is invalid.", iKeyIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ��������Կ��ɢ��������ɢ����, 2H+n*32H ***/
    rv = Tools_AddFieldDeriveData(1, iKeyDeriveNumber, pcKeyDeriveData, (char*)p);
    if (rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("Parameter: pcKeyDeriveData's length = [%d] is invalid.", strlen(pcKeyDeriveData));
        return HAR_PARAM_DERIVE_DATA;
    }
    p += rv;

    /*** ��Կ����, 4N ***/
    if(iSm2KeyIndex <= 0)
    {
        iSm2KeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iSm2KeyIndex);
    p += 4;

    if(iSm2KeyIndex == 9999)
    {
        /*** DER�����SM2��Կ, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;

        /*** ���ڼ��㹫ԿMAC�Ķ�������ݣ����ܰ����ַ���;����, nB ***/
        memcpy(p, pucAuthData, iAuthDataLen);
        p += iAuthDataLen;

        /*** ��֤���ݷָ���,';' ***/
        *p ++ = ';';

        /*** ��ԿMAC, 4B ***/
        memcpy(p, pucMac, 4);
        p += 4;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** SM2��Կ���ܵı�������Կ���ĳ���, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piCipherKeyLen)
    {
        *piCipherKeyLen = len;
    }

    /*** SM2��Կ���ܵı�������Կ����, nB ***/
    if(pucCipherKey)
    {
        memcpy(pucCipherKey, p, len);
    }
    p += len;

    /*** ��������Կ��У��ֵ  ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_ImportSymmetricKey, ��SM2��Կ���ܱ�������һ���Գ���Կ
 * pcKeyType            IN        ��������Կ����Կ���ͣ�"000"�CKEK; 00A�CDEK; "109"�CMDK;
 * cKeyScheme           IN        ��������Կ���㷨��ʶ��Z/X/Y/U/T/P/L/R
 * iKeyIndex            IN        ��������Կ��������<=0, ��ʶ��Կ���洢���ڲ�
 * pcKeyLabel           IN        ��������Կ�ı�ǩ����iKeyIndex>0ʱ��Ч
 * iSm2KeyIndex         IN        ��Ϊ������Կ��SM2��Կ������<=0��=9999ʱ��ʶʹ��pucPrivateKey_Lmk����
 * pucPrivateKey_Lmk    IN        ��Ϊ������Կ��SM2˽Կ���ģ�����iSm2KeyIndex<=0��=9999ʱ��Ч
 * iPrivateKeyLen_Lmk   IN        ��Ϊ������Կ��SM2˽Կ���ĳ��ȣ�����iSm2KeyIndex<=0��=9999ʱ��Ч
 * pucCipherKey         IN        SM2��Կ���ܵı�������Կ����
 * iCipherKeyLen        IN        SM2��Կ���ܵı�������Կ���ĳ���
 * pcKey_Lmk            OUT       LMK�¼��ܵı�������Կ����
 * pcKeyCv              OUT       ��������Կ��У��ֵ
 */
int HSM_SM2_ImportSymmetricKey(
    char *pcKeyType, char cKeyScheme,
    int iKeyIndex, char *pcKeyLabel,
    int iSm2KeyIndex,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucCipherKey, int iCipherKeyLen, 
    char *pcKey_Lmk/*out*/, char *pcKeyCv/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TY" ***/
    *p ++ = 'T';
    *p ++ = 'Y';

    /*** ���߱�ʶ, 2N, 07-����-256�����ߣ�SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** ��������Կ����Կ���ͣ�"000"�CKEK; 00A�CDEK; "109"�CMDK; ***/
    memcpy(p, pcKeyType, 3);
    p += 3;

    /*** ��������Կ���㷨��ʶ��Z/X/Y/U/T/P/L/R ***/
    *p ++ = cKeyScheme;

    /*** �ڲ��洢����Կ, ��Կ��������ǩ���ȡ���ǩ ***/
    rv = Tools_AddFieldSavedKey(iKeyIndex, pcKeyLabel, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    /*** ������Կ��У��ֵ, 16H, ȫ0��У�飬ֱ����ɵ��빤���� ***/
    memset(p, '0', 16);
    p += 16;

    /*** SM2��Կ���ܵı�������Կ���ĳ���, 4H ***/
    TASS_SPRINTF((char*)p, 5, "%04X", iCipherKeyLen);
    p += 4;

    /*** SM2��Կ���ܵı�������Կ����, nB ***/
    memcpy(p, pucCipherKey, iCipherKeyLen);
    p += iCipherKeyLen;

    /*** ��Կ����, 4N ***/
    if(iSm2KeyIndex <= 0)
    {
        iSm2KeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iSm2KeyIndex);
    p += 4;

    if(iSm2KeyIndex == 9999)
    {
        /*** ˽Կ����, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK���ܵ�����˽Կ����, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK�¼��ܵı�������Կ���� ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKey_Lmk)
    {
        strncpy(pcKey_Lmk, (char *)p, len);
    }
    p += len;

    /*** У��ֵ, 16H ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return 0;
}

/*
 * HSM_RSA_GenerateNewKeyPair, ����һ���µ�RSA��Կ��
 * iKeyIndex            IN        Ҫ������RSA��Կ������<=0��=9999ʱ��ʶ���洢
 * pcKeyLabel           IN        RSA��Կ��ǩ������iKeyIndex>0��!=9999ʱ��Ч;
 * iModulusBits         IN        RSA��Կģ����λ��
 * iPubE                IN        RSA��Կָ��E��3��65537
 * pucDerPublicKey      OUT       �����ɵ�RSA��Կ��DER����
 * piDerPublicKeyLen    OUT       �����ɵ�RSA��Կ����
 * pucPrivateKey_Lmk    OUT       LMK�¼��ܵ�RSA˽Կ����
 * piPrivateKeyLen_Lmk  OUT       LMK�¼��ܵ�RSA˽Կ���ĳ���
 */
int HSM_RSA_GenerateNewKeyPair(void *hSessionHandle,
    int iKeyIndex, char *pcKeyLabel,
    int iModulusBits, int iPubE,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "EI" ***/
    *p ++ = 'E';
    *p ++ = 'I';

    /*** ��Կ��;, 1N, 0�Cǩ����Կ��1�C��Կ������Կ��2�C���ޣ�����ʹ�ô��� ***/
    *p ++ = '2';

    /*** ��Կģ��, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iModulusBits);
    p += 4;

    /*** ��Կ��������, 2N, 01-ASN.1 ��ʽDER ����Ĺ�Կ������ʹ��2�Ĳ����ʾ�� ***/
    *p ++ = '0';
    *p ++ = '1';
#if 0
    /*** ��Կָ������, 4N, �ֽ���/λ����TODO�� ***/
    TASS_SPRINTF((char*)p, 5, "%04d", 4);
    p += 4;

    /*** ��Կָ��, nB ***/
    Tools_ConvertUint2Ucbuf(iPubE, p);
    p += 4;
#endif
    /*** �ڲ��洢����Կ, ��Կ��������ǩ���ȡ���ǩ ***/
    rv = Tools_AddFieldSavedKey(iKeyIndex, pcKeyLabel, (char*)p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ��Կ, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    if(piDerPublicKeyLen)
    {
        *piDerPublicKeyLen = len;
    }

    if(pucDerPublicKey)
    {
        memcpy(pucDerPublicKey, p, len);
    }
    p += len;

    /*** ˽Կ����, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKeyLen_Lmk)
    {
        *piPrivateKeyLen_Lmk = len;
    }

    /*** LMK���ܵ�˽Կ����, nB ***/
    if(pucPrivateKey_Lmk)
    {
        memcpy(pucPrivateKey_Lmk, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_GetPublicKey, ��ȡһ��RSA��Կ�Ĺ�Կ
 * iKeyIndex            IN        Ҫ������Կ��RSA��Կ����
 * pucDerPublicKey      OUT       ������RSA��Կ��DER����
 * piDerPublicKeyLen    OUT       ������RSA��Կ����
 */
int HSM_RSA_GetPublicKey(int iKeyIndex,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "ER" ***/
    *p ++ = 'E';
    *p ++ = 'R';

    /*** ��Կ����, K+4N ***/
    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ��Կ, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    if(piDerPublicKeyLen)
    {
        *piDerPublicKeyLen = len;
    }

    if(pucDerPublicKey)
    {
        memcpy(pucDerPublicKey, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_EncryptData, RSA��Կ��������
 * iPaddingMode            IN        ���ģʽ��00�C����䣨���ݿ鳤�ȱ����ģ���ȳ�����01�CPKCS#1 v1.5
 * iKeyIndex               IN        RSA��Կ������<=0��=9999ʱ����2��������Ч
 * pucDerPublicKey         IN        DER�����RSA��Կ����iKeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen        IN        DER�����RSA��Կ���ȣ���iKeyIndex=9999ʱ��Ч
 * pucInput                IN        Ҫ���ܵ��������ݣ����֧��136�ֽڵļ�������
 * iInputLength            IN        Ҫ���ܵ��������ݳ��ȣ����136
 * pucOutput               OUT       ���ܺ���������
 * piOutputLength          OUT       ���ܺ��������ݳ���
 */
int HSM_RSA_EncryptData( void *hSessionHandle,int iPaddingMode,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 256)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 256.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "3A" ***/
    *p ++ = '3';
    *p ++ = 'A';

    /*** �㷨��ʶ, 2N, 01-RSA ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** ���ģʽ, 2N, 00�C����䣨���ݿ鳤�ȱ����ģ���ȳ�����01�CPKCS#1 v1.5 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPaddingMode);
    p += 2;

    /*** ���ݿ鳤��, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** ���ݿ�, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ��Կ����, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    /*** ��ԿDER���� ***/
    if(iKeyIndex == 9999)
    {
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ���ĳ���, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piOutputLength)
    {
        *piOutputLength = len;
    }

    /*** ��������, nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_DecryptData, RSA˽Կ��������
 * iPaddingMode            IN        ���ģʽ��00�C����䣨���ܺ������ֱ���������01�CPKCS#1 v1.5
 * iKeyIndex               IN        RSA��Կ������<=0��=9999ʱ����2��������Ч
 * pucPrivateKey_Lmk       IN        LMK���ܵ�RSA˽Կ����iKeyIndex=9999ʱ��Ч
 * iPrivateKeyLen_Lmk      IN        LMK���ܵ�RSA˽Կ���ȣ���iKeyIndex=9999ʱ��Ч
 * pucInput                IN        Ҫ���ܵ���������
 * iInputLength            IN        Ҫ���ܵ��������ݳ���
 * pucOutput               OUT       ���ܺ���������
 * piOutputLength          OUT       ���ܺ��������ݳ���
 */
int HSM_RSA_DecryptData(void *hSessionHandle, int iPaddingMode,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength < 128 || iInputLength > 256)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be 128 - 256.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "3B" ***/
    *p ++ = '3';
    *p ++ = 'B';

    /*** �㷨��ʶ, 2N, 01-RSA ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** ���ģʽ, 2N, 00�C����䣨���ܺ������ֱ���������01�CPKCS#1 v1.5 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPaddingMode);
    p += 2;

    /*** ���ݿ鳤��, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** ���ݿ�, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ��Կ����, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** ˽Կ����, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK���ܵ�����˽Կ����, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ������ݳ���, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piOutputLength)
    {
        *piOutputLength = len;
    }

    /*** �������, nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_GenerateSignature, RSA˽Կ�����ݽ�������ǩ��
 * iHashMode               IN        HASH�㷨��ʶ
 * iPaddingMode            IN        ���ģʽ��00�C����䣨���ܺ������ֱ���������01�CPKCS#1 v1.5
 * iKeyIndex               IN        RSA��Կ������<=0��=9999ʱ����4��������Ч
 * pucPrivateKey_Lmk       IN        LMK���ܵ�RSA˽Կ����iSm2KeyIndex=9999ʱ��Ч
 * iPrivateKeyLen_Lmk      IN        LMK���ܵ�RSA˽Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucInput                IN        ��ǩ������������
 * iInputLength            IN        ��ǩ�����������ݳ���
 * pucSignature            OUT       ���������ǩ��
 * piSignatureLength       OUT       ���������ǩ������
 */
int HSM_RSA_GenerateSignature(
    int iHashMode, int iPaddingMode,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 512;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[512] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "EW" ***/
    *p ++ = 'E';
    *p ++ = 'W';

    /*** HASH�㷨��ʶ, 2N, ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iHashMode);
    p += 2;

    /*** �㷨��ʶ, 2N, 01-RSA ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** ���ģʽ, 2N, 00�C����䣨���ܺ������ֱ���������01�CPKCS#1 v1.5 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPaddingMode);
    p += 2;

    /*** ���ݿ鳤��, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** ���ݿ�, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ��Կ����, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** ˽Կ����, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK���ܵ�����˽Կ����, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ����ǩ������, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piSignatureLength)
    {
        *piSignatureLength = len;
    }

    /*** �������, nB ***/
    if(pucSignature)
    {
        memcpy(pucSignature, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_VerifySignature, RSA��Կ��֤���ݵ�ǩ��
 * iHashMode               IN        HASH�㷨��ʶ
 * iPaddingMode            IN        ���ģʽ��00�C����䣨���ܺ������ֱ���������01�CPKCS#1 v1.5
 * iKeyIndex               IN        RSA��Կ������<=0��=9999ʱ����2��������Ч
 * pucDerPublicKey         IN        DER�����RSA��Կ����iKeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen        IN        DER�����RSA��Կ���ȣ���iKeyIndex=9999ʱ��Ч
 * pucInput                IN        ����֤ǩ������������
 * iInputLength            IN        ����֤ǩ�����������ݳ���
 * pucSignature            IN        ����֤������ǩ��
 * iSignatureLength        IN        ����֤������ǩ������
 */
int HSM_RSA_VerifySignature(
    int iHashMode, int iPaddingMode,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature, int iSignatureLength)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 8;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[8] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "EY" ***/
    *p ++ = 'E';
    *p ++ = 'Y';

    /*** HASH�㷨��ʶ, 2N, ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iHashMode);
    p += 2;

    /*** �㷨��ʶ, 2N, 01-RSA ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** ���ģʽ, 2N, 00�C����䣨���ܺ������ֱ���������01�CPKCS#1 v1.5 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPaddingMode);
    p += 2;

    /*** ����ǩ��ǩ������, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iSignatureLength);
    p += 4;

    /*** ����ǩ��ǩ��, nB ***/
    memcpy(p, pucSignature, iSignatureLength);
    p += iSignatureLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ���ݿ鳤��, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** ���ݿ�, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** �ָ���, 1A ***/
    *p ++ = ';';

    /*** ��Կ����, K+4N ***/
    if(iKeyIndex<=0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** DER�����SM2��Կ, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/*
 * HSM_RSA_GeneratePublicKeyMac, ����Ȩ������ΪRSA��Կ������ԿMAC
 * pucDerPublicKey         IN        Ҫ����MAC��RSA��Կ��DER����
 * iDerPublicKeyLen        IN        Ҫ����MAC��RSA��Կ����
 * pucAuthData             IN        ��Կ�������ݣ����ܴ�';'�ַ�
 * iAuthDataLen            IN        ��Կ�������ݳ���
 * pucMac                  OUT       RSA��Կ��MACֵ
 * piMacLen                OUT       RSA��Կ��MACֵ����
 */
int HSM_RSA_GeneratePublicKeyMac(
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac/*out*/, int *piMacLen/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[1024] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    if(iAuthDataLen > 128)
    {
        LOG_ERROR("Parameter: iAuthDataLen = [%d] is invalid, it must be less than 128.", iAuthDataLen);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "EO" ***/
    *p ++ = 'E';
    *p ++ = 'O';

    /*** ��Կ��������, 2N, 01�CASN.1 ��ʽDER ����Ĺ�Կ������ʹ���޷��ű�ʾ�� ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** DER�����RSA��Կ, nB ***/
    memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
    p += iDerPublicKeyLen;

    /*** ���ڼ��㹫ԿMAC�Ķ�������ݣ����ܰ����ַ���;����, nB ***/
    memcpy(p, pucAuthData, iAuthDataLen);
    p += iAuthDataLen;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ʹ��LMK����Թ�Կ����֤���ݼ����MAC��4B ***/
    if(piMacLen)
    {
        *piMacLen = 4;
    }

    if(pucMac)
    {
        memcpy(pucMac, p, 4);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_ExportSymmetricKey, ��RSA��Կ���ܱ�������һ���Գ���Կ
 * pcKeyType               IN        ��������Կ����Կ����
 * iKeyIndex               IN        ��������Կ��������<=0, ʹ��pcKey_Lmk����������ʹ������ָ������Կ
 * pcKey_Lmk               IN        LMK���ܵı�������Կ�����ġ���iKeyIndex<=0ʱ��Ч
 * iKeyDeriveNumber        IN        ��������Կ�ķ�ɢ����
 * pcKeyDeriveData         IN        ��������Կ�ķ�ɢ���ӣ�ÿ��32H
 * iRsaKeyIndex            IN        ��Ϊ������Կ��RSA��Կ������<=0��=9999ʱ��ʶʹ��pucDerPublicKey����
 * pucDerPublicKey         IN        ��Ϊ������Կ��DER�����RSA��Կ������iRsaKeyIndex<=0��=9999ʱ��Ч
 * iDerPublicKeyLen        IN        ��Ϊ������Կ��DER�����RSA��Կ���ȣ�����iRsaKeyIndex<=0��=9999ʱ��Ч
 * pucAuthData             IN        ��Ϊ������Կ�Ĺ�Կ�������ݣ����ܴ�';'�ַ�
 * iAuthDataLen            IN        ��Ϊ������Կ�Ĺ�Կ�������ݳ���
 * pucMac                  IN        ��Ϊ������Կ��RSA��Կ��MACֵ
 * iMacLen                 IN        ��Ϊ������Կ��RSA��Կ��MACֵ����
 * pucCipherKey            OUT       RSA��Կ���ܵı�������Կ����
 * piCipherKeyLen          OUT       RSA��Կ���ܵı�������Կ���ĳ���
 * pcKeyCv                 OUT       ��������Կ��У��ֵ
 */
int HSM_RSA_ExportSymmetricKey(
    char *pcKeyType, int iKeyIndex, char *pcKey_Lmk,
    int iKeyDeriveNumber, char *pcKeyDeriveData,
    int iRsaKeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac,
    unsigned char *pucCipherKey/*out*/, int *piCipherKeyLen/*out*/,
    char *pcKeyCv/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TV" ***/
    *p ++ = 'T';
    *p ++ = 'V';

    /*** ���ģʽ, 2N, 01�CPKCS#1 v1.5 ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** ��������Կ����Կ���� ***/
    memcpy(p, pcKeyType, 3);
    p += 3;

    /*** ��������Կ ***/
    rv = Tools_AddFieldKey(iKeyIndex, pcKey_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iKeyIndex = [%d] is invalid.", iKeyIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ��������Կ��ɢ��������ɢ����, 2H+n*32H ***/
    rv = Tools_AddFieldDeriveData(1, iKeyDeriveNumber, pcKeyDeriveData, p);
    if (rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("Parameter: pcKeyDeriveData's length = [%d] is invalid.", strlen(pcKeyDeriveData) );
        return HAR_PARAM_DERIVE_DATA;
    }
    p += rv;

    /*** ��Կ����, 4N ***/
    if (iRsaKeyIndex <= 0)
    {
        iRsaKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iRsaKeyIndex);
    p += 5;

    if(iRsaKeyIndex == 9999)
    {
        /*** DER�����RSA��Կ, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;

        /*** ���ڼ��㹫ԿMAC�Ķ�������ݣ����ܰ����ַ���;����, nB ***/
        memcpy(p, pucAuthData, iAuthDataLen);
        p += iAuthDataLen;

        /*** ��֤���ݷָ���,';' ***/
        *p ++ = ';';

        /*** ��ԿMAC, 4B ***/
        memcpy(p, pucMac, 4);
        p += 4;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** RSA��Կ���ܵı�������Կ���ĳ���, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piCipherKeyLen)
    {
        *piCipherKeyLen = len;
    }

    /*** RSA��Կ���ܵı�������Կ����, nB ***/
    if(pucCipherKey)
    {
        memcpy(pucCipherKey, p, len);
    }
    p += len;

    /*** ��������Կ��У��ֵ ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, p, 16);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_ImportSymmetricKey, ��RSA��Կ���ܱ�������һ���Գ���Կ
 * pcKeyType               IN        ��������Կ����Կ����
 * cKeyScheme              IN        ��������Կ���㷨��ʶ��Z/X/Y/U/T/P/L/R
 * iKeyIndex               IN        ��������Կ��������<=0, ��ʶ��Կ���洢���ڲ�
 * pcKeyLabel              IN        ��������Կ�ı�ǩ����iKeyIndex>0ʱ��Ч
 * iRsaKeyIndex            IN        ��Ϊ������Կ��RSA��Կ������<=0��=9999ʱ��ʶʹ��pucPrivateKey_Lmk����
 * pucPrivateKey_Lmk       IN        ��Ϊ������Կ��RSA˽Կ���ģ�����iRsaKeyIndex<=0��=9999ʱ��Ч
 * iPrivateKeyLen_Lmk      IN        ��Ϊ������Կ��RSA˽Կ���ĳ��ȣ�����iRsaKeyIndex<=0��=9999ʱ��Ч
 * pucCipherKey            IN        RSA��Կ���ܵı�������Կ����
 * iCipherKeyLen           IN        RSA��Կ���ܵı�������Կ���ĳ���
 * pcKey_Lmk               OUT       LMK�¼��ܵı�������Կ����
 * pcKeyCv                 OUT       ��������Կ��У��ֵ
 */
int HSM_RSA_ImportSymmetricKey(
    char *pcKeyType, char cKeyScheme,
    int iKeyIndex, char *pcKeyLabel,
    int iRsaKeyIndex,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucCipherKey, int iCipherKeyLen, 
    char *pcKey_Lmk/*out*/, char *pcKeyCv/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TW" ***/
    *p ++ = 'T';
    *p ++ = 'W';

    /*** ���ģʽ, 2N, 01�CPKCS#1 v1.5 ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** ��������Կ����Կ���� ***/
    memcpy( p, pcKeyType, 3 );
    p += 3;

    /*** ��������Կ���㷨��ʶ��Z/X/Y/U/T/P/L/R ***/
    *p ++ = cKeyScheme;

    /*** �ڲ��洢����Կ, ��Կ��������ǩ���ȡ���ǩ ***/
    rv = Tools_AddFieldSavedKey(iKeyIndex, pcKeyLabel, (char*)p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel's length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    /*** ������Կ��У��ֵ, 16H, ȫ0��У�飬ֱ����ɵ��빤���� ***/
    memset(p, '0', 16);
    p += 16;

    /*** RSA��Կ���ܵı�������Կ���ĳ���, 4H ***/
    TASS_SPRINTF((char*)p, 5, "%04X", iCipherKeyLen);
    p += 4;

    /*** RSA��Կ���ܵı�������Կ����, nB ***/
    memcpy(p, pucCipherKey, iCipherKeyLen);
    p += iCipherKeyLen;

    /*** ��Կ����, 4N ***/
    if(iRsaKeyIndex<=0)
    {
        iRsaKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iRsaKeyIndex);
    p += 5;

    if(iRsaKeyIndex == 9999)
    {
        /*** ˽Կ����, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK���ܵ�����˽Կ����, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK�¼��ܵı�������Կ���� ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if (pcKey_Lmk)
    {
        memcpy(pcKey_Lmk, p, len);
    }
    p += len;

    /*** У��ֵ, 16H ***/
    if (pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_ExportRSAKey     ������Կ���Գƣ����ܵ���һ��RSA��Կ
 * iMode                    �����㷨ģʽ  2 H  00 �C ECB 01 �C CBC
 * pcTkType                 ���ڼ��ܱ���RSA��Կ�ı�����Կ���� 000 �C KEK;   109 �C MDK;
 * iTkIndex                 ���ڼ��ܱ���RSA�ı�����Կ����
 * pcTk_Lmk                 ���ڼ��ܱ���RSA�ı�����Կ����
 * iTkDeriveNumber          ������Կ��ɢ����
 * pcTkDeriveData           ������Կ��ɢ����
 * iRsaKeyIndex             ��������Կ������
 * pucPrivateKey            ��������Կ˽Կ����
 * iPrivateKeyLen           ��������Կ˽Կ����
 * pcExpandFlg              ��չ��ʶ
 * pcPADFlg                 ��ʶ�������ĸ�˽Կ������������
 * iOutPublicKeyFlg         ��Կ�����ʽ,0 - ����DER��ʽ����� ASN.1 ��ʽDER ���루ģ��ָ�����У� 1 - m��e���÷���������ʽ���
 * pcIV                     ��ʼ������
 */

int HSM_RSA_ExportRSAKey(void *hSessionHandle,
    int iMode,  char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iRsaKeyIndex,
    unsigned char *pucPrivateKey, int iPrivateKeyLen,
    char *pcExpandFlg, char *pcPADFlg,
    int iOutPublicKeyFlg, char *pcIV,
    unsigned char *pucDerPublicKey/*OUT*/, int *piDerPublicKeyLen/*OUT*/,
    unsigned char *pucPublicKey_m/*OUT*/, int *piPublicKey_mLen/*OUT*/,
    unsigned char *pucPublicKey_e/*OUT*/, int *piPublicKey_eLen/*OUT*/,
    unsigned char *pucPrivateKey_d/*OUT*/, int *piPrivateKey_dLen/*OUT*/,
    unsigned char *pucPrivateKey_p/*OUT*/, int *piPrivateKey_pLen/*OUT*/,
    unsigned char *pucPrivateKey_q/*OUT*/, int *piPrivateKey_qLen/*OUT*/,
    unsigned char *pucPrivateKey_dp/*OUT*/, int *piPrivateKey_dpLen/*OUT*/,
    unsigned char *pucPrivateKey_dq/*OUT*/, int *piPrivateKey_dqLen/*OUT*/,
    unsigned char *pucPrivateKey_qInv/*OUT*/, int *piPrivateKey_qInvLen/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TR" ***/
    *p ++ = 'T';
    *p ++ = 'R';

    /*** �����㷨ģʽ ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** ��������Կ����Կ���� ***/
    memcpy(p, pcTkType, 3);
    p += 3;

    /*** ������Կ��Կ ***/
    rv = Tools_AddFieldKey(iTkIndex, pcTk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iTkIndex = [%d] is invalid.", iTkIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ������Կ��ɢ��������ɢ����, 2H+n*32H ***/
    rv = Tools_AddFieldDeriveData(1, iTkDeriveNumber, pcTkDeriveData, (char*)p);
    if (rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("Parameter: pcTkDeriveData's length = [%d] is invalid.", strlen(pcTkDeriveData));
        return HAR_PARAM_DERIVE_DATA;
    }
    p += rv;

    /*** ��������Կ����, 4N ***/
    if(iRsaKeyIndex <= 0)
    {
        iRsaKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iRsaKeyIndex);
    p += 5;

    if(iRsaKeyIndex == 9999)
    {
	/*** ��������RSA˽Կ�ֽ��� ***/
    	TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen);
    	p += 4;

        /*** ��������RSA˽Կ, nB ***/
        memcpy(p, pucPrivateKey, iPrivateKeyLen);
        p += iPrivateKeyLen;
    }

    if(!strcmp(pcExpandFlg, "P"))
    {
        /*** ��չ��ʶ ***/
        memcpy(p, pcExpandFlg, 1);
        p += 1;

        /*** PAD��ʶ ***/
        memcpy(p, pcPADFlg, 2);
        p += 2;

        /*** 0 - ����DER��ʽ����� ASN.1 ��ʽDER ���루ģ��ָ�����У� 1 - m��e���÷���������ʽ��� ***/
        TASS_SPRINTF((char*)p, 2, "%d", iOutPublicKeyFlg);
        p += 1;

        /*** IV ***/
        memcpy(p, pcIV, strlen(pcIV));
        p += strlen(pcIV);
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    if(iOutPublicKeyFlg == 0 || strcmp(pcExpandFlg, "P"))
    {
        /*** DER���빫Կ, nB ***/
        len = Tools_GetFieldDerBufLength(p);
        if(piDerPublicKeyLen)
        {
            *piDerPublicKeyLen = len;
        }
        if(pucDerPublicKey)
        {
            memcpy(pucDerPublicKey, p, len);
        }
        p += len;
    }
    else if(iOutPublicKeyFlg == 1 && (!strcmp(pcExpandFlg, "P")))/***  m��e���÷���������ʽ����Ĺ�Կ ***/
    {
        /*** ��Կģm���ĳ���  ***/
        len = Tools_ConvertDecBuf2Int(p, 4);
        p += 4;
        if (piPublicKey_mLen)
        {
	    printf("m len = [%d]\n", len);
            *piPublicKey_mLen = len;
        }

        /*** ��Կģm����  ***/
        if(pucPublicKey_m)
        {
            memcpy(pucPublicKey_m, p, len);
        }
        p += len;

        /*** ��Կָ��e���ĳ��� ***/
        len = Tools_ConvertDecBuf2Int(p, 4);
        p += 4;
        if (piPublicKey_eLen)
        {
	    printf("e len = [%d]\n", len);
            *piPublicKey_eLen = len;
        }

        /*** ��Կָ��e���� ***/
        if(pucPublicKey_e)
        {
            memcpy(pucPublicKey_e, p, len);
        }
        p += len;
    }

    /*** ˽Կָ��d���ĳ��� ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if (piPrivateKey_dLen)
    {
        *piPrivateKey_dLen = len;
    }

    /*** ˽Կָ��d���� ***/
    if (pucPrivateKey_d)
    {
        memcpy(pucPrivateKey_d, p, len);
    }
    p += len;

    /*** ˽Կ����P���ĳ��� ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if (piPrivateKey_pLen)
    {
        *piPrivateKey_pLen = len;
    }

    /*** ˽Կ����P���� ***/
    if(pucPrivateKey_p)
    {
        memcpy(pucPrivateKey_p, p, len);
    }
    p += len;

    /*** ˽Կ����Q���ĳ��� ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if (piPrivateKey_qLen)
    {
        *piPrivateKey_qLen = len;
    }

    /*** ˽Կ����Q���� ***/
    if(pucPrivateKey_q)
    {
        memcpy(pucPrivateKey_q, p, len);
    }
    p += len;

    /*** ˽Կ����dP ���ĳ��� ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if (piPrivateKey_dpLen)
    {
        *piPrivateKey_dpLen = len;
    }

    /*** ˽Կ����dP���� ***/
    if (pucPrivateKey_dp)
    {
        memcpy(pucPrivateKey_dp, p, len);
    }
    p += len;

    /*** ˽Կ����dQ ���ĳ��� ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKey_dqLen)
    {
        *piPrivateKey_dqLen = len;
    }

    /*** ˽Կ����dQ���� ***/
    if(pucPrivateKey_dq)
    {
        memcpy(pucPrivateKey_dq, p, len);
    }
    p += len;

    /*** ˽Կ����qInv ���ĳ��� ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKey_qInvLen)
    {
        *piPrivateKey_qInvLen = len;
    }

    /*** ˽Կ����qInv���� ***/
    if(pucPrivateKey_qInv)
    {
        memcpy(pucPrivateKey_qInv, p, len);
    }

    return rv;
}

/*
 * HSM_RSA_ImportByTk     ������Կ���Գƣ����ܵ���һ��RSA��Կ
 * iMode                    �����㷨ģʽ  2 H  00 �C ECB 01 �C CBC
 * pcTkType                 ���ڼ��ܱ���RSA��Կ�ı�����Կ���� 000 �C KEK;   109 �C MDK;
 * iTkIndex                 ���ڼ��ܱ���RSA�ı�����Կ����
 * pcTk_Lmk                 ���ڼ��ܱ���RSA�ı�����Կ����
 * iTkDeriveNumber          ������Կ��ɢ����
 * pcTkDeriveData           ������Կ��ɢ����
 * iRsaKeyIndex             ��������Կ������
 * pucRsaKeyTag             RSA��Կ��ǩ
 * iRsaKeyTagLen            RSA��Կ��ǩ����
 * pucPublicKey             ��Կ�� ASN.1 ��ʽDER ���루ģ��ָ������)
 * iPublicKeyLen            ��Կ���ݳ���
 * pucPrivateKey_d          ˽Կָ��d  n B  ˽Կָ��d����
 * iPrivateKey_dLen         ˽Կָ��d����  4 N  ˽Կָ��d���ĳ��ȣ��ֽ���
 * pucPrivateKey_p          ˽Կ����P  n B  ˽Կ����p����
 * iPrivateKey_pLen         ˽Կ����P����  4 N  ˽Կ����p���ĳ��ȣ��ֽ���
 * pucPrivateKey_q          ˽Կ����Q  n B  ˽Կ����q����
 * iPrivateKey_qLen         ˽Կ����Q����  4 N  ˽Կ����q���ĳ��ȣ��ֽ���
 * pucPrivateKey_dp         ˽Կ����dP  n B  ˽Կ����dP����
 * iPrivateKey_dpLen        ˽Կ����dP����  4 N  ˽Կ����dP���ĳ��ȣ��ֽ���
 * pucPrivateKey_dq         ˽Կ����dQ  n B  ˽Կ����dQ����
 * iPrivateKey_dqLen        ˽Կ����dQ����  4 N  ˽Կ����dQ���ĳ��ȣ��ֽ���
 * pucPrivateKey_qInv       ˽Կ����qInv  n B  ˽Կ����qInv����
 * iPrivateKey_qInvLen      ˽Կ����qInv����  4 N  ˽Կ����qInv���ĳ��ȣ��ֽ���
 */

int HSM_RSA_ImportByTk(
    int iMode,  char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iRsaKeyIndex,
    unsigned char *pucRsaKeyTag, int iRsaKeyTagLen,
    unsigned char *pucPublicKey, int iPublicKeyLen,
    unsigned char *pucPrivateKey_d, int iPrivateKey_dLen,
    unsigned char *pucPrivateKey_p, int iPrivateKey_pLen,
    unsigned char *pucPrivateKey_q, int iPrivateKey_qLen,
    unsigned char *pucPrivateKey_dp, int iPrivateKey_dpLen,
    unsigned char *pucPrivateKey_dq, int iPrivateKey_dqLen,
    unsigned char *pucPrivateKey_qInv, int iPrivateKey_qInvLen,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TS" ***/
    *p ++ = 'T';
    *p ++ = 'S';

    /*** �����㷨ģʽ ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** ������Կ����Կ���� ***/
    memcpy(p, pcTkType, 3);
    p += 3;

    /*** ������Կ��Կ ***/
    rv = Tools_AddFieldKey(iTkIndex, pcTk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iTkIndex = [%d] is invalid.", iTkIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ������Կ��ɢ��������ɢ����, 2H+n*32H ***/
    rv = Tools_AddFieldDeriveData( 1, iTkDeriveNumber, pcTkDeriveData, (char*)p );
    if (rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("Parameter: pcTkDeriveData length = [%d] is invalid.", strlen(pcTkDeriveData));
        return HAR_PARAM_DERIVE_DATA;
    }
    p += rv;

    /*** ���������Կ����, 4N ***/
    if (iRsaKeyIndex<=0)
    {
        iRsaKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iRsaKeyIndex);
    p += 5;

    if (iRsaKeyIndex != 9999)
    {
        TASS_SPRINTF((char *)p, 3, "%02d", iRsaKeyTagLen);
        p += 2;

        /*** RSA��Կ��ǩ  ***/
        memcpy(p, pucRsaKeyTag, iRsaKeyTagLen);
        p += iRsaKeyTagLen;
    }

    /*** Ҫ�����RSA��Կ�Ĺ�Կ����, ASN.1 ��ʽDER ���루ģ��ָ�����У�***/
    memcpy(p, pucPublicKey, iPublicKeyLen);
    p += iPublicKeyLen;

    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_dLen);
    p += 4;

    /*** ˽Կָ��d ***/
    memcpy(p, pucPrivateKey_d, iPrivateKey_dLen);
    p += iPrivateKey_dLen;

    /*** ˽Կ����P ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_pLen);
    p += 4;
    memcpy(p, pucPrivateKey_p, iPrivateKey_pLen);
    p += iPrivateKey_pLen;

    /*** ˽Կ����Q ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_qLen);
    p += 4;
    memcpy(p, pucPrivateKey_q, iPrivateKey_qLen);
    p += iPrivateKey_qLen;

    /*** ˽Կ����dP ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_dpLen);
    p += 4;
    memcpy(p, pucPrivateKey_dp, iPrivateKey_dpLen);
    p += iPrivateKey_dpLen;

    /*** ˽Կ����dQ ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_dqLen);
    p += 4;
    memcpy(p, pucPrivateKey_dq, iPrivateKey_dqLen);
    p += iPrivateKey_dqLen;

    /*** ˽Կ����qInv ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_qInvLen);
    p += 4;
    memcpy(p, pucPrivateKey_qInv, iPrivateKey_qInvLen);
    p += iPrivateKey_qInvLen;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ˽Կ���� ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKeyLen_Lmk)
    {
        *piPrivateKeyLen_Lmk = len;
    }

    /*** ˽Կ����  ***/
    if(pucPrivateKey_Lmk)
    {
        memcpy(pucPrivateKey_Lmk, p, len);
    }

    return HAR_OK;
}


