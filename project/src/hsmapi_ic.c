/*----------------------------------------------------------------------|
|    hsmapi_ic.c                                                        |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口金融IC卡应用主机命令函数            |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-03. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <stdarg.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#endif

#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmapi_init.h"
#include "hsmapi_tcpcom.h"
#include "hsmapi_ic.h"

int HSM_IC_PutPlainKey(
        char *pcKeyType,
        char cKeyScheme,
        char *pcPlainKey,
        int  iKeyIdx,
        char *pcKeyLabel,
        char *pcKeyCipherByLmk/*out*/,
        char *pcKeyCv/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "AM"  ***/
    *p ++= 'A';
    *p ++= 'M';

    /*** 密钥类型, 3H, 109–MDK; 209–MK-SMI; 000–KEK; 011–KMC; 008–ZAK;  ***/
    memcpy(p, pcKeyType, 3);
    p += 3;

    /*** 密钥标识(LMK), 1A, Z/X/Y/U/T/P/L/R  ***/
    *p ++= cKeyScheme;
    if (cKeyScheme == 'Z')
    {
        len = 16;
    }
    else if (cKeyScheme == 'Y' || cKeyScheme == 'T')
    {
        len = 48;
    }
    else
    {
        len = 32;
    }

    /*** 密钥合成方式, 2H, 00  ***/
    *p ++= '0';
    *p ++= '0';

    /*** 密钥成份个数, 2H, 固定为2 ***/
    *p ++= '0';
    *p ++= '2';

    /*** 密钥成份1，16H/32H/48H ***/
    plainlen = strlen(pcPlainKey);
    if (len != plainlen)
    {
        LOG_ERROR("Parameter: pcPlainKey length = [%d] is Invalid.", strlen(pcPlainKey));
        return HAR_PARAM_LEN;
    }

    memcpy(p, pcPlainKey, plainlen);
    p += plainlen;

    /*** 密钥成份2，16H/32H/48H, 全0 ***/
    memset(p, '0', plainlen);
    p += plainlen;

    /*** 内部存储的密钥, 密钥索引、标签长度、标签 ***/
    rv = Tools_AddFieldSavedKey(iKeyIdx, pcKeyLabel, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密钥密文, 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByLmk)
    {
        strncpy(pcKeyCipherByLmk, (char *)p, len);
    }
    p += len;

    /*** 校验值, 16H ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

int HSM_IC_GetKeyInfo(
        int iKeyIdx,
        char *pcKeyType,
        char *pcKeyScheme,
        char *pcKeyCv,
        char *pcKeyLabel,
        char *pcTime)
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "KG"  ***/
    *p ++ = 'K';
    *p ++ = 'G';

    /*** 密钥索引号, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iKeyIdx);
    p += 4;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密钥类型, 3H ***/
    strncpy(pcKeyType, (char *)p, 3);
    p += 3;

    /*** 密钥算法标识, 1A ***/
    *pcKeyScheme = *p;
    p ++;

    /*** KeyCV, 16H ***/
    strncpy(pcKeyCv, (char *)p, 16);
    p += 16;

    /*** 密钥标签长度, 2N ***/
    len = Tools_ConvertDecBuf2Int(p, 2);
    p += 2;

    /*** 密钥标签, nA ***/
    strncpy(pcKeyLabel, (char *)p, len);
    p += len;

    /*** 密钥最后更新时间长度, 2N ***/
    len = Tools_ConvertDecBuf2Int(p, 2);
    p += 2;

    /*** 密钥最后更新时间标签, nA*/
    strncpy(pcTime, (char *)p, len);
    p += len;

    return HAR_OK;
}

int HSM_IC_GenerateNewKey(
        char *pcKeyType,
        char cKeyScheme,
        int  iKeyIdx,
        char *pcKeyLabel,
        char *pcKeyCipherByLmk,
        char *pcKeyCv)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "KR" ***/
    *p ++ = 'K';
    *p ++ = 'R';

    /*** 密钥类型, 3H, 109–MDK; 209–MK-SMI; 000–KEK; 011–KMC; 008–ZAK; ***/
    memcpy(p, pcKeyType, 3);
    p += 3;

    /*** 密钥标识(LMK), 1A, Z/X/Y/U/T/P/L/R ***/
    *p ++ = cKeyScheme;

    /*** 内部存储的密钥, 密钥索引、标签长度、标签 ***/
    rv = Tools_AddFieldSavedKey(iKeyIdx, pcKeyLabel, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密钥密文, 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByLmk)
    {
        strncpy(pcKeyCipherByLmk, (char *)p, len);
    }
    p += len;

    /*** 校验值, 16H/32H ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, len);
    }

    return HAR_OK;
}

int HSM_IC_DeriveNewKey(
            char *pcSrcKeyType,
            int  iSrcKeyIdx,
            char *pcSrcKeyCipherByLmk,
            char *pcDstKeyType,
            char cDstKeyScheme,
            int  iDeriveMode,
            int  iDeriveNumber,
            char *pcDeriveFactor,
            int  iDstKeyIdx,
            char *pcDstKeyLabel,
            char *pcDstKeyCipherByLmk/*out*/,
            char *pcDstKeyCv/*out*/ )
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "KD" ***/
    *p ++ = 'K';
    *p ++ = 'D';

    /*** 源密钥类型, 3H, 109–MDK; ***/
    memcpy(p, pcSrcKeyType, 3);
    p += 3;

    /*** 源密钥 ***/
    rv = Tools_AddFieldKey(iSrcKeyIdx, pcSrcKeyCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyIdx or pcSrcKeyCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 子密钥类型, 3H, 109–MDK; 209–MK-SMI; 000–KEK; 011–KMC; 008–ZAK; ***/
    memcpy(p, pcDstKeyType, 3);
    p += 3;

    /*** 子密钥标识(LMK), 1A, X/U/P/L/R ***/
    *p ++ = cDstKeyScheme;

    /*** 分散算法模式, 1H
     0-PBOC子密钥分散算法,每级分散因子为8字节（16H）
     1-ECB模式加密16字节分散因子,每级分散因子为16字节（32H） ***/
    TASS_SPRINTF((char *)p, 2, "%d", iDeriveMode);
    p += 1;

    /*** 分散级数及分散因子, 2H ***/
    rv = Tools_AddFieldDeriveData(iDeriveMode, iDeriveNumber, pcDeriveFactor, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: iDeriveNumber or pcDeriveFactor is invalid.");
        return rv;
    }

    /*** 内部存储的子密钥, 密钥索引、标签长度、标签 ***/
    rv = Tools_AddFieldSavedKey(iDstKeyIdx, pcDstKeyLabel, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcDstKeyLabel));
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密钥密文, 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcDstKeyCipherByLmk)
    {
        strncpy(pcDstKeyCipherByLmk, (char *)p, len);
    }
    p += len;

    /*** 校验值, 16H ***/
    if(pcDstKeyCv)
    {
        strncpy(pcDstKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

int HSM_IC_ExportCipherKey(
    void *hSessionHandle,
    int iEncryptMode,
    char *pcSrcKeyType, int iSrcKeyIdx, char *pcSrcKeyCipherByLmk,
    int iSrcKeyDeriveNum, char *pcSrcKeyDeriveData,
    int iSrcSessionMode, char *pcSrcSessionData,
    char *pcDstKeyType, int iDstKeyIdx, char *pcDstKeyCipherByLmk,
    int iDstKeyDeriveNumber, char *pcDstKeyDeriveFactor,
    char *pcDstKeyHeader,
    char *pcCipherDstKey/*out*/, char *pcDstKeyCv/*out*/)
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if (iEncryptMode != ENCRYPT_MODE_ECB && iEncryptMode != ENCRYPT_MODE_CBC)
    {
        LOG_ERROR("Parameter: iEncryptMode = [%d] is invalid, it must be 0 or 1.", iEncryptMode);
        return HAR_PARAM_ENC_MODE;
    }

    /*** Command Code    "SH" ***/
    *p ++ = 'S';
    *p ++ = 'H';

    /*** 加密算法模式, 2H, 00-ECB, 01-CBC; ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iEncryptMode);
    p += 2;

    /*** 源密钥类型, 3H, 109–MDK; ***/
    memcpy(p, pcSrcKeyType, 3);
    p += 3;

    /*** 源密钥 ***/
    rv = Tools_AddFieldKey(iSrcKeyIdx, pcSrcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyIdx or pcSrcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 源密钥分散级数及分散因子, 2H+n*32H ***/
    rv = Tools_AddFieldDeriveData(1, iSrcKeyDeriveNum, pcSrcKeyDeriveData, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyDeriveNum or pcSrcKeyDeriveData is invalid.");
        return rv;
    }
    p += rv;

    /*** 源密钥会话密钥类型及会话密钥因子 ***/
    rv = Tools_AddFieldSessionData(iSrcSessionMode, pcSrcSessionData, p);
    if(rv == HAR_PARAM_SESSION_KEY_DATA || rv == HAR_PARAM_SESSION_KEY_MODE)
    {
        LOG_ERROR("Parameter: iSrcSessionMode = [%d], pcSessionData = [%s] is invalid.",
                iSrcSessionMode, pcSrcSessionData);
        return rv;
    }
    p += rv;

    /*** 导出密钥类型, 3H, 109–MDK; 209–MK-SMI; 000–KEK; 011–KMC; 008–ZAK; ***/
    memcpy(p, pcDstKeyType, 3);
    p += 3;

    /*** 导出密钥 ***/
    rv = Tools_AddFieldKey(iDstKeyIdx, pcDstKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iDstKeyIdx or pcDstKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 分散级数及分散因子, 2H ***/
    rv = Tools_AddFieldDeriveData(1, iDstKeyDeriveNumber, pcDstKeyDeriveFactor, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: iDstKeyDeriveNumber or pcDstKeyDeriveFactor is invalid.");
        return rv;
    }
    p += rv;

    /*** 密钥头长度, 2H ***/
    if (!pcDstKeyHeader)
    {
        len = 0;
    }
    else
    {
        len = strlen(pcDstKeyHeader);
    }

    if (len % 2 || len > 64)
    {
        LOG_ERROR("Parameter: pcDstKeyHeader length = [%d] is invalid.", strlen(pcDstKeyHeader));
        return HAR_PARAM_KEY_HEADER;
    }

    TASS_SPRINTF((char*)p, 3, "%02d", len / 2);
    p += 2;

    /*** 密钥头, n*2H ***/
    memcpy(p, pcDstKeyHeader, len);
    p += len;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密文长度, 4H ***/
    len = Tools_ConvertHexBuf2Int(p, 4) * 2;
    p += 4;

    /*** 密钥密文, n*2H ***/
    if(pcCipherDstKey)
    {
        strncpy(pcCipherDstKey, p, len);
    }
    p += len;

    /*** 校验值, 16H ***/
    if(pcDstKeyCv)
    {
        strncpy(pcDstKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

int HSM_IC_ImportCipherKey(
    int iEncryptMode,
    char *pcSrcKeyType, int iSrcKeyIdx, char *pcSrcKeyCipherByLmk,
    int iSrcKeyDeriveNum, char *pcSrcKeyDeriveData,
    int iSrcSessionMode, char *pcSrcSessionData,
    char *pcDstKeyType, char cDstKeyScheme,
    char *pcDstKeyCipherByTk,
    int iDstKeyIdx, char *pcDstKeyLabel,
    char *pcDstKeyHeader, char cExpandFlg,
    char *pcPad, char *pcIV,
    char *pcSrcKeyCv,
    char *pcDstKeyCipherByLmk/*out*/, char *pcDstKeyCv/*out*/ )
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "SI" ***/
    *p ++ = 'S';
    *p ++ = 'I';

    /*** 加密算法模式, 2H, 00-ECB, 01-CBC; ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iEncryptMode);
    p += 2;

    /*** 源密钥类型, 3H ***/
    memcpy(p, pcSrcKeyType, 3);
    p += 3;

    /*** 源密钥 ***/
    rv = Tools_AddFieldKey(iSrcKeyIdx, pcSrcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyIdx or pcSrcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 源密钥分散级数及分散因子, 2H+n*32H ***/
    rv = Tools_AddFieldDeriveData(1, iSrcKeyDeriveNum, pcSrcKeyDeriveData, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyDeriveNum or pcSrcKeyDeriveData is invalid.");
        return rv;
    }
    p += rv;

    /*** 源密钥会话密钥类型及会话密钥因子 ***/
    rv = Tools_AddFieldSessionData(iSrcSessionMode, pcSrcSessionData, p);
    if(rv == HAR_PARAM_SESSION_KEY_DATA || rv == HAR_PARAM_SESSION_KEY_MODE)
    {
        LOG_ERROR("Parameter: iSrcSessionMode = [%d], pcSessionData = [%s] is invalid.",
                iSrcSessionMode, pcSrcSessionData);
        return rv;
    }
    p += rv;

    /*** 导入密钥类型, 3H, 109–MDK; 209–MK-SMI; 000–KEK; 011–KMC; 008–ZAK; ***/
    memcpy(p, pcDstKeyType, 3);
    p += 3;

    /*** 导入密钥标识(LMK), 1A, Z/X/Y/U/T/P/L/R ***/
    *p ++ = cDstKeyScheme;

    /*** 导入密钥密文长度, 4H ***/
    if (!pcDstKeyCipherByTk)
    {
        len = 0;
    }
    else
    {
        len = strlen(pcDstKeyCipherByTk);
    }

    if(len == 0 || len % 2 != 0)
    {
        LOG_ERROR("Parameter: pcDstKeyCipherByTk length = [%d] is invalid.", len);
        return HAR_PARAM_LEN;
    }

    TASS_SPRINTF((char*)p, 5, "%04X", len / 2);
    p += 4;

    /*** 导入密钥密文, n*2H ***/
    memcpy(p, pcDstKeyCipherByTk, len);
    p += len;

    /*** 内部存储的导入密钥, 密钥索引、标签长度、标签 ***/
    rv = Tools_AddFieldSavedKey(iDstKeyIdx, pcDstKeyLabel, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcDstKeyLabel));
        return rv;
    }
    p += rv;

    /*** 密钥头长度, 2H ***/
    if (!pcDstKeyHeader)
    {
        len = 0;
    }
    else
    {
        len = strlen(pcDstKeyHeader);
    }

    if (len % 2 || len > 64)
    {
        LOG_ERROR("Parameter: pcDstKeyHeader length = [%d] is invalid.", strlen(pcDstKeyHeader));
        return HAR_PARAM_KEY_HEADER;
    }

    TASS_SPRINTF((char*)p, 3, "%02d", len / 2);
    p += 2;

    /*** 密钥头, n*2H ***/
    memcpy( p, pcDstKeyHeader, len );
    p += len;

    if(cExpandFlg == 'P')
    {
        /*** 扩展标识 ***/
        *p ++ = 'P';

        /*** pad 标识 ***/
        memcpy(p, pcPad, 2);
        p += 2;

        /*** IV ***/
        if(iEncryptMode)
        {
            memcpy(p, pcIV, strlen(pcIV));
            p += strlen(pcIV);
        }

        /*** 校验值 ***/
        memcpy(p, pcSrcKeyCv, strlen(pcSrcKeyCv));
        p += strlen(pcSrcKeyCv);
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

    /*** 密钥密文, 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcDstKeyCipherByLmk)
    {
        strncpy(pcDstKeyCipherByLmk, p, len);
    }
    p += len;

    /*** 校验值, 16H ***/
    if(pcDstKeyCv)
    {
        strncpy(pcDstKeyCv, p, 16);
    }

    return HAR_OK;
}

int HSM_IC_VerifyArqc(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcData, char *pcArqc )
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "K6" ***/
    *p ++ = 'K';
    *p ++ = '6';

    /*** 模式标志, 1H, 0 – ARQC 验证 ***/
    *p ++ = '0';

    /*** MDK源密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PAN域，16H ***/
    rv = Tools_AddFieldPan(PANFMT_DISPER, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Parameter: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** ATC, 4H ***/
    memcpy(p, pcAtc, 4);
    p += 4;

    /*** 交易数据长度, 2H ***/
    if (!pcData)
    {
        len = 0;
    }
    else
    {
        len = strlen(pcData);
    }
    TASS_SPRINTF((char*)p, 3, "%02X", len / 2);
    p += 2;

    /*** 交易数据, n*2H ***/
    memcpy(p, pcData, len);
    p += len;

    /*** 分隔符 ***/
    *p ++ = ';';

    /*** ARQC, 16H ***/
    memcpy(p, pcArqc, 16);
    p += 16;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ARQC验证失败 ***/
    if (rv == 1)
    {
        /*** ARQC, 16H ***/
        if(pcArqc)
        {
            strncpy(pcArqc, (char *)p, 16);
        }
    }

    return rv;
}

int HSM_IC_GenerateArpc(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcArqc, char *pcArc, char *pcArpc/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "K6" ***/
    *p ++ = 'K';
    *p ++ = '6';

    /*** 模式标志, 1H, 2 – 产生ARPC ***/
    *p ++ = '2';

    /*** MDK源密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PAN域，16H ***/
    rv = Tools_AddFieldPan(PANFMT_DISPER, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Parameter: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** ATC, 4H ***/
    memcpy(p, pcAtc, 4);
    p += 4;

    /*** ARQC, 16H ***/
    memcpy(p, pcArqc, 16);
    p += 16;

    /*** ARC, 4H ***/
    memcpy(p, pcArc, 4);
    p += 4;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ARPC, 16H ***/
    if(pcArpc)
    {
        strncpy(pcArpc, (char *)p, iRspLen);
    }

    return 0;
}

int HSM_IC_EncryptPbocScript(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcData, char *pcCipher)
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "K2" ***/
    *p ++ = 'K';
    *p ++ = '2';

    /*** MDK源密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PAN域，16H ***/
    rv = Tools_AddFieldPan(PANFMT_DISPER, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Parameter: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** ATC, 4H ***/
    memcpy(p, pcAtc, 4);
    p += 4;

    /*** 交易数据长度, 3H ***/
    if (!pcData)
    {
        len = 0;
    }
    else
    {
        len = strlen(pcData);
    }

    TASS_SPRINTF((char*)p, 4, "%03X", len / 2);
    p += 3;

    /*** 交易数据, n*2H ***/
    memcpy(p, pcData, len);
    p += len;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** Cipher, 2*nH ***/
    if(pcCipher)
    {
        strncpy(pcCipher, (char *)p, iRspLen);
    }

    return 0;
}

int HSM_IC_GeneratePbocScriptMac(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcData, char *pcMac)
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "K4" ***/
    *p ++ = 'K';
    *p ++ = '4';

    /*** MDK源密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PAN域，16H ***/
    rv = Tools_AddFieldPan(PANFMT_DISPER, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Parameter: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** ATC, 4H ***/
    memcpy(p, pcAtc, 4);
    p += 4;

    /*** 交易数据长度, 3H ***/
    if (!pcData)
    {
        len = 0;
    }
    else
    {
        len = strlen(pcData);
    }

    TASS_SPRINTF((char*)p, 4, "%03X", len/2);
    p += 3;

    /*** 交易数据, n*2H ***/
    memcpy( p, pcData, len );
    p += len;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** MAC, 16H ***/
    if(pcMac)
    {
        strncpy(pcMac, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_IC_SymmKeyEncryptData(void *hSessionHandle,
    int iMode, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, char *pcIV,
    unsigned char *pucInputData, int iInputLength,
    unsigned char *pucOutputData/*out*/, int *piOutputLength/*out*/ )
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 1984 + 32;
    unsigned char aucCmd[1984 + 512] = {0};
    unsigned char aucRsp[1984 + 32] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "S3" ***/
    *p ++ = 'S';
    *p ++ = '3';

    /*** 加密算法模式，2H, 00–ECB, 01–CBC ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** 密钥类型, 3H, 000–KEK; 109–MDK; 309–MK-SMC; 00A–ZEK; 011–KMC;  ***/
    TASS_SPRINTF((char*)p, 4, "%s", pcType);
    p += 3;

    /*** 加密数据的密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 分散 ***/
    if (!pcDeriveData)
    {
        len = 0;
    }
    else
    {
        len = (int)strlen(pcDeriveData);
    }

    if (len > 32 * 8)
    {
        LOG_ERROR("Parameter: pcDeriveData length = [%d] is invalid, it must be less than %d.", 32 * 8);
        return HAR_PARAM_LEN;
    }

    rv = Tools_AddFieldDeriveData(1, len / 32, pcDeriveData, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: pcDeriveData length = [%d] is invalid.", len);
        return rv;
    }
    p += rv;

    /*** 会话密钥 ***/
    rv = Tools_AddFieldSessionData(iSessionKeyMode, pcSessionData, p);
    if(rv == HAR_PARAM_SESSION_KEY_DATA || rv == HAR_PARAM_SESSION_KEY_MODE)
    {
        LOG_ERROR("Parameter: iSessionKeyMode = [%d], pcSessionData = [%s] is invalid.",
                iSessionKeyMode, pcSessionData);
        return rv;
    }
    p += rv;

    /*** PAD标识, 2H ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPadMode);
    p += 2;

    /*** 数据长度, 4H ***/
    if (iInputLength > 1968)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1968.", iInputLength);
        return HAR_PARAM_LEN;
    }

    TASS_SPRINTF((char*)p, 5, "%04X", iInputLength);
    p += 4;

    /*** 数据, nB ***/
    memcpy(p, pucInputData, iInputLength);
    p += iInputLength;

    if (iMode == ENCRYPT_MODE_CBC)
    {
        if (!pcIV)
        {
            len = 0;
        }
        else
        {
            len = (int)strlen(pcIV);
        }

        if (len != 16 && len != 32)
        {
            LOG_ERROR("Parameter: pcIV length = [%d] is invalid, it must be 16 or 32.", len);
            return HAR_PARAM_VALUE;
        }

        /*** IV, 16H/32H ***/
        memcpy(p, pcIV, len);
        p += len;
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

    /*** Cipher Length, 4H ***/
    len = Tools_ConvertHexBuf2Int(p, 4);
    if(piOutputLength)
    {
        *piOutputLength = len;
    }
    p += 4;

    /*** Cipher Data, nB ***/
    if(pucOutputData)
    {
        memcpy(pucOutputData, p, *piOutputLength);
    }

    return HAR_OK;
}

int HSM_IC_SymmKeyDecryptData(void *hSessionHandle,
    int iMode, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, char *pcIV,
    unsigned char *pucInputData, int iInputLength,
    unsigned char *pucOutputData/*out*/, int *piOutputLength/*out*/)
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 1984 + 32;
    unsigned char aucCmd[1984 + 512] = {0};
    unsigned char aucRsp[1984 + 32] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "S4" ***/
    *p ++ = 'S';
    *p ++ = '4';

    /*** 加密算法模式，2H, 00–ECB, 01–CBC ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** 密钥类型, 3H, 000–KEK; 109–MDK; 309–MK-SMC; 00A–ZEK; 011–KMC; ***/
    TASS_SPRINTF((char*)p, 4, "%s", pcType);
    p += 3;

    /*** 加密数据的密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 分散 ***/
    if (!pcDeriveData)
    {
        len = 0;
    }
    else
    {
        len = (int)strlen(pcDeriveData);
    }

    if (len > 32 * 8)
    {
        LOG_ERROR("Parameter: pcDeriveData length = [%d] is invalid, it must be less than %d.", 32 * 8);
        return HAR_PARAM_LEN;
    }

    rv = Tools_AddFieldDeriveData(1, len / 32, pcDeriveData, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: pcDeriveData length = [%d] is invalid.", len);
        return rv;
    }
    p += rv;

    /*** 会话密钥 ***/
    rv = Tools_AddFieldSessionData(iSessionKeyMode, pcSessionData, p);
    if(rv == HAR_PARAM_SESSION_KEY_DATA || rv == HAR_PARAM_SESSION_KEY_MODE)
    {
        LOG_ERROR("Parameter: iSessionKeyMode = [%d], pcSessionData = [%s] is invalid.",
                iSessionKeyMode, pcSessionData);
        return rv;
    }
    p += rv;

    /*** PAD标识, 2H ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPadMode);
    p += 2;

    /*** 数据长度, 4H ***/
    if (iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    TASS_SPRINTF((char*)p, 5, "%04X", iInputLength);
    p += 4;

    /*** 数据, nB ***/
    memcpy(p, pucInputData, iInputLength);
    p += iInputLength;

    if (iMode == ENCRYPT_MODE_CBC)
    {
        if (!pcIV)
        {
            len = 0;
        }
        else
        {
            len = (int)strlen( pcIV );
        }

        if (len != 16 && len != 32)
        {
            LOG_ERROR("Parameter: pcIV length = [%d] is invalid, it must be 16 or 32.", len);
            return HAR_PARAM_VALUE;
        }

        /*** IV, 16H/32H ***/
        memcpy(p, pcIV, len);
        p += len;
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

    /*** data Length, 4H ***/
    len = Tools_ConvertHexBuf2Int(p, 4);
    if(piOutputLength)
    {
        *piOutputLength = len;
    }
    p += 4;

    /*** Cipher Data, nB ***/
    if(pucOutputData)
    {
        memcpy(pucOutputData, p, *piOutputLength);
    }

    return HAR_OK;
}

int HSM_IC_SymmKeyTransferCipher(
    int iSrcEncMode, char *pcSrcKeyType, int iSrcKeyIdx, char *pcSrcKeyCipherByLmk,
    char *pcSrcDeriveData, int iSrcSessionKeyMode, char *pcSrcSessionData,
    int iSrcPadMode, char *pcSrcIv,
    int iDstEncMode, char *pcDstKeyType, int iDstKeyIdx, char *pcDstKeyCipherByLmk,
    char *pcDstDeriveData, int iDstSessionKeyMode, char *pcDstSessionData,
    int iDstPadMode, char *pcDstIv,
    unsigned char *pucInputData, int iInputLength,
    unsigned char *pucOutputData/*out*/, int *piOutputLength/*out*/ )
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 1984 + 32;
    unsigned char aucCmd[1984 + 1024] = {0};
    unsigned char aucRsp[1984 + 32] = {0};
    unsigned char *p = aucCmd;

    /***  Command Code    "S5" ***/
    *p ++ = 'S';
    *p ++ = '5';

    /*** 源密钥加密算法模式，2H, 00–ECB, 01–CBC ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iSrcEncMode);
    p += 2;

    /*** 源密钥密钥类型, 3H, 000–KEK; 109–MDK; 309–MK-SMC; 00A–ZEK; 011–KMC;  ***/
    TASS_SPRINTF((char*)p, 4, "%s", pcSrcKeyType);
    p += 3;

    /*** 加密数据的源密钥 ***/
    rv = Tools_AddFieldKey(iSrcKeyIdx, pcSrcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyIdx or pcSrcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 分散(源密钥) ***/
    if (!pcSrcDeriveData)
    {
        len = 0;
    }
    else
    {
        len = (int)strlen(pcSrcDeriveData);
    }

    if (len > 32 * 8 )
    {
        LOG_ERROR("Parameter: pcSrcDeriveData length = [%d] is invalid, it must be less than %d.", 32 * 8);
        return HAR_PARAM_LEN;
    }

    rv = Tools_AddFieldDeriveData(1, len / 32, pcSrcDeriveData, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: pcSrcDeriveData length = [%d] is invalid.", len);
        return rv;
    }
    p += rv;

    /*** 会话密钥(源密钥) ***/
    rv = Tools_AddFieldSessionData(iSrcSessionKeyMode, pcSrcSessionData, p);
    if(rv == HAR_PARAM_SESSION_KEY_DATA || rv == HAR_PARAM_SESSION_KEY_MODE)
    {
        LOG_ERROR("Parameter: iSrcSessionKeyMode = [%d], pcSrcSessionData = [%s] is invalid.",
                iSrcSessionKeyMode, pcSrcSessionData);
        return rv;
    }
    p += rv;

    /*** (源密钥)PAD标识, 2H ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iSrcPadMode);
    p += 2;

    /*** (源密钥)IV, 16H/32H ***/
    if (iSrcEncMode == ENCRYPT_MODE_CBC)
    {
        if (!pcSrcIv)
        {
            len = 0;
        }
        else
        {
            len = (int)strlen(pcSrcIv);
        }

        if (len != 16 && len != 32)
        {
            LOG_ERROR("Parameter: pcSrcIv length = [%d] is invalid, it must be 16 or 32.", len);
            return HAR_PARAM_VALUE;
        }

        memcpy(p, pcSrcIv, len);
        p += len;
    }

    /*** 目的密钥加密算法模式，2H, 00–ECB, 01–CBC ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iDstEncMode);
    p += 2;

    /*** 目的密钥密钥类型, 3H, 000–KEK; 109–MDK; 309–MK-SMC; 00A–ZEK; 011–KMC;  ***/
    TASS_SPRINTF((char*)p, 4, "%s", pcDstKeyType);
    p += 3;

    /*** 加密数据的目的密钥 ***/
    rv = Tools_AddFieldKey(iDstKeyIdx, pcDstKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iDstKeyIdx or pcDstKeyCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /***  分散(目的密钥) ***/
    if (!pcDstDeriveData)
    {
        len = 0;
    }
    else
    {
        len = (int)strlen(pcDstDeriveData);
    }

    if (len > 32 * 8)
    {
        LOG_ERROR("Parameter: pcDstDeriveData length = [%d] is invalid, it must be less than %d.", 32 * 8);
        return HAR_PARAM_LEN;
    }

    rv = Tools_AddFieldDeriveData(1, len / 32, pcDstDeriveData, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: pcDstDeriveData length = [%d] is invalid.", len);
        return rv;
    }
    p += rv;

    /*** 会话密钥(目的密钥) ***/
    rv = Tools_AddFieldSessionData(iDstSessionKeyMode, pcDstSessionData, p);
    if(rv == HAR_PARAM_SESSION_KEY_DATA || rv == HAR_PARAM_SESSION_KEY_MODE)
    {
        LOG_ERROR("Parameter: iDstSessionKeyMode = [%d], pcDstSessionData = [%s] is invalid.",
                iDstSessionKeyMode, pcDstSessionData);
        return rv;
    }
    p += rv;

    /*** (目的密钥)PAD标识, 2H ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iDstPadMode);
    p += 2;

    /*** (目的密钥)IV, 16H/32H ***/
    if (iDstEncMode == ENCRYPT_MODE_CBC)
    {
        if (!pcDstIv)
        {
            len = 0;
        }
        else
        {
            len = (int)strlen(pcDstIv);
        }

        if (len != 16 && len != 32)
        {
            LOG_ERROR("Parameter: pcDstIv length = [%d] is invalid, it must be 16 or 32.", len);
            return HAR_PARAM_VALUE;
        }

        memcpy(p, pcDstIv, len);
        p += len;
    }

    /*** 输入数据长度, 4H ***/
    if (iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    TASS_SPRINTF((char*)p, 5, "%04X", iInputLength);
    p += 4;

    /***  数据, nB ***/
    memcpy(p, pucInputData, iInputLength);
    p += iInputLength;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** Output Data Length, 4H ***/
    len = Tools_ConvertHexBuf2Int(p, 4);
    if(piOutputLength)
    {
        *piOutputLength = len;
    }
    p += 4;

    /*** Output Data, nB ***/
    if(pucOutputData)
    {
        memcpy(pucOutputData, p, *piOutputLength);
    }

    return HAR_OK;
}

int HSM_IC_GeneralGenerateMac(
    int iMode, int iMacType, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, unsigned char *pcInputData, int iInputLength,
    char *pcIV, char *pcMac/*out*/, char *pcMacCiher)
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1968 + 512] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "S0" ***/
    *p ++ = 'S';
    *p ++ = '0';

    /*** MAC算法模式 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** MAC取值方式 ***/
    TASS_SPRINTF((char*)p, 3, "%s", iMacType);
    p += 2;

    /*** 密钥类型, 3H, 109–MDK; 209–MK-SMI; 000–KEK; 011–KMC; 008–ZAK; ***/
    TASS_SPRINTF((char*)p, 4, "%s", pcType);
    p += 3;

    /*** 计算MAC的密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 分散 ***/
    if (!pcDeriveData)
    {
        len = 0;
    }
    else
    {
        len = (int)strlen(pcDeriveData);
    }

    if (len > 32 * 3)
    {
        LOG_ERROR("Parameter: pcDeriveData length = [%d] is invalid, it must be less than %d.", 32 * 3);
        return HAR_PARAM_LEN;
    }

    rv = Tools_AddFieldDeriveData(1, len / 32, pcDeriveData, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: pcDeriveData length = [%d] is invalid.", len);
        return rv;
    }
    p += rv;

    /*** 会话密钥 ***/
    rv = Tools_AddFieldSessionData(iSessionKeyMode, pcSessionData, p);
    if(rv == HAR_PARAM_SESSION_KEY_DATA || rv == HAR_PARAM_SESSION_KEY_MODE)
    {
        LOG_ERROR("Parameter: iSessionKeyMode = [%d], pcSessionData = [%s] is invalid.",
                iSessionKeyMode, pcSessionData);
        return rv;
    }
    p += rv;

    /*** PAD标识, 2H ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPadMode);
    p += 2;

    /***  数据长度, 4H ***/
    TASS_SPRINTF((char*)p, 5, "%04X", iInputLength);
    p += 4;

    /***  数据, nB ***/
    memcpy(p, pcInputData, iInputLength);
    p += iInputLength;

    /*** IV, 16H/32H ***/
    memcpy(p, pcIV, strlen(pcIV));
    p += strlen(pcIV);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    len = (iMacType % 10) * 2;

    if(len)
    {
        /*** MAC, n*2H ***/
        if(pcMac)
        {
            strncpy(pcMac, (char *)p, len);
        }
        p += len;

        if(iRspLen > len)
        {
            /*** MAC密文 16H ***/
            if(pcMacCiher)
            {
                strncpy(pcMacCiher, (char *)p, 16);
            }
        }
    }
    else
    {
        /*** MAC, 32H ***/
        if(pcMac)
        {
            strncpy(pcMac, (char *)p, 32);
        }
    }

    return HAR_OK;
}

int HSM_IC_GenerateMac(
    void *hSessionHandle,
    int iMode, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, unsigned char *pcInputData, int iInputLength,
    char *pcIV, char *pcMac/*out*/ )
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1968 + 512] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "S0" ***/
    *p ++ = 'S';
    *p ++ = '0';

    /*** MAC算法模式 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** MAC取值方式 ***/
    TASS_SPRINTF((char*)p, 3, "%02X", 8);
    p += 2;

    /*** 密钥类型, 3H, 109–MDK; 209–MK-SMI; 000–KEK; 011–KMC; 008–ZAK; ***/
    TASS_SPRINTF((char*)p, 4, "%s", pcType);
    p += 3;

    /*** 计算MAC的密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 分散 ***/
    if (!pcDeriveData)
    {
        len = 0;
    }
    else
    {
        len = (int)strlen(pcDeriveData);
    }

    if (len > 32 * 3)
    {
        LOG_ERROR("Parameter: pcDeriveData length = [%d] is invalid, it must be less than %d.", 32 * 3);
        return HAR_PARAM_LEN;
    }

    rv = Tools_AddFieldDeriveData(1, len / 32, pcDeriveData, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: pcDeriveData length = [%d] is invalid.", len);
        return rv;
    }
    p += rv;

    /*** 会话密钥 ***/
    rv = Tools_AddFieldSessionData(iSessionKeyMode, pcSessionData, p);
    if(rv == HAR_PARAM_SESSION_KEY_DATA || rv == HAR_PARAM_SESSION_KEY_MODE)
    {
        LOG_ERROR("Parameter: iSessionKeyMode = [%d], pcSessionData = [%s] is invalid.",
                iSessionKeyMode, pcSessionData);
        return rv;
    }
    p += rv;

    /*** PAD标识, 2H ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPadMode);
    p += 2;

    /*** 数据长度, 4H ***/
    TASS_SPRINTF((char*)p, 5, "%04X", iInputLength);
    p += 4;

    /*** 数据, nB ***/
    memcpy(p, pcInputData, iInputLength);
    p += iInputLength;

    memcpy(p, pcIV, strlen(pcIV));
    p += strlen(pcIV);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** MAC, 16H ***/
    if(pcMac)
    {
        strncpy(pcMac, (char *)p, 16);
    }

    return HAR_OK;
}

int HSM_IC_VerifyArqc_GenARPC(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcData, char *pcArqc , char *pcArc,
    char *pcOutput/*out*/)
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "K6" ***/
    *p ++ = 'K';
    *p ++ = '6';

    /*** 模式标志, 1H, 1 – ARQC验证和ARPC产生 ***/
    *p ++ = '1';

    /*** MDK源密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PAN域，16H ***/
    rv = Tools_AddFieldPan(PANFMT_DISPER, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Parameter: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** ATC, 4H ***/
    memcpy(p, pcAtc, 4);
    p += 4;

    /*** 交易数据长度, 2H ***/
    if (!pcData)
    {
        len = 0;
    }
    else
    {
        len = strlen(pcData);
    }

    TASS_SPRINTF((char*)p, 3, "%02X", len / 2);
    p += 2;

    /*** 交易数据, n*2H ***/
    memcpy(p, pcData, len);
    p += len;

    /*** 分隔符 ***/
    *p ++ = ';';

    /*** ARQC, 16H ***/
    memcpy(p, pcArqc, 16);
    p += 16;

    /*** ARC, 4H ***/
    memcpy(p, pcArc, 4);
    p += 4;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ARQC验证失败 ***/
    if(rv == 1)
    {
        /*** ARQC, 16H ***/
        if(pcOutput)
        {
            strncpy(pcOutput, (char *)p, 16);
        }
        LOG_ERROR("Parameter: ARQC diagnostic data = [%s].", pcOutput);
    }

    /*** ARPC ***/
    if(rv == 0)
    {
        if(pcOutput)
        {
            strncpy(pcOutput, (char *)p, iRspLen);
        }
    }

    return rv;
}


int HSM_IC_GenerateMac_SM4(
    int iMode, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, unsigned char *pcInputData, int iInputLength,
    char *pcIV, char *pcMac/*out*/ )
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1968 + 512] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "S0" ***/
    *p ++ = 'S';
    *p ++ = '0';

    /*** MAC算法模式 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** MAC取值方式 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", 10);
    p += 2;

    /*** 密钥类型, 3H, 109–MDK; 209–MK-SMI; 000–KEK; 011–KMC; 008–ZAK; ***/
    TASS_SPRINTF((char*)p, 4, "%s", pcType);
    p += 3;

    /*** 计算MAC的密钥 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 分散 ***/
    if (!pcDeriveData)
    {
        len = 0;
    }
    else
    {
        len = (int)strlen(pcDeriveData);
    }

    if (len > 32 * 3)
    {
        LOG_ERROR("Parameter: pcDeriveData length = [%d] is invalid, it must be less than %d.", 32 * 3);
        return HAR_PARAM_LEN;
    }

    rv = Tools_AddFieldDeriveData(1, len / 32, pcDeriveData, p);
    if(rv == HAR_PARAM_DERIVE_DATA)
    {
        LOG_ERROR("%s", "Parameter: pcDeriveData length = [%d] is invalid.", len);
        return rv;
    }
    p += rv;

    /*** 会话密钥 ***/
    rv = Tools_AddFieldSessionData(iSessionKeyMode, pcSessionData, p);
    if(rv == HAR_PARAM_SESSION_KEY_DATA || rv == HAR_PARAM_SESSION_KEY_MODE)
    {
        LOG_ERROR("Parameter: iSessionKeyMode = [%d], pcSessionData = [%s] is invalid.",
                iSessionKeyMode, pcSessionData);
        return rv;
    }
    p += rv;

    /*** PAD标识, 2H ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPadMode);
    p += 2;

    /*** 数据长度, 4H ***/
    TASS_SPRINTF((char*)p, 5, "%04X", iInputLength);
    p += 4;

    /*** 数据, nB ***/
    memcpy(p, pcInputData, iInputLength);
    p += iInputLength;

    /*** IV, 16H/32H ***/
    memcpy(p, pcIV, strlen(pcIV));
    p += strlen(pcIV);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** MAC, 16H/32H ***/
    if(pcMac)
    {
        strncpy(pcMac, (char *)p, iRspLen);
    }

    return HAR_OK;
}


int HSM_GetDeviceBaseInfo(char *pcDmkCv/*OUT*/, char *pcVersion, char *pcSerial)
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[8] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /***  Command Code    "NC" ***/
    *p ++ = 'N';
    *p ++ = 'C';

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** Dmk CV, 16H ***/
    if(pcDmkCv)
    {
        strncpy(pcDmkCv, (char *)p, 16);
    }
    p += 16;

    /*** Version Info, 24A ***/
    if(pcVersion)
    {
        strncpy(pcVersion, (char *)p, 24);
    }
    p += 24;

    /*** Device Serial, 12A ***/
    if(pcSerial)
    {
        strncpy(pcSerial, (char *)p, 12);
    }

    return HAR_OK;
}


int HSM_CalculateHash(
    int iMode, unsigned char *pucInputData, int iInputLength,
    unsigned char *pucUserID, int iUserIDLen,
    unsigned char *pucSM2Pub, int iSM2PubLen,
    unsigned char *pucHash/*out*/, int *piHashLength/*out*/ )
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[4096 + 128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "3C" ***/
    *p ++ = '3';
    *p ++ = 'C';

    /*** 摘要算法模式，2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** 数据长度, 4N ***/
    if (iInputLength > 4 * 1024)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than %d.",
                iInputLength, 4 * 1024);
        return HAR_PARAM_LEN;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** 数据, nB ***/
    memcpy(p, pucInputData, iInputLength);
    p += iInputLength;

    /*** ; ***/
    *p ++ = ';';

    /*** UserId Length ***/
    if (iUserIDLen > 32)
    {
        LOG_ERROR("Parameter[iUserIDLen=%d] is Invalid.", iUserIDLen);
        return HAR_PARAM_LEN;
    }
    TASS_SPRINTF((char*)p, 5, "%04d", iUserIDLen);
    p += 4;

    /*** userID ***/
    memcpy(p, pucUserID, iUserIDLen);
    p += iUserIDLen;

    /*** DER编码的sm2公钥长度 ***/
    if (iSM2PubLen > 1024)
    {
        LOG_ERROR("Parameter: iSM2PubLen = [%d] is invalid.", iSM2PubLen);
        return HAR_PARAM_LEN;
    }
    TASS_SPRINTF((char*)p, 5, "%04d", iSM2PubLen);
    p += 4;

    /*** DER编码的sm2公钥 ***/
    memcpy(p, pucSM2Pub, iSM2PubLen);
    p += iSM2PubLen;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** Hash Length, 2N ***/
    len = Tools_ConvertDecBuf2Int(p, 2);
    if(piHashLength)
    {
        *piHashLength = len;
    }
    p += 2;

    /*** Cipher Data, nB ***/
    if(pucHash)
    {
        memcpy(pucHash, p, *piHashLength);
    }

    return HAR_OK;
}

int HSM_GenerateRandomData(void *hSessionHandle, int iRandomLength, unsigned char *pucRandomData/*out*/ )
{
    int rv = HAR_OK;
    int len;
    int iCmdLen;
    int iRspLen = 2048 + 128;
    unsigned char aucCmd[8] = {0};
    unsigned char aucRsp[2048 + 128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "CR" ***/
    *p ++ = 'C';
    *p ++ = 'R';

    /*** 数据长度, 4N ***/
    if (iRandomLength > 2048)
    {
        LOG_ERROR("Parameter: iRandomLength = [%d] is invalid, it must be 1 - 2048.", iRandomLength);
        return HAR_PARAM_LEN;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iRandomLength);
    p += 4;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** Cipher Data, nB ***/
    if(pucRandomData)
    {
        memcpy(pucRandomData, p, iRandomLength);
    }

    return HAR_OK;
}

int HSM_IC_OfflinePin_PlaintextPin(
                int iSrcKeyIdx, char *pcSrcKeyCipherByLmk,
                char *pcPan, char *pcAtc,
                char *pcPinBlkFmt1, char *pcPlaintextPin_New,
                char *pcPlaintextPin_Old, char *pcAccountNum,
                char *pcPinCipher/*out*/)
{
    int rv = HAR_OK;
    int iPinCipherLen = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code  "KX" ***/
    *p ++ = 'K';
    *p ++ = 'X';

    /*** 方案ID ***/
    TASS_SPRINTF((char*)p, 2, "%d", 9);
    p += 1;

    /*** 应用主密钥类型 ***/
    memcpy(p, "109", 3);
    p += 3;

    /*** 应用主密钥 ***/
    rv = Tools_AddFieldKey(iSrcKeyIdx, pcSrcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyIdx or pcSrcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PAN或PAN序列号 ***/
    memcpy(p, pcPan, 16);
    p += 16;

    /*** ATC ***/
    memcpy(p, pcAtc, 4);
    p += 4;

    /*** PINBLOCK格式1 ***/
    memcpy(p, pcPinBlkFmt1, 2);
    p += 2;

    /*** PIN输入模式, 固定为1 ***/
    memcpy(p, "1", 1);
    p += 1;

    /*** 明文PIN（新）***/
    memcpy(p, pcPlaintextPin_New, strlen(pcPlaintextPin_New));
    p += strlen(pcPlaintextPin_New);

    /*** 分隔符1 ***/
    memcpy(p, ";", 1);
    p += 1;

    if(!strcmp(pcPinBlkFmt1, "42"))
    {
        /*** 明文PIN（旧）***/
        memcpy( p, pcPlaintextPin_Old, strlen(pcPlaintextPin_Old) );
        p += strlen(pcPlaintextPin_Old);

        /*** 分隔符2 ***/
        memcpy( p, ";", 1 );
        p += 1;
    }

    /*** 帐号 ***/
    memcpy( p, pcAccountNum, strlen(pcAccountNum) );
    p += strlen(pcAccountNum);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN密文字节数 4H***/
    iPinCipherLen = Tools_ConvertHexBuf2Int(p, 4);
    p += 4;

    /*** PIN Cipher Data, n*2H ***/
    if(pcPinCipher)
    {
        strncpy(pcPinCipher, (char *)p, iPinCipherLen * 2);
    }

    return HAR_OK;
}

int HSM_IC_OfflinePin_CipherPin(
                int iSrcKeyIdx, char *pcSrcKeyCipherByLmk,
                int iDstKeyIdx, char *pcDstKeyCipherByLmk,
                char *pcPan, char *pcAtc,
                char *pcPinInputMode,
                char *pcSrcPinBlkFmt, char *pcDstPinBlkFmt,
                char *pcCipherPin_New, char *pcCipherPin_Old,
                char *pcAccountNum,
                char *pcPinCipher/*out*/)
{
    int rv = HAR_OK;
    int iPinCipherLen = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code  "KX" ***/
    *p ++ = 'K';
    *p ++ = 'X';

    /*** 方案ID ***/
    TASS_SPRINTF((char*)p, 2, "%d", 9);
    p += 1;

    /*** 应用主密钥类型 ***/
    memcpy(p, "109", 3);
    p += 3;

    /*** 应用主密钥 ***/
    rv = Tools_AddFieldKey(iDstKeyIdx, pcDstKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iDstKeyIdx or pcDstKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PAN或PAN序列号 ***/
    memcpy(p, pcPan, 16);
    p += 16;

    /*** ATC ***/
    memcpy(p, pcAtc, 4);
    p += 4;

    /*** PINBLOCK格式1 ***/
    memcpy(p, pcDstPinBlkFmt, 2);
    p += 2;

    /*** PIN输入模式, 该参数只能为2或3 ***/
    memcpy(p, pcPinInputMode, 1);
    p += 1;

    /*** PINBLOCK格式2 ***/
    memcpy(p, pcSrcPinBlkFmt, 2);
    p += 2;

    /*** PIN密文（新）***/
    memcpy(p, pcCipherPin_New, strlen(pcCipherPin_New));
    p += strlen(pcCipherPin_New);

    if(!strcmp(pcDstPinBlkFmt, "42"))
    {
        /*** PIN密文（旧）***/
        memcpy(p, pcCipherPin_Old, strlen(pcCipherPin_Old));
        p += strlen(pcCipherPin_Old);
    }

    /*** 源PIN 加密密钥密钥 ***/
    rv = Tools_AddFieldKey(iSrcKeyIdx, pcSrcKeyCipherByLmk, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyIdx or pcSrcKeyCipherByLmk is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 帐号 ***/
    memcpy(p, pcAccountNum, strlen(pcAccountNum));
    p += strlen(pcAccountNum);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN密文字节数 4H***/
    iPinCipherLen = Tools_ConvertHexBuf2Int(p, 4);
    p += 4;

    /*** PIN Cipher Data, n*2H ***/
    if(pcPinCipher)
    {
        strncpy(pcPinCipher, (char *)p, iPinCipherLen * 2);
    }

    return HAR_OK;
}


