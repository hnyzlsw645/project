/*----------------------------------------------------------------------|
|    hsmapi_racal.c                                                     |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310������ӿ��׿��������������                |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-03. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#ifdef WIN32
#include <windows.h>
#endif

#include "hsmapi_racal.h"
#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmsocket.h"

int HSM_RCL_GenerateRandomPin(char *pcPAN, int iPinLength, char *pcPinCipherByLmk/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "JA" ***/
    *p ++ = 'J';
    *p ++ = 'A';

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** Pin Length ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPinLength);
    p += 2;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN, LH ***/
    if(pcPinCipherByLmk)
    {
        strncpy(pcPinCipherByLmk, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_EncryptPin_LMK(char *pcPlainPin, char *pcPAN, char *pcPinCipherByLmk/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "BA" ***/
    *p ++ = 'B';
    *p ++ = 'A';

    /*** PIN ***/
    memcpy(p, pcPlainPin, strlen(pcPlainPin));
    p += strlen(pcPlainPin);
    *p ++ = 'F';

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN, LH ***/
    if(pcPinCipherByLmk)
    {
        strncpy(pcPinCipherByLmk, (char *)p, iRspLen);
    }

    return rv;
}

int HSM_RCL_DecryptPin_LMK(void *hSessionHandle,char *pcPinCipherByLmk, char *pcPAN, char *pcPlainPin/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "NG" ***/
    *p ++ = 'N';
    *p ++ = 'G';

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** Cipher PIN ***/
    memcpy(p, pcPinCipherByLmk, strlen(pcPinCipherByLmk));
    p += strlen(pcPinCipherByLmk);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN, LH ***/
    if(pcPlainPin)
    {
        strncpy(pcPlainPin, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_TransferCipherPin_Lmk2Zpk(void *hSessionHandle,
    int iZpkIdx, char *pcZpkCipherByLmk, int iPinFmt,
    char *pcPAN, char *pcPinCipherByLmk, char *pcPinCipherByZpk/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "JG" ***/
    *p ++ = 'J';
    *p ++ = 'G';

    /*** Dst ZPK ***/
    rv = Tools_AddFieldKey(iZpkIdx, pcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iZpkIdx or pcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Pin Block Format ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPinFmt);
    p += 2;

    /*** PAN ***/
    rv = Tools_AddFieldPan(iPinFmt, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** Cipher Pin_LMK ***/
    memcpy(p, pcPinCipherByLmk, strlen(pcPinCipherByLmk));
    p += strlen(pcPinCipherByLmk);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN, 16H/32H ***/
    if(pcPinCipherByZpk)
    {
        strncpy(pcPinCipherByZpk, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_TransferCipherPin_Zpk2Lmk(
    void *hSessionHandle,
    int iZpkIdx, char *pcZpkCipherByLmk, int iPinFmt,
    char *pcPAN, char *pcPinCipherByZpk, char *pcPinCipherByLmk/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "JE" ***/
    *p ++ = 'J';
    *p ++ = 'E';

    /*** Src ZPK ***/
    rv = Tools_AddFieldKey(iZpkIdx, pcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iZpkIdx or pcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Cipher Pin_ZPK, 16H/32H ***/
    memcpy(p, pcPinCipherByZpk, strlen(pcPinCipherByZpk));
    p += strlen( pcPinCipherByZpk );

    /*** Pin Block Format ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPinFmt);
    p += 2;

    /*** PAN ***/
    rv = Tools_AddFieldPan(iPinFmt, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN_Lmk, LH ***/
    if(pcPinCipherByLmk)
    {
        strncpy(pcPinCipherByLmk, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_TransferCipherPin_Zpk2Zpk(
    int iSrcZpkIdx, char *pcSrcZpkCipherByLmk, int iDstZpkIdx, char *pcDstZpkCipherByLmk,
    int iSrcPinFmt, int iDstPinFmt,
    char *pcSrcPAN, char *pcDstPAN,
    char *pcSrcPinCipherByZpk, char *pcDstPinCipherByZpk/*out*/ )
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TI" ***/
    *p ++ = 'T';
    *p ++ = 'I';

    /*** Src Key Type, 1��TPK; 2��ZPK ***/
    *p ++ = '2';

    /*** Src ZPK ***/
    rv = Tools_AddFieldKey(iSrcZpkIdx, pcSrcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iSrcZpkIdx or pcSrcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Dst Key Type, 1��TPK; 2��ZPK ***/
    *p ++ = '2';

    /*** Dst ZPK ***/
    rv = Tools_AddFieldKey(iDstZpkIdx, pcDstZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iDstZpkIdx or pcDstZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Pin Length, "12" ***/
    TASS_SPRINTF((char*)p, 3, "%2d", 12);
    p += 2;

    /*** Cipher Pin_ZPK1, 16H/32H ***/
    memcpy(p, pcSrcPinCipherByZpk, strlen(pcSrcPinCipherByZpk));
    p += strlen(pcSrcPinCipherByZpk);

    /*** Pin Block Format 1 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iSrcPinFmt);
    p += 2;

    /*** Src PAN ***/
    rv = Tools_AddFieldPan(iSrcPinFmt, pcSrcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcSrcPAN = [%s] is invaild.", pcSrcPAN);
        return rv;
    }
    p += rv;

    /*** Pin Block Format 2 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iDstPinFmt);
    p += 2;

    /*** Dst PAN ***/
    rv = Tools_AddFieldPan(iDstPinFmt, pcDstPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcDstPAN = [%s] is invaild.", pcDstPAN);
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN_Zpk2, 16H/32H ***/
    if(pcDstPinCipherByZpk)
    {
        strncpy(pcDstPinCipherByZpk, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_GenerateIBMPinOffset(
    int iPvkIdx, char *pcPvkCipherByLmk,
    char *pcPinCipherByLmk, int iMinLength,
    char *pcPAN, char *pcDecimalTable, char *pcPinVerifyData,
    char *pcPinOffset/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "DE" ***/
    *p ++ = 'D';
    *p ++ = 'E';

    /*** PVK ***/
    rv = Tools_AddFieldKey(iPvkIdx, pcPvkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iPvkIdx or pcPvkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Cipher Pin_Lmk ***/
    memcpy(p, pcPinCipherByLmk, strlen(pcPinCipherByLmk));
    p += strlen(pcPinCipherByLmk);

    /*** PINУ�鳤��, 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMinLength);
    p += 2;

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** ʮ����ת����, 16N ***/
    memcpy(p, pcDecimalTable, 16);
    p += 16;

    /*** PINУ������, 12A ***/
    memcpy(p, pcPinVerifyData, 12);
    p += 12;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN Offset, 12H ***/
    if(pcPinOffset)
    {
        strncpy(pcPinOffset, (char *)p, 12);
    }

    return HAR_OK;
}

int HSM_RCL_VerifyZonePinBlock_PinOffset(
    int iZpkIdx, char *pcZpkCipherByLmk,
    int iPvkIdx, char *pcPvkCipherByLmk,
    char *pcPinBlock_Zpk, int iPinFormat, int iMinLength,
    char *pcPAN, char *pcDecimalTable, char *pcPinVerifyData,
    char *pcPinOffset)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "EA" ***/
    *p ++ = 'E';
    *p ++ = 'A';

    /*** ZPK ***/
    rv = Tools_AddFieldKey(iZpkIdx, pcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iZpkIdx or pcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PVK ***/
    rv = Tools_AddFieldKey(iPvkIdx, pcPvkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iPvkIdx or pcPvkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PIN��󳤶�, 2N, 12 ***/
    *p ++ = '1';
    *p ++ = '2';

    /*** Cipher PinBlock_ZPK ***/
    memcpy(p, pcPinBlock_Zpk, strlen(pcPinBlock_Zpk));
    p += strlen( pcPinBlock_Zpk );

    /*** PIN��ʽ����, 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPinFormat);
    p += 2;

    /*** PINУ�鳤��, 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMinLength);
    p += 2;

    /*** PAN ***/
    rv = Tools_AddFieldPan(iPinFormat, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Parameter: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** ʮ����ת����, 16N ***/
    memcpy(p, pcDecimalTable, 16);
    p += 16;

    /*** PINУ������, 12A ***/
    memcpy(p, pcPinVerifyData, 12);
    p += 12;

    /*** PIN Offset, 12H ***/
    memcpy(p, pcPinOffset, 12);
    p += 12;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


int HSM_RCL_GeneratePVV(
    int iPvkIdx, char *pcPvkCipherByLmk, int iPvkID,
    char *pcPinCipherByLmk, char *pcPAN,
    char *pcPVV/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "DG" ***/
    *p ++ = 'D';
    *p ++ = 'G';

    /*** PVK ***/
    rv = Tools_AddFieldKey(iPvkIdx, pcPvkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPvkIdx or pcPvkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Cipher Pin_Lmk ***/
    memcpy(p, pcPinCipherByLmk, strlen(pcPinCipherByLmk));
    p += strlen(pcPinCipherByLmk);

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Parameter: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** PVK ID ***/
    if (iPvkID < 10)
    {
        *p ++ = iPvkID + '0';
    }
    else if (iPvkID <= 15)
    {
        *p ++ = iPvkID-10 + 'A';
    }
    else
    {
        LOG_ERROR("Parameter: iPvkID[%d] is Invalid.", iPvkID);
        return HAR_PARAM_KEY_ID;
    }

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PVV, 4N ***/
    if(pcPVV)
    {
        strncpy(pcPVV, (char *)p, 4);
    }

    return HAR_OK;
}

int HSM_RCL_GenerateCVV(
    int iCvkIdx, char *pcCvk_Lmk,
    char *pcPAN, char *pcExpirationDate, char *pcServiceCode,
    char *pcCVV/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "CW" ***/
    *p ++ = 'C';
    *p ++ = 'W';

    /*** CVK ***/
    rv = Tools_AddFieldKey(iCvkIdx, pcCvk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iCvkIdx or pcCvk_Lmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** All PAN ***/
    memcpy(p, pcPAN, strlen(pcPAN));
    p += strlen(pcPAN);

    /*** ; ***/
    *p ++ = ';';

    /*** Valid Time ***/
    memcpy(p, pcExpirationDate, 4);
    p += 4;

    /*** Service Code ***/
    memcpy(p, pcServiceCode, 3);
    p += 3;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** CVV, 3N ***/
    if(pcCVV)
    {
        strncpy(pcCVV, (char *)p, 3);
    }

    return HAR_OK;
}

int HSM_RCL_VerifyCVV(
    int iCvkIdx, char *pcCvk_Lmk,
    char *pcPAN, char *pcExpirationDate, char *pcServiceCode,
    char *pcCVV)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "CY" ***/
    *p ++ = 'C';
    *p ++ = 'Y';

    /*** CVK ***/
    rv = Tools_AddFieldKey(iCvkIdx, pcCvk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iCvkIdx or pcCvk_Lmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ��У���CVV, 3N ***/
    memcpy(p, pcCVV, 3);
    p += 3;

    /*** All PAN ***/
    memcpy(p, pcPAN, strlen(pcPAN));
    p += strlen( pcPAN );

    /*** ; ***/
    *p ++ = ';';

    /*** Valid Time, 4N ***/
    memcpy( p, pcExpirationDate, 4 );
    p += 4;

    /*** Service Code, 3N ***/
    memcpy(p, pcServiceCode, 3);
    p += 3;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

int HSM_RCL_EncryptData(
    int iBlockFlg, int iAlgoMode,
    int iZekIdx, char *pcZekCipherByLmk,
    unsigned char *pucIv/*in&out*/, int iIvLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 1984 + 128;
    unsigned char aucCmd[1968 + 128] = {0};
    unsigned char aucRsp[1984 + 128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1968)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1968.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E0" ***/
    *p ++ = 'E';
    *p ++ = '0';

    /*** ���Ŀ��ʶ, 1N ***/
    *p ++ = (unsigned char)(iBlockFlg + '0');

    /*** �����ʶ, 1N, 0 - ����; 1 - ���� ***/
    *p ++ = '0';

    /*** �㷨��ʶ, 1N, 1 - ECB; 2 - CBC ***/
    *p ++ = (unsigned char)(iAlgoMode + '0');

    /*** ��Կ����, 1N, 0 - ZEK ***/
    *p ++ = '0';

    /*** ZEK ***/
    rv = Tools_AddFieldKey(iZekIdx, pcZekCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZekIdx or pcZekCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** �������ݸ�ʽ, 1N, 0 �C Binaryģʽ, 1 �C Expanded Hexģʽ ***/
    *p ++ = '0';

    /*** ������ݸ�ʽ, 1N, 0 �C Binaryģʽ, 1 �C Expanded Hexģʽ ***/
    *p ++ = '0';

    /*** Pad ģʽ+Pad �ַ�+Pad ������ʶ, ����PBOC MAC��ǿ�����80ģʽ��***/
    memcpy(p, "180000", 6);
    p += 6;

    /*** IV ***/
    if (iAlgoMode != ENCRYPT_MODE_ECB)
    {
        memcpy(p, pucIv, iIvLength);
        p += iIvLength;
    }

    /*** ���ݳ���, 3H ***/
    TASS_SPRINTF((char*)p, 4, "%03X", iInputLength);
    p += 3;

    /*** �������ݣ�nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ������ݵĸ�ʽ, 1N, 0 �C Binaryģʽ, 1 �C Expanded Hexģʽ ***/
    p ++;

    /*** ������ݳ���, 3H ***/
    len = Tools_ConvertHexBuf2Int(p, 3);
    if(piOutputLength)
    {
        *piOutputLength = len;
    }
    p += 3;

    /*** ������ݣ�nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, *piOutputLength);
    }
    p += *piOutputLength;

    /*** iv ***/
    if ((iAlgoMode != ENCRYPT_MODE_ECB) && (iBlockFlg==1 || iBlockFlg ==2))
    {
        if(pucIv)
        {
            memcpy(pucIv, p, iIvLength);
        }
    }

    return HAR_OK;
}

int HSM_RCL_DecryptData(
    int iBlockFlg, int iAlgoMode,
    int iZekIdx, char *pcZekCipherByLmk,
    unsigned char *pucIv/*in&out*/, int iIvLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 1968 + 128;
    unsigned char aucCmd[1984 + 128] = {0};
    unsigned char aucRsp[1968 + 128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E0" ***/
    *p ++ = 'E';
    *p ++ = '0';

    /*** ���Ŀ��ʶ, 1N ***/
    *p ++ = (unsigned char)(iBlockFlg + '0');

    /*** �����ʶ, 1N, 0 - ����; 1 - ���� ***/
    *p ++ = '1';

    /*** �㷨��ʶ, 1N, 1 - ECB; 2 - CBC ***/
    *p ++ = (unsigned char)(iAlgoMode + '0');

    /*** ��Կ����, 1N, 0 - ZEK ***/
    *p ++ = '0';

    /*** ZEK*/
    rv = Tools_AddFieldKey(iZekIdx, pcZekCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZekIdx or pcZekCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** �������ݸ�ʽ, 1N, 0 �C Binaryģʽ, 1 �C Expanded Hexģʽ ***/
    *p ++ = '0';

    /*** ������ݸ�ʽ, 1N, 0 �C Binaryģʽ, 1 �C Expanded Hexģʽ ***/
    *p ++ = '0';

    /*** Pad ģʽ+Pad �ַ�+Pad ������ʶ, ����PBOC MAC��ǿ�����80ģʽ��***/
    memcpy(p, "180000", 6);
    p += 6;

    /*** IV ***/
    if (iAlgoMode != ENCRYPT_MODE_ECB)
    {
        memcpy(p, pucIv, iIvLength);
        p += iIvLength;
    }

    /*** ���ݳ���, 3H ***/
    TASS_SPRINTF((char*)p, 4, "%03X", iInputLength);
    p += 3;

    /*** �������ݣ�nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ������ݵĸ�ʽ, 1N, 0 �C Binaryģʽ, 1 �C Expanded Hexģʽ ***/
    p ++;

    /*** ������ݳ���, 3H ***/
    len = Tools_ConvertHexBuf2Int(p, 3);
    if(piOutputLength)
    {
        *piOutputLength = len;
    }
    p += 3;

    /*** ������ݣ�nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, *piOutputLength);
    }
    p += *piOutputLength;

    /*** iv ***/
    if ((iAlgoMode != ENCRYPT_MODE_ECB) && (iBlockFlg==1 || iBlockFlg ==2))
    {
        if(pucIv)
        {
            memcpy(pucIv, p, iIvLength);
        }
    }

    return HAR_OK;
}

int HSM_RCL_ZpkGenCbcMac(
    int iBlockFlg,
    int iZpkIdx, char *pcZpkCipherByLmk,
    unsigned char *pucIv/*in&out*/, int iIvLength,
    unsigned char *pucInput, int iInputLength,
    int iMacLen,
    char *pcOutput/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[4095 + 128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 4095)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 4095.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "UQ" ***/
    *p ++ = 'U';
    *p ++ = 'Q';

    /*** ���Ŀ��ʶ, 1N ***/
    *p ++ = (unsigned char)(iBlockFlg + '0');

    /*** ZPK ***/
    rv = Tools_AddFieldKey(iZpkIdx, pcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZpkIdx or pcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** IV ***/
    if(iBlockFlg == 2 || iBlockFlg == 3)
    {
        memcpy(p, pucIv, iIvLength);
        p += iIvLength;
    }

    /*** ���ݳ���, 3H ***/
    TASS_SPRINTF((char*)p, 4, "%03X", iInputLength);
    p += 3;

    /*** �������ݣ�nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** �����MAC����, 2H ***/
    TASS_SPRINTF((char*)p, 3, "%02X", iMacLen);
    p += 2;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ������ݣ�n*2H ***/
    if(pcOutput)
    {
        strncpy(pcOutput, (char *)p, iRspLen);
    }

    return HAR_OK;
}

/**********************************
* �ӿ����� ��ZAK/TAK ����X9.9��X9.19�ı���MAC
* ʹ��ָ�MS
* �޸ļ�¼��
*         20140830 - ����IV���������޸����ݳ��Ȳ���
*/
int HSM_RCL_ZakAndTakGenCbcMac(
            int iBlockFlg, int iKeyType,
            int iKeyLength,int iDataType,
            int iKeyIdx, char *pcKey_Lmk,
            unsigned char *pucIv, int iIvLength,
            unsigned char *pucInput, int iInputLength,
            unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 64;
    unsigned char aucCmd[4096 + 128] = {0};
    unsigned char aucRsp[64] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 4096)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 4096.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "MS" ***/
    *p ++ = 'M';
    *p ++ = 'S';

    /*** ���Ŀ��ʶ, 1N ***/
    *p ++ = (unsigned char)(iBlockFlg + '0');

    /*** ��Կ����, 1N,  0 �C TAK    1 �C ZAK ***/
    *p ++ = (unsigned char)(iKeyType + '0');

    /*** ��Կ����, 1N, 0 �C 8�ֽڣ�������DES��Կ        1 �C 16�ֽڣ�˫����DES��SM1��SM4��AES��Կ ***/
    *p ++ = (unsigned char)(iKeyLength + '0');

    /*** ��������, 1N, 0 �C ������            1 �C ��չʮ������ ***/
    *p ++ = (unsigned char)(iDataType + '0');

    /*** KEY ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKey_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKey_Lmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** IV ***/
    memcpy((char*)p, pucIv, iIvLength);
    p += iIvLength;

    /*** ���ݳ���, 4H ***/
    TASS_SPRINTF((char*)p, 5, "%04X", iInputLength);
    p += 4;

    /*** �������ݣ�nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ��������ݳ��� ***/
    if(piOutputLength)
    {
        *piOutputLength = iRspLen;
    }

    /*** ������ݣ�nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, *piOutputLength);
    }

    return HAR_OK;
}


int HSM_RCL_GenWorkingKey(
    void *hSessionHandle,
    int iGeneratMode, char *pcKeyType, char cKeyFlg_Lmk,
    int iZmkIdx, char *pcZmkCipher, char cKeyFlg_Zmk, char cKeyStorageFlg,
    int iKeyIdx, char *pcKeyTag, char *pcKeyCipherByLmk/*OUT*/,
    char *pcKeyCipherByZmk/*OUT*/, char *pcKeyCv/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "A0" ***/
    *p ++ = 'A';
    *p ++ = '0';

    /*** ����ģʽ    0 - ������Կ        1 - ������Կ����ZMK�¼��� ***/
    *p ++= (unsigned char)(iGeneratMode + '0');

    /*** ������Կ���� ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** ��Կ��ʶ ***/
    *p ++ = cKeyFlg_Lmk;

    if(iGeneratMode == 1)
    {
        /*** ZMK��Կ ***/
        rv = Tools_AddFieldKey(iZmkIdx, pcZmkCipher, p);
        if (rv == HAR_PARAM_VALUE)
        {
            LOG_ERROR("%s", "Parameter: iZmkIdx or pcZmkCipher is invalid.");
            return HAR_PARAM_KEY_ID;
        }
        p += rv;

        /*** ��Կ��ʶ ***/
        *p ++=  cKeyFlg_Zmk;
    }

    if(cKeyStorageFlg == 'K')
    {
        /*** ��Կ�洢��ʶ ***/
        *p ++= cKeyStorageFlg;

        /*** ��Կ���� ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iKeyIdx);
        p += 4;

        /*** ��Կ��ǩ���� ***/
        TASS_SPRINTF((char*)p, 3, "%02d", (int)strlen(pcKeyTag));
        p += 2;

        /*** ��Կ��ǩ ***/
        memcpy(p, pcKeyTag, strlen(pcKeyTag));
        p += strlen(pcKeyTag);
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

    if(iGeneratMode)
    {
        /*** LMK�¼��ܵ����� ***/
        len = Tools_GetFieldKeyLength((char *)p);
        if(pcKeyCipherByLmk)
        {
            strncpy(pcKeyCipherByLmk, (char *)p, len);
        }
        p += len;

        /*** ZMK�¼��ܵ����� ***/
        len = Tools_GetFieldKeyLength((char *)p);
        if(pcKeyCipherByZmk)
        {
            strncpy(pcKeyCipherByZmk, (char *)p, len);
        }
        p += len;
    }
    else
    {
        /*** LMK�¼��ܵ����� ***/
        len = Tools_GetFieldKeyLength((char *)p);
        if(pcKeyCipherByLmk)
        {
            strncpy(pcKeyCipherByLmk, (char *)p, len);
        }
        p += len;
    }

    /*** ��ԿУ��ֵ ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

int HSM_RCL_ImportKey_A6(
    void *hSessionHandle,
    char *pcKeyType, int iZmkIdx, char *pcZmkCipher,
    char *pcKeyCipherByZmk, char cKeyFlg_Lmk, char cKeyStorageFlg,
    int iKeyIdx, char *pcKeyTag, char *pcKeyCipherByLmk/*OUT*/,
    char *pcKeyCv/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "A6" ***/
    *p ++ = 'A';
    *p ++ = '6';

    /*** ������Կ���� ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** ZMK��Կ ***/
    rv = Tools_AddFieldKey(iZmkIdx, pcZmkCipher, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZmkIdx or pcZmkCipher is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ZMK�¼��ܵ����� ***/
    memcpy(p, pcKeyCipherByZmk, strlen(pcKeyCipherByZmk));
    p += strlen(pcKeyCipherByZmk);

    /*** ��Կ��ʶ ***/
    *p ++ = cKeyFlg_Lmk;

    if(cKeyStorageFlg == 'K')
    {
        rv = Tools_AddFieldSavedKey(iKeyIdx, pcKeyTag, p);
        if(rv == HAR_PARAM_VALUE)
        {
            LOG_ERROR("Parameter: pcKeyTag length = [%d] is invalid.", strlen(pcKeyTag));
            return rv;
        }
        p += rv;
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

    /*** LMK�¼��ܵ����� ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByLmk)
    {
        strncpy(pcKeyCipherByLmk, (char *)p, len);
    }
    p += len;

    /*** ��ԿУ��ֵ ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

int HSM_RCL_ExportKey_A8(
    char *pcKeyType, int iZmkIdx, char *pcZmkCipher,
    int iKeyIdx, char *pcKeyCipherByLmk, char cKeyFlg_Zmk,
    char *pcKeyCipherByZmk/*OUT*/,
    char *pcKeyCv/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "A8" ***/
    *p ++ = 'A';;
    *p ++ = '8';

    /*** ������Կ���� ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** ZMK��Կ ***/
    rv = Tools_AddFieldKey(iZmkIdx, pcZmkCipher, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZmkIdx or pcZmkCipher is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** LMK�¼��ܵ����� ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ��Կ��ʶ ***/
    *p ++ = cKeyFlg_Zmk;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ZMK�¼��ܵ����� ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByZmk)
    {
        strncpy(pcKeyCipherByZmk, (char *)p, len);
    }
    p += len;

    /*** ��ԿУ��ֵ ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}


int HSM_RCL_LoadFormatData(char* pcFormatData)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024 + 2] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(pcFormatData == NULL)
    {
        LOG_ERROR("Parameter: pcFormatData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcFormatData) > 1024)
    {
        LOG_ERROR("Parameter: pcFormatData length = [%d] is invalid.", strlen(pcFormatData));
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "PA" ***/
    *p ++ = 'P';
    *p ++ = 'A';

    /*** ��ʽ���� ***/
    memcpy(p, pcFormatData, strlen(pcFormatData));
    p += strlen(pcFormatData);

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


int HSM_RCL_GenAndPrintKeyElement(char* pcKeyType, char cKeyFlg, char* pcPrintDomain, char* pcKeyCipherByLmk/*OUT*/, char* pcKCV/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024 + 6] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(pcKeyType == NULL)
    {
        LOG_ERROR("Parameter: pcKeyType = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcKeyType) != 3)
    {
        LOG_ERROR("Parameter: pcKeyType length = [%d] is invalid.", strlen(pcKeyType));
        return HAR_PARAM_LEN;
    }

    if(pcPrintDomain == NULL)
    {
        LOG_ERROR("Parameter: pcPrintDomain = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPrintDomain) > 1024)
    {
        LOG_ERROR("Parameter: pcPrintDomain = [%d] is invalid.", strlen(pcPrintDomain));
        return HAR_PARAM_ISNULL;
    }

    /*** Command Code    "A2" ***/
    *p ++ = 'A';
    *p ++ = '2';

    /*** ������Կ���� ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** ��Կ��ʶ��LMK��***/
    *p++ = cKeyFlg;

    /*** ��ӡ�� ***/
    memcpy(p, pcPrintDomain, strlen(pcPrintDomain));
    p += strlen(pcPrintDomain);

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ��Կ����(LMK) ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByLmk)
    {
        strncpy(pcKeyCipherByLmk, (char *)p, len);
    }
    p += len;

    /*** ��ԿУ��ֵ ***/
    if(pcKCV)
    {
        strncpy(pcKCV, (char *)p, 8);
    }

    return HAR_OK;
}

int HSM_RCL_SyntheticKey_KeyCipher(int iElementNum, char* pcKeyType, char cKeyFlg,
    char* pcKeyElemnet, char* pcKeyCipherByLmk/*OUT*/, char* pcKCV/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024 + 6] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(iElementNum < 2 || iElementNum > 8)
    {
        LOG_ERROR("Parameter: iElementNum = [%d] is invalid.It must be 2 -- 8.", iElementNum);
        return HAR_PARAM_ELEMENT_NUM;
    }

    if(pcKeyType == NULL)
    {
        LOG_ERROR("Parameter: pcKeyType = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcKeyType) != 3)
    {
        LOG_ERROR("Parameter: pcKeyType length = [%d] is invalid.", strlen(pcKeyType));
        return HAR_PARAM_LEN;
    }

    if(pcKeyElemnet == NULL)
    {
        LOG_ERROR("Parameter: pcKeyElemnet = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcKeyElemnet) > 1024)
    {
        LOG_ERROR("Parameter: pcKeyElemnet = [%d] is invalid.", strlen(pcKeyElemnet));
        return HAR_PARAM_ISNULL;
    }

    if(pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter: pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcKCV == NULL)
    {
        LOG_ERROR("Parameter: pcKCV = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** Command Code    "A4" ***/
    *p ++ = 'A';
    *p ++ = '4';

    /*** ��Կ�ɷ� ***/
    *p ++ = iElementNum + '0';

    /*** ��Կ���� ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** ��Կ��ʶ��LMK��***/
    *p++ = cKeyFlg;

    /*** ��Կ�ɷ� ***/
    memcpy(p, pcKeyElemnet, strlen(pcKeyElemnet));
    p += strlen(pcKeyElemnet);

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ��Կ����(LMK) ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByLmk)
    {
        strncpy(pcKeyCipherByLmk, (char *)p, len);
    }
    p += len;

    /*** ��ԿУ��ֵ ***/
    if(pcKCV)
    {
        strncpy(pcKCV, (char *)p, 8);
    }

    return HAR_OK;
}

int HSM_RCL_KeyTypeConversion(
    char *pcSrcKeyType,
    int  iSrcKeyIdx,
    char *pcSrcKeyCipherByLmk,
    char *pcDstKeyType,
    char cDstScheme,
    char *pcDstKeyCipherByLmk/*OUT*/,
    char *pcDstKeyCv/*OUT*/ )
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "AN" ***/
    *p ++ = 'A';
    *p ++ = 'N';

    /*** Դ��Կ���� ***/
    memcpy(p, pcSrcKeyType, strlen(pcSrcKeyType));
    p += strlen( pcSrcKeyType );

    /*** Դ��Կ ***/
    rv = Tools_AddFieldKey(iSrcKeyIdx, pcSrcKeyCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyIdx or pcSrcKeyCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Ŀ����Կ���� ***/
    memcpy(p, pcDstKeyType, strlen( pcDstKeyType ));
    p += strlen( pcDstKeyType );

    /*** Ŀ����Կ�㷨��ʶ ***/
    *p ++ = cDstScheme;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK�¼��ܵ����� ***/
    if(pcDstKeyCipherByLmk)
    {
        strncpy(pcDstKeyCipherByLmk, p, iRspLen - 16);
    }
    p += iRspLen - 16;

    /*** ��ԿУ��ֵ ***/
    strncpy(pcDstKeyCv, p + iRspLen - 16, 16);

    return HAR_OK;
}


int HSM_RCL_SynthesisKeyByPlaintext(
    char *pcKeyType,
    char cDstScheme,
    int  iElementCount,
    char *pcElement,
    int  iKeyIdx,
    char *pcKeyLabel,
    char *pcKeyCipherByLmk/*OUT*/,
    char *pcKeyCv/*OUT*/ )
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "AM" ***/
    *p ++ = 'A';
    *p ++ = 'M';

    /*** ��Կ���� ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** ��Կ�㷨��ʶ ***/
    *p ++ = cDstScheme;

    /*** ��Կ�ϳɷ�ʽ ***/
    memcpy(p, "00", 2);
    p += 2;

    /*** ��Կ�ɷݸ��� ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iElementCount);
    p += 2;

    /*** ��Կ�ɷ� ***/
    memcpy(p, pcElement, strlen(pcElement));
    p += strlen(pcElement);

    /*** ��Կ�洢��ʶ ***/
    if(iKeyIdx)
    {
        rv = Tools_AddFieldSavedKey(iKeyIdx, pcKeyLabel, p);
        if(rv == HAR_PARAM_VALUE)
        {
            LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
            return rv;
        }
        p += rv;
    }

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK�¼��ܵ����� ***/
    strncpy( pcKeyCipherByLmk, p, iRspLen - 16 );

    /*** ��ԿУ��ֵ ***/
    strncpy( pcKeyCv, p + iRspLen - 16, 16);

    return HAR_OK;
}

int HSM_RCL_GenAndPrintKey(int iGenMode,
                char *pcKeyType,
                char cKeyScheme,
                int  iKeyComponentLen,
                int  iKeyCvAlg,
                int  iGetKeyCvType,
                char *pcPrintDomain,
                char *pcKeyCipher,
                char *pcKeyCv)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "A3" ***/
    *p ++ = 'A';
    *p ++ = '3';

    /*** ����ģʽ ***/
    *p ++ = '0' + iGenMode;

    if(iGenMode)
    {
        /*** ��Կ�������� ***/
        *p ++ = '0' + iKeyComponentLen;
    }
    else
    {
        /*** ��Կ���� ***/
        memcpy(p, pcKeyType, 3);
        p += 3;

        /*** ��Կ�㷨��ʶ ***/
        *p ++ = cKeyScheme;
    }

    /*** У��ֵ�㷨��ʶ ***/
    TASS_SPRINTF((char *)p, 3, "%02d", iKeyCvAlg);
    p += 2;

    /*** У��ֵȡֵ��ʽ ***/
    TASS_SPRINTF((char *)p, 3, "%02d", iGetKeyCvType);
    p += 2;

    /*** ��ӡ�� ***/
    memcpy(p, pcPrintDomain, (int)strlen(pcPrintDomain));
    p += strlen(pcPrintDomain);

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    if(iGenMode)
    {
        /*** ��Կ����,��������Կ������������� ***/
        len = iKeyComponentLen * 2;
    }
    else
    {
        /*** ��Կ�������ģ�LMK�� ***/
        len = Tools_GetFieldKeyLength((char*)p);

    }

    /*** ��Կ�������� ***/
    if(pcKeyCipher)
    {
        strncpy(pcKeyCipher, (char *)p, len);
    }
    p += len;

    if(pcKeyCv)
    {
        /*** ��ԿУ��ֵ ***/
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

