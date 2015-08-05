/*----------------------------------------------------------------------|
|    hsmapi_ic.h                                                        |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口金融IC卡应用主机命令函数            |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-03. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSM_API_IC_H__
#define __HSM_API_IC_H__

int HSM_IC_PutPlainKey(
        char *pcKeyType,
        char cKeyScheme,
        char *pcPlainKey,
        int  iKeyIdx,
        char *pcKeyLabel,
        char *pcKeyCipherByLmk/*out*/,
        char *pcKeyCv/*out*/ );

int HSM_IC_GetKeyInfo(
        int iKeyIdx,
        char *pcKeyType,
        char *pcKeyScheme,
        char *pcKeyCv,
        char *pcKeyLabel,
        char *pcTime);

int HSM_IC_GenerateNewKey(
        char *pcKeyType,
        char cKeyScheme,
        int  iKeyIdx,
        char *pcKeyLabel,
        char *pcKeyCipherByLmk,
        char *pcKeyCv);

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
            char *pcDstKeyCv/*out*/ );

int HSM_IC_ExportCipherKey(
    void *hSessionHandle,
    int iEncryptMode,
    char *pcSrcKeyType, int iSrcKeyIdx, char *pcSrcKeyCipherByLmk,
    int iSrcKeyDeriveNum, char *pcSrcKeyDeriveData,
    int iSrcSessionMode, char *pcSrcSessionData,
    char *pcDstKeyType, int iDstKeyIdx, char *pcDstKeyCipherByLmk,
    int iDstKeyDeriveNumber, char *pcDstKeyDeriveFactor,
    char *pcDstKeyHeader,
    char *pcCipherDstKey/*out*/, char *pcDstKeyCv/*out*/);

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
    char *pcDstKeyCipherByLmk/*out*/, char *pcDstKeyCv/*out*/ );

int HSM_IC_VerifyArqc(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcData, char *pcArqc );

int HSM_IC_GenerateArpc(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcArqc, char *pcArc, char *pcArpc/*out*/);

int HSM_IC_EncryptPbocScript(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcData, char *pcCipher);

int HSM_IC_GeneratePbocScriptMac(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcData, char *pcMac);

int HSM_IC_SymmKeyEncryptData(void *hSessionHandle,
    int iMode, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, char *pcIV,
    unsigned char *pucInputData, int iInputLength,
    unsigned char *pucOutputData/*out*/, int *piOutputLength/*out*/ );

int HSM_IC_SymmKeyDecryptData(void *hSessionHandle,
    int iMode, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, char *pcIV,
    unsigned char *pucInputData, int iInputLength,
    unsigned char *pucOutputData/*out*/, int *piOutputLength/*out*/);

int HSM_IC_SymmKeyTransferCipher(
    int iSrcEncMode, char *pcSrcKeyType, int iSrcKeyIdx, char *pcSrcKeyCipherByLmk,
    char *pcSrcDeriveData, int iSrcSessionKeyMode, char *pcSrcSessionData,
    int iSrcPadMode, char *pcSrcIv,
    int iDstEncMode, char *pcDstKeyType, int iDstKeyIdx, char *pcDstKeyCipherByLmk,
    char *pcDstDeriveData, int iDstSessionKeyMode, char *pcDstSessionData,
    int iDstPadMode, char *pcDstIv,
    unsigned char *pucInputData, int iInputLength,
    unsigned char *pucOutputData/*out*/, int *piOutputLength/*out*/ );

int HSM_IC_GeneralGenerateMac(
    int iMode, int iMacType, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, unsigned char *pcInputData, int iInputLength,
    char *pcIV, char *pcMac/*out*/, char *pcMacCiher);

int HSM_IC_GenerateMac(
    void *hSessionHandle,
    int iMode, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, unsigned char *pcInputData, int iInputLength,
    char *pcIV, char *pcMac/*out*/ );

int HSM_IC_VerifyArqc_GenARPC(
    int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcPAN, char *pcAtc,
    char *pcData, char *pcArqc , char *pcArc,
    char *pcOutput/*out*/);

int HSM_IC_GenerateMac_SM4(
    int iMode, char *pcType, int iKeyIdx, char *pcKeyCipherByLmk,
    char *pcDeriveData, int iSessionKeyMode, char *pcSessionData,
    int iPadMode, unsigned char *pcInputData, int iInputLength,
    char *pcIV, char *pcMac/*out*/ );


int HSM_GetDeviceBaseInfo(char *pcDmkCv/*OUT*/, char *pcVersion, char *pcSerial);

int HSM_CalculateHash(
    int iMode, unsigned char *pucInputData, int iInputLength,
    unsigned char *pucUserID, int iUserIDLen,
    unsigned char *pucSM2Pub, int iSM2PubLen,
    unsigned char *pucHash/*out*/, int *piHashLength/*out*/ );

int HSM_GenerateRandomData(void *hSessionHandle, int iRandomLength, unsigned char *pucRandomData/*out*/);

int HSM_IC_OfflinePin_PlaintextPin(
                int iSrcKeyIdx, char *pcSrcKeyCipherByLmk,
                char *pcPan, char *pcAtc,
                char *pcPinBlkFmt1, char *pcPlaintextPin_New,
                char *pcPlaintextPin_Old, char *pcAccountNum,
                char *pcPinCipher/*out*/);

int HSM_IC_OfflinePin_CipherPin(
                int iSrcKeyIdx, char *pcSrcKeyCipherByLmk,
                int iDstKeyIdx, char *pcDstKeyCipherByLmk,
                char *pcPan, char *pcAtc,
                char *pcPinInputMode,
                char *pcSrcPinBlkFmt, char *pcDstPinBlkFmt,
                char *pcCipherPin_New, char *pcCipherPin_Old,
                char *pcAccountNum,
                char *pcPinCipher/*out*/);

#endif /*__HSM_API_IC_H__*/

