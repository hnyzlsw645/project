/*----------------------------------------------------------------------|
|    hsmapi.c                                                           |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310��������ڽ���ͨ�ýӿ�                        |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-05. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History: TODO:��Կ���ȣ��Լ����ݳ��ȵ��жϻ����һ����顣  |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>

#include "hsmapi.h"
#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmapi_init.h"
#include "hsmapi_tcpcom.h"
#include "hsmapi_ic.h"
#include "hsmapi_racal.h"
#include "hsmapi_asym.h"

/***************************************************************************
 *   Subroutine: Tass_GenSm2Key
 *   Function:   �������RSA��Կ�ԣ���ʹ��ZMK���ܵ���
 *   Input:
 *     @hSessionHandle         �Ự���
 *     @zmkIndex               ��Կ����
 *     @zmk_Lmk                ����RSA��Կ�����ı�����Կ
 *     @zmk_disData            ZMK��ɢ������NULLʱ����ɢ
 *     @mode                   �����㷨ģʽ
 *   Output:
 *     @SM2_D_ZMK       
 *     @SM2_PUBKEY
 *     @SM2_LMK
 *   Return:            �ɹ�����0��������ʾʧ��
 *   Description:
 *   Author:       Luo Cangjian
 *   Date:         2015.06.05
 *   ModifyRecord:
 ****************************************************************************/
HSMAPI int 
Tass_GenSm2Key(
     void *hSessionHandle,
     int zmkIndex,
     char *zmk_Lmk,
     char *zmk_disData,
     int mode,
     char *SM2_D_ZMK/*out*/,
     char *SM2_PUBKEY/*out*/,
     char *SM2_LMK/*out*/)
{
     int rv = HAR_OK;
     int piDerPublicKeyLen = 0;
     int piPrivateKeyLen_Lmk = 0;
     rv = HSM_SM2_GenerateNewKeyPair(
              hSessionHandle,
              9999, "",
              SM2_PUBKEY, &piDerPublicKeyLen,
              SM2_LMK,  &piPrivateKeyLen_Lmk );
     int piPrivateKeyLen_Tk = 0;
     rv = HSM_SM2_ExportByTK(
              hSessionHandle,mode,
              "000",/**KEK**/
               0, zmk_Lmk,
               strlen(zmk_disData)/32, zmk_disData,
               0,/*Ҫ��������sm2����*/
               SM2_PUBKEY, piDerPublicKeyLen,
               SM2_LMK, piPrivateKeyLen_Lmk,
               SM2_D_ZMK, &piPrivateKeyLen_Tk/*out*/ );
   return rv;

}


/***************************************************************************
 *    Subroutine: Tass_DeriveKeyExportedByRsa
 *    Function:   ��ZMK��ɢ��������Կ��Ȼ���ñ�����Կ������Կ���ܱ�������  
 *    Input:
 *       @hSessionHandle         �Ự���
 *       @pcZmkCipher_Lmk        ����ɢ��zmk
 *       @pcPublicKey            ������Կ��Der�����RSA��Կ
 *       @pcDisData              ��ɢ����
 *    Output:
 *       @pcSubKeyCipher_TK      ����Կ����
 *       @pcSubKeyCipher_Lmk     LMK���ܵ�����Կ����
 *       @pcSubKeyCv             ����ԿУ��ֵ
 *    Return:            �ɹ�����0��������ʾʧ��
 *    Description:
 *    Author:       Luo Cangjian
 *    Date:         2015.06.05
 *    ModifyRecord:
 **************************************************************************/
HSMAPI int 
Tass_DeriveKeyExportedByRsa(
     void *hSessionHandle,
     char *pcZmkCipher_Lmk,
     char *pcPublicKey,
     char *pcDisData,
     char *pcSubKeyCipher_TK/*out*/,
     char *pcSubKeyCipher_Lmk/*out*/,
     char *pcSubKeyCv/*out*/)
{
     int rv = 0;
     //�˴�������
     rv = HSM_IC_ExportCipherKey(
                  hSessionHandle,
                  0,
                  "000",/*������Կ����*/
                  9999, pcPublicKey,
                  0, "",
                  0, "",
                  "000",
                  9999, pcZmkCipher_Lmk,
                  strlen(pcDisData), pcDisData,
                  "",
                  pcSubKeyCipher_Lmk/*out*/, pcSubKeyCv/*out*/);
    //......................
    return rv; 
}


/***************************************************************************
 * Subroutine: Tass_GenRSAKey
 * Function:   �������RSA��Կ�ԣ���ʹ��ZMK���ܵ���
 * Input:
 *   @hSessionHandle  �Ự���
 *   @RsaLen          Rsa��Կ����
 *   @zmkIndex
 *   @zmk_Lmk
 *   @zmk_disData
 *   @mode
 * Output:
 *   @Rsa_D_ZMK
 *   @Rsa_P_ZMK
 *   @Rsa_Q_ZMK
 *   @Rsa_DP_ZMK
 *   @Rsa_DQ_ZMK
 *   @Rsa_QINV_ZMK
 *   @Rsa_N
 *   @Rsa_E
 *   @Rsa_LMK*
 * Return:            �ɹ�����0��������ʾʧ��
 * Description:
 * Author:       Luo Cangjian
 * * Date:         2015.06.05
 * * ModifyRecord:
 * * *************************************************************************/
HSMAPI int 
Tass_GenRSAKey(
      void *hSessionHandle,
      int RsaLen,
      int zmkIndex,
      char *zmk_Lmk,
      char *zmk_disData,
      int mode,
      char *Rsa_D_ZMK/*out*/,
      char *Rsa_P_ZMK/*out*/,
      char *Rsa_Q_ZMK/*out*/,
      char Rsa_DP_ZMK/*out*/,
      char *Rsa_DQ_ZMK/*out*/,
      char *Rsa_QINV_ZMK/*out*/,
      char *Rsa_N/*out*/,
      char *Rsa_E/*out*/,
      char *Rsa_LMK/*out*/)
{
    int rv = HAR_OK;
    
    unsigned char pucDerPublicKey[512+32] = {0};
    int piDerPublicKeyLen = 0;
    unsigned char pucPrivateKey_Lmk[512+32] = {0};
    int piPrivateKeyLen_Lmk = 0;
   
    int iTkDeriveNumber = zmk_disData == NULL ? 0 : strlen(zmk_disData)/32;
    
    rv = HSM_RSA_GenerateNewKeyPair(
           hSessionHandle,
           0,
           NULL,
           RsaLen, 
           NULL,
           pucDerPublicKey/*out*/, 
           &piDerPublicKeyLen/*out*/,
           Rsa_LMK/*out*/, 
           &piPrivateKeyLen_Lmk/*out*/ );
   if(rv)
    {
      LOG_ERROR("%s","GenerateNewKeyPair is error");
      return rv;
    }
  //����Der����
  int Rsa_N_Len = 0;
  int Rsa_E_Len = 0;
  printf("pucDerPublicKey = %02x \n", *pucDerPublicKey); 
  Tools_PrintBuf("pucDerPublicKey",pucDerPublicKey,piDerPublicKeyLen);
  int len = Tools_ConvertByte2HexStr(pucDerPublicKey,strlen(pucDerPublicKey),pucDerPublicKey);
  printf("pucDerPublicKey = %x \n", pucDerPublicKey);
  rv =  Tools_DDer(pucDerPublicKey,Rsa_N,&Rsa_N_Len,Rsa_E,&Rsa_E_Len);
    if(rv)
     {
       LOG_ERROR("%s","pucDerPublicKey Convert is error");
       return rv;
     }
  printf("RSA_N = %s\n",Rsa_N);
  printf("RSA_E = %s\n",Rsa_E);
     unsigned char *piDerPublicKey[2048] = {0};
     int piPublicKey_mLen = 0;
     int piPublicKey_eLen = 0;
     int piPrivateKey_dLen = 0;
     int piPrivateKey_pLen = 0;
     int piPrivateKey_qLen = 0;
     int piPrivateKey_dpLen = 0;
     int piPrivateKey_dqLen = 0;
     int piPrivateKey_qInvLen = 0;
   rv = HSM_RSA_ExportRSAKey(
               hSessionHandle,
               mode,  "000",
               zmkIndex, zmk_Lmk,
               iTkDeriveNumber, zmk_disData,
               9999,
               Rsa_LMK, piPrivateKeyLen_Lmk,
               "", "",
               NULL, "",
               piDerPublicKey/*OUT*/, &piDerPublicKeyLen/*OUT*/,
               Rsa_N/*OUT*/, &piPublicKey_mLen/*OUT*/,
               Rsa_E/*OUT*/, &piPublicKey_eLen/*OUT*/,
               Rsa_DQ_ZMK/*OUT*/, &piPrivateKey_dLen/*OUT*/,
               Rsa_P_ZMK/*OUT*/, &piPrivateKey_pLen/*OUT*/,
               Rsa_Q_ZMK/*OUT*/, &piPrivateKey_qLen/*OUT*/,
               Rsa_DP_ZMK/*OUT*/, &piPrivateKey_dpLen/*OUT*/,
               Rsa_DQ_ZMK/*OUT*/, &piPrivateKey_dqLen/*OUT*/,
               Rsa_QINV_ZMK/*OUT*/, &piPrivateKey_qInvLen/*OUT*/);   

    return rv; 
}

/***************************************************************************
 * * Subroutine: Tass_PubKey_Oper
 * * Function:   RSA/SM2��Կ��������ӿ�
 * * Input:
 * *   @hSessionHandle  �Ự���
 * *   @keytype         ��Կ����
 * *   @indata          �������ݣ��빫Կ�ȳ�
 * *   @RSAPubKeyE      RSA��Կ
 * *   @RSAPubKeyN      RSA��Կ
 * *   @SM2PubKey       SM2��Կ
 * * Output:
 * *   @outdata         ���ܺ�����
 * *
 * * Return:            �ɹ�����0��������ʾʧ��
 * * Description:
 * * Author:       Luo Cangjian
 * * Date:         2015.06.05
 * * ModifyRecord:
 * * *************************************************************************/
HSMAPI int 
Tass_PubKey_Oper(
     void *hSessionHandle,
     int keytype,
     char *indata,
     char *RSAPubKeyE,
     char *RSAPubKeyN,
     char *SM2PubKey,
     char *outdata/*out*/)
{

  int rv = HAR_OK;
  char aucInData[2048*2] = {0};
  unsigned char publicDer[512+32];
  int publicDerLen = 512+32;
  unsigned char pucInput[1024*2] = {0};
  unsigned char pucOutput[1024*2] = {0};
  int piOutputLength = 0;
  rv =  Tools_ConvertHexStr2Byte(indata,strlen(indata),pucInput);
  rv =  Tools_Der(RSAPubKeyN,RSAPubKeyE,publicDer,&publicDerLen);
  Tools_PrintBuf("publicDer",publicDer,publicDerLen);
  if(keytype == 0)
   {
    rv = HSM_RSA_EncryptData( 
                hSessionHandle,0,
                0, 
                publicDer, publicDerLen,
                pucInput, strlen(pucInput),
                pucOutput/*out*/, &piOutputLength/*out*/ );

   }
  else if(keytype == 1)
   {
    rv = HSM_SM2_EncryptData(
                hSessionHandle,0,
                SM2PubKey, strlen(SM2PubKey),
                pucInput, strlen(pucInput),
                pucOutput/*out*/, &piOutputLength/*out*/ );

   }
  else
   {
    LOG_ERROR("%s", "keytype is error");
    return rv;
   }
  Tools_PrintBuf("pucOutput = ",pucOutput,strlen(outdata));
  rv = Tools_ConvertByte2HexStr(pucOutput, strlen(pucOutput), outdata);
  Tools_PrintBuf("pcout = ",outdata,strlen(outdata));
  return rv;

}

/***************************************************************************
 * * Subroutine: Tass_PRIVATE_Oper
 * * Function:   ˽Կ��������ӿڡ�
 * * Input:
 * *   @hSessionHandle  �Ự���
 * *   @keytype         ��Կ����,0Ϊrsa,1Ϊsm2
 * *   @Rsa_LMK         rsa������Կ
 * *   @SM2_LMK         sm2������Կ
 * *   @indata          �ⲿ��������
 * * Output:
 * *   @outdata         ˽Կ���ܺ�����
 * *
 * * Return:            �ɹ�����0��������ʾʧ��
 * * Description:
 * * Author:       Luo Cangjian
 * * Date:         2015.06.05
 * * ModifyRecord:
 * * *************************************************************************/
HSMAPI int 
Tass_PRIVATE_Oper(
     void *hSessionHandle,
     int keytype,
     char *Rsa_LMK,
     char *SM2_LMK,
     char *indata,
     char *outdata/*out*/)
 
{
  int rv = HAR_OK;
  int piOutputLength[8] = {0};
  unsigned char aucInData[2048*2] = {0};
  rv =  Tools_ConvertHexStr2Byte(indata,strlen(indata),aucInData);
  
  if(keytype == 0)
   {
    rv = HSM_RSA_DecryptData(hSessionHandle, 0,
    9999, Rsa_LMK, strlen(Rsa_LMK),
    aucInData, strlen(aucInData),
    outdata/*out*/, piOutputLength/*out*/ );
  
   }
  else if(keytype == 1)
   {
    rv = HSM_SM2_DecryptData(hSessionHandle,
    9999, SM2_LMK, strlen(SM2_LMK),
    aucInData, strlen(aucInData),
    outdata/*out*/, piOutputLength/*out*/ );
   
   }
  else
   {
    LOG_ERROR("%s", "keytype is error");
    return rv;
   }
  rv = Tools_ConvertByte2HexStr(outdata, strlen(outdata), outdata);
  return rv;
}

/***************************************************************************
* Subroutine: Tass_GenerateRandom
* Function:   ���������
* Input:
*   @hSessionHandle  �Ự���
*   @iRandomLen      ������ֽ���
* Output:
*   @pcRandom        ������ݣ�ʮ�����ַ�����
*
* Return:            �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenerateRandom(void *hSessionHandle, int iRandomLen, char *pcRandom/*out*/)
{
    int     rv = HAR_OK;
    int     len = 0;
    unsigned char aucRandom[2048];

    if(iRandomLen < 0 || iRandomLen > 2048)
    {
        LOG_ERROR("Parameter iRandomLen = [%d] is invalid. It must 1 -- 2048", iRandomLen);
        return HAR_PARAM_VALUE;
    }

    if(pcRandom == NULL)
    {
        LOG_ERROR("Parameter pcRandom = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_GenerateRandomData(hSessionHandle, iRandomLen, aucRandom/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    len = Tools_ConvertByte2HexStr(aucRandom, iRandomLen, pcRandom);
    if(len == -1)
    {
        LOG_ERROR("%s", "Byte data conversion to hexadecimalstring failure.");
        rv = HAR_BYTE_TO_HEX;
    }

    return rv;
}

/***************************************************************************
 * * Subroutine: Tass_DecryptTrackData
 * * Function:   ʹ��ZEK���ܴŵ����ݡ�
 * * Input:
 * *   @hSessionHandle  �Ự���
 * *   @iKeyIdx         ��Կ����
 * *   @pcKey_LMK       ��Կ����
 * *   @pcTrackText     �ŵ�����
 * *   @iTrackTextLen   �ŵ����ĳ���
 * *   @iAlgId          ����ģʽ
 * *   @pcIV            ��ʼ��IV 
 * * Output:
 * *   @pcTrackCipher   �ŵ�����
 * *
 * * Return:            �ɹ�����0��������ʾʧ��
 * * Description:
 * * Author:       Luo Cangjian
 * * Date:         2015.06.05
 * * ModifyRecord:
 * * *************************************************************************/
HSMAPI int 
Tass_DecryptTrackData(
     void *hSessionHandle,
     int iKeyIdx,
     char *pcKey_LMK,
     char *pcTrackCipher,
     int iTrackTextLen,
     int iAlgId,
     int iPadFlg,
     char *pcIV,
     char *pcTrackText/*out*/)
{
    int     rv = HAR_OK;
    int     iOutDataLen = 0;
    int     iInDataLen = 0;
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};
    int piOutputLength[]={0};
    rv =  Tools_ConvertHexStr2Byte(pcTrackCipher,strlen(pcTrackCipher),aucInData);
    rv = HSM_IC_SymmKeyDecryptData(hSessionHandle,
    	iAlgId, "000", iKeyIdx, pcKey_LMK,
    	"", 0, "",
    	iPadFlg, pcIV,
    	aucInData, strlen(aucInData),
    	pcTrackText/*out*/, piOutputLength/*out*/ );
    rv = Tools_ConvertByte2HexStr(pcTrackText, strlen(pcTrackText), pcTrackText);
    return rv;
    
}




/***************************************************************************
 * * Subroutine: Tass_EncryptTrackData
 * * Function:   ʹ��ZEK���ܴŵ����ݡ�
 * * Input:
 * *   @hSessionHandle  �Ự���
 * *   @iKeyIdx         ��Կ����
 * *   @pcKey_LMK       ��Կ����
 * *   @pcTrackText     �ŵ�����
 * *   @iTrackTextLen   �ŵ����ĳ���
 * *   @iAlgId          ����ģʽ
 * *   @pcIV            ��ʼ��IV 
 * * Output:
 * *   @pcTrackCipher   �ŵ�����
 * *
 * * Return:            �ɹ�����0��������ʾʧ��
 * * Description:
 * * Author:       Luo Cangjian
 * * Date:         2015.06.05
 * * ModifyRecord:
 * * *************************************************************************/
HSMAPI int 
Tass_EncryptTrackData(
     void *hSessionHandle,
     int iKeyIdx,
     char *pcKey_LMK,
     char *pcTrackText,
     int iTrackTextLen,
     int iAlgId,
     int iPadFlg,
     char *pcIV,
     char *pcTrackCipher/*out*/)
{
    int     rv = HAR_OK;
    int     iOutDataLen = 0;
    int     iInDataLen = 0;
    //��������תΪ������
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};
    int piOutputLength[]={0};
    rv =  Tools_ConvertHexStr2Byte(pcTrackText,strlen(pcTrackText),aucInData);
    rv = HSM_IC_SymmKeyEncryptData(hSessionHandle,
    iAlgId, "000", iKeyIdx, pcKey_LMK,
    "", 0, "",
    iPadFlg, pcIV,
    aucInData, strlen(aucInData),
    pcTrackCipher/*out*/, piOutputLength/*out*/ );
    //תΪʮ������
    rv = Tools_ConvertByte2HexStr(pcTrackCipher, strlen(pcTrackCipher), pcTrackCipher);
    return rv;
} 

/***************************************************************************
* Subroutine: Tass_Disper_Zmk
* * Function:   ��һ��ZMK��ɢ��������һ������Կ����ͨ��ZMK��Կ���ܱ�������
* * Input:
* *   @hSessionHandle  �Ự���
* *   @iKeyIdx         ��Կ����
* *   @pcKey_LMK       ��Կ����
* *   @pcDisData       ��ɢ����
* * Output:
* *   @pcZmk_LMK       ZMK����
* *   @pcZmk_ZMK       ZMK������ɢ������Կ����
* *   @pcZmkCv         ��ԿУ��ֵ
* *
* * Return:            �ɹ�����0��������ʾʧ��
* * Description:
* * Author:       Luo Cangjian
* * Date:         2015.06.05
* * ModifyRecord:
****************************************************************************/
HSMAPI int
Tass_Disper_Zmk(
    void *hSessionHandle, 
    int iKeyIdx,
    char *pcKey_LMK,
    char *pcDisData,
    int iZmkIdx,
    char *pcZmkKey_LMK,
    char *pcZmk_ZMK/*out*/,
    char *pcZmk_LMK/*out*/, 
    char *pcZmkCv/*out*/)
{
    int  rv = HAR_OK;
    int  len = 0;
    if(strlen(pcDisData)%2 != 0)
       {
         LOG_ERROR("Param pcDisData length is error",rv,rv);
         return rv;
       }   
    int iEncryptMode = 0;
    char pcSrcKeyType[4] = "000";
    int iSrcKeyDeriveNum = 0;
    int iSrcSessionMode = 0;
    char pcSrcSessionData[128] = {};
    char pcDstKeyType[3+1] = "000";
    int iDstKeyDeriveNumber = strlen(pcDisData)/32;
    char pcCipherDstKey[128] ={0};
    char pcDstKeyCv[18] ={0};
    
    rv = HSM_IC_ExportCipherKey(
    	hSessionHandle,
	iEncryptMode,
    	pcSrcKeyType,
        iKeyIdx, pcKey_LMK,
    	iSrcKeyDeriveNum, "",
    	0, "",/*�Ự��Կ*/
    	pcDstKeyType,
        0, pcZmkKey_LMK,
    	iDstKeyDeriveNumber, pcDisData,
    	"",
    	pcZmk_ZMK/*out*/, pcDstKeyCv/*out*/);
    
     if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
    unsigned char pcZmk_ZMK_1[128] = {0};
    unsigned char *p = pcZmk_ZMK_1;
    if(strlen(pcZmk_ZMK)/16 < 1)
    {
      LOG_ERROR("Tass hsm api return code = [%d],[%#010X].",rv,rv);
      return rv;
    }
    if(strlen(pcZmk_ZMK)/32 >= 1)
    {
      *p ++ = 'X';
       memcpy(p, pcZmk_ZMK,strlen(pcZmk_ZMK));
       pcZmk_ZMK = pcZmk_ZMK_1;
    }
    
	printf("zmd index = %d\n", iZmkIdx);
	printf("zmk cipher = %s\n", pcZmk_LMK);
        printf("pcZmkKey_LMK = %s\n", pcZmkKey_LMK);
        printf("pcZmk_ZMK = %s\n", pcZmk_ZMK);
    rv = HSM_RCL_ImportKey_A6(
    	hSessionHandle,
    	"000",
	 iZmkIdx,
	 pcZmkKey_LMK,
         pcZmk_ZMK,
	 strlen(pcZmk_ZMK)/16>=2 ? 'X':'Z',
	 'N',
    	  0,
	 "",
	 pcZmk_LMK,
    	pcZmkCv/*OUT*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    return rv;
}




/***************************************************************************
* Subroutine: Tass_VerifyARQC
* Function:   ��֤ARQC/TC
* Input:
*    @iKeyIdx               ��Կ����
*    @pcKeyCipherByLmk      ��Կ����
*    @pcPan                 PAN
*    @pcATC                 ATC
*    @pcTransData           ��������
*    @pcARQC                ����֤��ARQC
* Output:
*    ��
*
* Return:      �ɹ�����0��������ʾʧ��
* Description: ��ɢMDKԴ��Կ������Ƭ����ԿUDK������ATCֵ���㽻�׻Ự��ԿSDK��
*              ��佻�����ݣ�ʹ��SDK������MACֵ���������ARQC�Աȡ�
*
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_VerifyARQC(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcTransData,
        char    *pcARQC)
{
    int     rv = HAR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcTransData == NULL)
    {
        LOG_ERROR( "Parameter pcTransData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcTransData) % 2 != 0)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d], Its length is a multiple of 2.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcTransData) < 2 || strlen(pcTransData) > 255 * 2)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d] is ivnalid. Its length must be 2 -- 510 characters.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(pcARQC == NULL)
    {
        LOG_ERROR("Parameter pcARQC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARQC) != 16)
    {
        LOG_ERROR("Parameter pcARQC'length = [%d] is invalid. It must be 16 characters.", strlen(pcARQC));
        return HAR_PARAM_LEN;
    }

    rv = HSM_IC_VerifyArqc(iKeyIdx,
                    szKeyCipher,
                    pcPan,
                    pcATC,
                    pcTransData,
                    pcARQC);
    if(rv)
    {
         LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenARPC
* Function:   ����ARPC
* Input:
*    @iKeyIdx               ��Կ����
*    @pcKeyCipherByLmk      ��Կ���ģ�����������Ϊ0ʱ��Ч
*    @pcPan                 ���źͿ����к�
*    @pcATC                 Ӧ�ý��׼����������ڼ��㽻�׻Ự��Կ
*    @pcARQC                ARQC
*    @pcARC                 ARC
* Output:
*    @pcARPC                �����ARPC
*
* Return:       �ɹ�����0��������ʾʧ��
* Description: ��ɢMDKԴ��Կ������Ƭ����ԿUDK������ATCֵ���㽻�׻Ự��ԿSDK��
*              ��֯ARPC���ݣ���SDK�������ݣ�����ARPC��
*
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenARPC(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcARQC,
        char    *pcARC,
        char    *pcARPC)
{
    int     rv = HAR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcARQC == NULL)
    {
        LOG_ERROR("Parameter pcARQC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARQC) != 16)
    {
        LOG_ERROR("Parameter pcARQC'length = [%d] is invalid. It must be 16 characters.", strlen(pcARQC));
        return HAR_PARAM_LEN;
    }

    if(pcARC == NULL)
    {
        LOG_ERROR("Parameter pcARC = [%d] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARC) != 4)
    {
        LOG_ERROR("Parameter pcARC'length = [%d] is invalid. It must be 4 characters.", strlen(pcARC));
        return HAR_PARAM_LEN;
    }

    if(pcARPC == NULL)
    {
        LOG_ERROR("Parameter pcARPC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** �ú���ģʽ��־Ӧ��Ϊ2 ***/
    rv = HSM_IC_GenerateArpc(
            iKeyIdx,
            szKeyCipher,
            pcPan,
            pcATC,
            pcARQC,
            pcARC,
            pcARPC/*out*/);
    if(rv)
    {
         LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_VerifyARQC_GenARPC
* Function:   ��֤ARQC/TC������ARPC
* Input:
*    @iKeyIdx               ��Կ����
*    @pcKeyCipherByLmk      ��Կ���ģ�����������Ϊ0ʱ��Ч
*    @pcPan                 ���źͿ����к�
*    @pcATC                 Ӧ�ý��׼����������ڼ��㽻�׻Ự��Կ
*    @pcTransData           ARQC����
*    @pcARQC                ARQC
*    @pcARC                 ARC
* Output:
*    @pcARPC                �����ARPC
*
* Return:       �ɹ�����0��������ʾʧ��
* Description: ��ɢMDKԴ��Կ������Ƭ����ԿUDK������ATCֵ���㽻�׻Ự��ԿSDK��
*              ��佻�����ݣ�ʹ��SDK������MACֵ���������ARQC�ԱȲ�����ARPC��
*
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_VerifyARQC_GenARPC(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcTransData,
        char    *pcARQC,
        char    *pcARC,
        char    *pcARPC/*out*/)
{
    int     rv = HAR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcTransData == NULL)
    {
        LOG_ERROR("Parameter pcTransData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcTransData) % 2 != 0)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d], Its length is a multiple of 2.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcTransData) < 2 || strlen(pcTransData) > 255 * 2)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d] is ivnalid. Its length must be 2 -- 510 characters.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(pcARQC == NULL)
    {
        LOG_ERROR("Parameter pcARQC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARQC) != 16)
    {
        LOG_ERROR("Parameter pcARQC'length = [%d] is invalid. It must be 16 characters.", strlen(pcARQC));
        return HAR_PARAM_LEN;
    }

    if(pcARC == NULL)
    {
        LOG_ERROR("Parameter pcARC = [%d] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARC) != 4)
    {
        LOG_ERROR("Parameter pcARC'length = [%d] is invalid. It must be 4 characters.", strlen(pcARC));
        return HAR_PARAM_LEN;
    }

    if(pcARPC == NULL)
    {
        LOG_ERROR( "Parameter pcARPC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** �ú���ģʽ��־Ӧ��Ϊ1 ***/
    rv = HSM_IC_VerifyArqc_GenARPC(
            iKeyIdx,
            szKeyCipher,
            pcPan,
            pcATC,
            pcTransData,
            pcARQC,
            pcARC,
            pcARPC);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);

        if(rv == 1)
        {
            LOG_ERROR("authentication failed, ARQC = [%s].", pcARPC);
        }
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_ScriptEncrypt
* Function:   �ű�����
* Input:
*    @iKeyIdx               ��Կ����
*    @pcKeyCipherByLmk      ��Կ���ģ�����������Ϊ0ʱ��Ч
*    @pcPan                 ���źͿ����к�
*    @pcATC                 Ӧ�ý��׼����������ڼ��㽻�׻Ự��Կ
*    @pcTransData           �ű�����
* Output:
*    @pcDataCipher          �ű���������
*
* Return:       �ɹ�����0��������ʾʧ��
* Description: ��ɢMDKԴ��Կ������Ƭ����ԿUDK������ATCֵ���㽻�׻Ự��ԿSDK��
*              ���������ݽ�����䣬ʹ��SDK���м�������,����������ݡ�
*
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_ScriptEncrypt(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcTransData,
        char    *pcDataCipher/*out*/)
{
    int     rv = HAR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcTransData == NULL)
    {
        LOG_ERROR( "Parameter pcTransData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcTransData) % 2 != 0)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d], Its length is a multiple of 2.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcTransData) < 2 || strlen(pcTransData) > 984 * 2)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d] is ivnalid. Its length must be 2 -- %d characters.",
                strlen(pcTransData), 984 * 2);
        return HAR_PARAM_LEN;
    }

    if(pcDataCipher == NULL)
    {
        LOG_ERROR("Parameter pcDataCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** �ű����� ***/
    rv = HSM_IC_EncryptPbocScript(
            iKeyIdx,
            szKeyCipher,
            pcPan,
            pcATC,
            pcTransData,
            pcDataCipher);
    if(rv)
    {
         LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_ScriptMAC
* Function:   �ű�MAC
* Input:
*    @iKeyIdx               ��Կ����
*    @pcKeyCipherByLmk      ��Կ���ģ�����������Ϊ0ʱ��Ч
*    @pcPan                 ���źͿ����к�
*    @pcATC                 Ӧ�ý��׼����������ڼ��㽻�׻Ự��Կ
*    @pcTransData           �ű�����
* Output:
*    @pcMAC                 �ű�����MAC
*
* Return:       �ɹ�����0��������ʾʧ��
* Description: ��ɢMDKԴ��Կ������Ƭ����ԿUDK������ATCֵ���㽻�׻Ự��ԿSDK��
*              ���������ݽ�����䣬ʹ��SDK����MAC���㣬���.
*
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_ScriptMAC(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcTransData,
        char    *pcMAC)
{
    int     rv = HAR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcTransData == NULL)
    {
        LOG_ERROR("Parameter pcTransData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcTransData) % 2 != 0)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d], Its length is a multiple of 2.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcTransData) < 2 || strlen(pcTransData) > 984 * 2)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d] is ivnalid. Its length must be 2 -- %d characters.",
                strlen(pcTransData), 984 * 2);
        return HAR_PARAM_LEN;
    }

    if(pcMAC == NULL)
    {
        LOG_ERROR("Parameter pcMAC = [%s] is invalid..", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** ����ű�MAC ***/
    rv = HSM_IC_GeneratePbocScriptMac(
            iKeyIdx,
            szKeyCipher,
            pcPan,
            pcATC,
            pcTransData,
            pcMAC);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_EncryptICData
* Function:   IC���ݼ���
* Input:
*   @iKeyIdx                 ��Կ����
*   @pcKeyCipherByLmk        ��Կ���ģ�����������Ϊ0ʱ�ò�����Ч
*   @iEncMode                �����㷨ģʽ
*   @iDeriveNum              ��Կ��ɢ����
*   @pcDeriveData            ��Կ��ɢ����
*   @iSessionKeyMode         �Ự��Կģʽ
*   @pcSessionKeyData        �Ự��Կ����
*   @iPaddingMode            �������ģʽ
*   @pcInData                ��������
*   @pcIv                    IV����
* Output:
*   @pcOutData               ��������
*
* Return:       �ɹ�����0��������ʾʧ��
* Description: ��Ӧ��ϵͳȷ����Կ��ɢ��ģʽ������������Կ����ָ�������ݽ��м���
*
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_EncryptICData(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iEncMode,
        int     iDeriveNum,
        char    *pcDeriveData,
        int     iSessionKeyMode,
        char    *pcSessionKeyData,
        int     iPaddingMode,
        char    *pcInData,
        char    *pcIv,
        char    *pcOutData)
{
    int     rv = HAR_OK;
    int     iOutDataLen = 0;
    int     iInDataLen = 0;
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(iEncMode != 0 && iEncMode != 1)
    {
        LOG_ERROR("Parameter iEncMode = [%d] is invalid. It must be 0 or 1.", iEncMode);
        return HAR_PARAM_ENC_MODE;
    }

    if(iDeriveNum < 0 || iDeriveNum > 3)
    {
        LOG_ERROR("Parameter iDeriveNum = [%d] is invalid. It must be 0-3.", iDeriveNum);
        return HAR_PARAM_DERIVE_NUM;
    }

    if(iDeriveNum != 0)
    {
        if(pcDeriveData == NULL)
        {
            LOG_ERROR("Parameter pcDeriveData = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if((int)strlen(pcDeriveData) != 32 * iDeriveNum)
        {
            LOG_ERROR("Parameter pcDeriveData'length = [%d] is invalid. It must be %d characters.",
                    strlen(pcDeriveData),  32 * iDeriveNum);
            return HAR_PARAM_LEN;
        }
    }

    rv = Tools_CheckSessionKeyDataValidity(iSessionKeyMode, pcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSessionKeyMode or pcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iPaddingMode = [%d] is invalid.", iPaddingMode);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if((int)strlen(pcInData) > 2048)
    {
        LOG_ERROR("Parameter pcInData'length = [%d] is invalid. It must be less than 2048 characters.", strlen(pcInData));
        return HAR_PARAM_LEN;
    }

    if(iEncMode == 1)
    {
        if(pcIv == NULL)
        {
            LOG_ERROR("Parameter pcIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcIv) != 16 && strlen(pcIv) != 32)
        {
            LOG_ERROR("Parameter pcIv'length = [%d] is invalid. It must be 16 or 32 characters.", strlen(pcIv));
            return HAR_PARAM_LEN;
        }
    }

    if(pcOutData == NULL)
    {
        LOG_ERROR("Parameter pcOutData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iInDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    rv = HSM_IC_SymmKeyEncryptData(
            hSessionHandle, 
            iEncMode,               /*** �����㷨ģʽ ***/
            "109",                  /*** ��Կ���� ***/
            iKeyIdx,                /*** ��Կ���� ***/
            szKeyCipher,            /*** ��Կ���� ***/
            pcDeriveData,           /*** ��Կ��ɢ���� ***/
            iSessionKeyMode,        /*** �Ự��Կ����ģʽ ***/
            pcSessionKeyData,       /*** �Ự��Կ���� ***/
            iPaddingMode,           /*** �������ģʽ ***/
            pcIv,                   /*** ��ʼ������ ***/
            aucInData,              /*** �����ܵ����� ***/
            iInDataLen,             /*** �����ܵ����ݳ��� ***/
            aucOutData,             /*** �������Կ���� ***/
            &iOutDataLen);          /*** �������Կ�����ֽ��� ***/
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    rv = Tools_ConvertByte2HexStr(aucOutData, iOutDataLen, pcOutData);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Byte data conversion to hexadecimalstring failure.");
        rv = HAR_BYTE_TO_HEX;
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenerateICMac
* Function:   ͨ��MAC/TAC����
* Input:
*   @iKeyIdx                ��Կ����
*   @pcKeyCipherByLmk       ��Կ���ģ���������ֵΪ0ʱ�ò�����Ч
*   @iMode                  �㷨��ʶ
*   @iMacType               MACȡֵ��ʽ
*   @iDeriveNum             ��Կ��ɢ����
*   @pcDeriveData           ��Կ��ɢ����
*   @iSessionKeyMode        �Ự��Կģʽ
*   @pcSessionKeyData       �Ự��Կ����
*   @iPaddingMode           �������ģʽ
*   @pcInData               ��������
*   @iInDataLen             �������ݳ���
*   @pcIv                   IV����
* Output:
*   @pcMac                  ����MAC
*
* Return:      �ɹ�����0��������ʾʧ��
* Description: ʹ��IC��������Կ��ɢ�����֤IC�����Ĺ�����Կ�����㽻�����ݵ�MAC��TAC�����ڽ���ϵͳ�ͷ������̡�
*              ���Զ���MAC�㷨ģʽ��ȡֵģʽ��֧�ֶ�����Կ���ͣ��Զ�������PADDING���򡢼���MAC��IV���ݵȡ�
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenerateICMac(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iMode,
        int     iMacType,
        int     iDeriveNum,
        char    *pcDeriveData,
        int     iSessionKeyMode,
        char    *pcSessionKeyData,
        int     iPaddingMode,
        char    *pcInData,
        int     iInDataLen,
        char    *pcIv,
        char    *pcMac/*out*/)
{
    int     rv = HAR_OK;
    char    szKeyCipher[49 + 1] = {0};
    char    szMacCiher[16 + 1] = {0};
    unsigned char aucInData[1968] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(iMode != 1 && iMode != 3)
    {
        LOG_ERROR("Parameter iMode = [%d] is invalid. It must be 1 or 3.", iMode);
        return HAR_PARAM_MAC_MODE;
    }

    if(iDeriveNum < 0 || iDeriveNum > 3)
    {
        LOG_ERROR("Parameter iDeriveNum = [%d] is invalid. It must be 0 - 3.", iDeriveNum);
        return HAR_PARAM_DERIVE_NUM;
    }

    if(pcDeriveData == NULL)
    {
        LOG_ERROR("Parameter pcDeriveData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if((int)strlen(pcDeriveData) != 32 * iDeriveNum)
    {
        LOG_ERROR("Parameter pcDeriveData'length = [%d] is invalid.", strlen(pcDeriveData));
        return HAR_PARAM_DERIVE_NUM;
    }

    rv = Tools_CheckSessionKeyDataValidity(iSessionKeyMode, pcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSessionKeyMode or pcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iPaddingMode = [%d] is invalid.", iPaddingMode);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(iInDataLen > 1968 * 2)
    {
        LOG_ERROR("Parameter pucInData'length = [%d] is invalid. It must be less than %d.", iInDataLen, 1968 * 2);
        return HAR_PARAM_LEN;
    }

    if(pcIv == NULL)
    {
        LOG_ERROR("Parameter pcIv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcIv) != 16 && strlen(pcIv) != 32)
    {
        LOG_ERROR("Parameter pcIv'length = [%d] is invalid. It must be 16 or 32 characters.", strlen(pcIv));
        return HAR_PARAM_LEN;
    }

    if(pcMac == NULL)
    {
        LOG_ERROR("Parameter pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iInDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    /*** �ú�����MACȡֵ��ʽ�̶�Ϊ8��***/
    rv = HSM_IC_GeneralGenerateMac(
            iMode,                          /*** MAC�㷨ģʽ ***/
            iMacType,                       /*** MACȡֵ��ʽ ***/
            "008",                          /*** ��Կ���� ***/
            iKeyIdx,                        /*** ��Կ���� ***/
            szKeyCipher,                    /*** ��Կ���� ***/
            pcDeriveData,                   /*** ��ɢ���� ***/
            iSessionKeyMode,                /*** �Ự��Կ����ģʽ ***/
            pcSessionKeyData,               /*** �Ự��Կ���� ***/
            iPaddingMode,                   /*** �������ģʽ ***/
            aucInData,                      /*** ������MAC������ ***/
            iInDataLen,                     /*** ������MAC�����ݳ��� ***/
            pcIv,                           /*** ��ʼ������ ***/
            pcMac,                          /*** �����MAC ***/
            szMacCiher);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenVerifyCvn
* Function:   ������У��CVN
* Input:
*   @iKeyIdx            ��Կ����������Կ����Ϊ0,ʱ���������ķ�ʽ
*   @pcKeyCipherByLmk   LMK�»��ܵ���Կ����
*   @iMode              ����У���ʶ: 0-����, 1-У��
*   @pcPan              �ʺ�
*   @pcValidity         ��Ч��
*   @pcServiceCode      �������
*   @pcCvn              CVN������iMode = 1ʱ�ò�����Ч
* Output:
*   @pcCvn              CVN������iMode = 0ʱ�ò�����Ч
*
* Return:       �ɹ�����0��������ʾʧ��
* Description: ��������CVN���ݺ�CVK����CVN��У��CVN
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenVerifyCvn(
        int  iKeyIdx,
        char *pcKeyCipherByLmk,
        int  iMode,
        char *pcPan,
        char *pcValidity,
        char *pcServiceCode,
        char *pcCvn/*in&out*/)
{
    int rv = HAR_OK;

    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invalid. It must be 0-2048.", iKeyIdx);
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcKeyCipherByLmk) != 33)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk'length = [%d] is invalid. It must be 33 characters.", strlen(pcKeyCipherByLmk));
            return HAR_PARAM_LEN;
        }
    }

    if(iMode != 0 && iMode != 1)
    {
        LOG_ERROR("Parameter iMode = [%d] is invalid. It must be 0 or 1.", iMode);
        return HAR_PARAM_VALUE;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcValidity == NULL)
    {
        LOG_ERROR("Parameter pcValidity = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcValidity) != 4)
    {
        LOG_ERROR("Parameter pcValidity'length = [%d] is invalid. It must be 4 characters.", pcValidity);
        return HAR_PARAM_LEN;
    }

    if(pcServiceCode == NULL)
    {
        LOG_ERROR("Parameter pcServiceCode = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcServiceCode) != 3)
    {
        LOG_ERROR("Parameter pcServiceCode'length = [%d] is invalid. It must be 3 characters.", strlen(pcServiceCode));
        return HAR_PARAM_LEN;
    }

    if(pcCvn == NULL)
    {
        LOG_ERROR("Parameter pcCvn = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** ����CVV,call CW  ***/
    if(iMode == 0)
    {
        rv = HSM_RCL_GenerateCVV(iKeyIdx, pcKeyCipherByLmk, pcPan, pcValidity, pcServiceCode, pcCvn);
        if(rv)
        {
            LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        }

    }/*** У��ʱ��Ϊ�������,У��CVV,call CY ***/
    else
    {
        if(strlen(pcCvn) != 3)
        {
            LOG_ERROR("Parameter pcCvn'length = [%d] is invalid. It must be 3 characters.", pcCvn);
            return HAR_PARAM_LEN;
        }

        rv = HSM_RCL_VerifyCVV(iKeyIdx, pcKeyCipherByLmk, pcPan, pcValidity, pcServiceCode, pcCvn);
        if(rv)
        {
            LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        }
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_Gen_ANSI_Mac
* Function:   ����ANSIX9.19MAC
* Input:
*   @hSessionHandle     �Ự���
*   @iKeyIdx            ��Կ����
*   pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ�ò�����Ч
*   iInDataLen          ����MACֵ�����ݳ���
*   pcInData            ����MACֵ������
* Output:
*   @pcMac              MACֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description: ���������MAC���ݲ��ñ�׼��ANSIX9.19�㷨����MAC
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_Gen_ANSI_Mac(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iInDataLen,
        char    *pcInData,
        char    *pcMac/*out*/)
{
    int     rv = HAR_OK;
    unsigned char aucData[1024 * 2] = {0};
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if((int)strlen(pcInData) != iInDataLen)
    {
        LOG_ERROR("Parameter iInDataLen = [%d] is invalid.", iInDataLen);
        return HAR_PARAM_LEN;
    }

    if(iInDataLen % 2 != 0)
    {
        LOG_ERROR("Parameter iInDataLen = [%d] is invalid.", iInDataLen);
        return HAR_PARAM_LEN;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucData);
    if(iInDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    if(pcMac == NULL)
    {
        LOG_ERROR("Parameter pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_IC_GenerateMac(
            hSessionHandle,
            3,
            "008",
            iKeyIdx,
            szKeyCipher,
            "",
            0,                          /*** �Ựģʽ ***/
            "",                         /*** �Ự���� ***/
            2,
            aucData,                    /*** ��������� ***/
            iInDataLen,                 /*** ��������ݳ��� ***/
            "0000000000000000",
            pcMac);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenUnionMac
* Function:   ��������MAC�����߷ַ�ZAK/TAKʱ��֤��Կ����Ч�ԣ�
* Input:
*   @iKeyIdx            ��Կ����
*   @pcKeyCipherByLmk   ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @iInDataLen         ������MAC�����ݳ���
*   @pcInData           ������MAC������
* Output:
*   @pcMac              MACֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:  ���������MAC���ݺ�MAK���������㷨����MAC
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenUnionMac(
        void *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iInDataLen,
        char    *pcInData,
        char    *pcMac)
{
    int     rv = HAR_OK;
    int     iDataLen = 0;
    unsigned char aucInData[1024 * 2] = {0};
    char    szKeyCipher[50] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if((int)strlen(pcInData) != iInDataLen)
    {
        LOG_ERROR("Parameter iInDataLen = [%d] is invalid.", iInDataLen);
        return HAR_PARAM_LEN;
    }

    iDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    //Tools_PrintBuf("InData", aucInData, iDataLen);
    if(pcMac == NULL)
    {
        LOG_ERROR("Parameter pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** �ú�����MACȡֵ��ʽ�̶�Ϊ8 ***/
    rv =  HSM_IC_GenerateMac(
                hSessionHandle,
                1,
                "008",
                iKeyIdx,
                szKeyCipher,
                "",
                0,                       /*** �Ựģʽ ***/
                "",                      /*** �Ự���� ***/
                2,
                aucInData,               /*** ��������� ***/
                iDataLen,                /*** ��������ݳ��� ***/
                "0000000000000000",
                pcMac);

    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenZPKMac
* Function:   ��������ZPK-MAC�����߷ַ�ZPKʱ��֤��Կ����Ч�ԣ�
* Input:
*   @iKeyIdx            ��Կ����
*   @pcKeyCipherByLmk   ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @iInDataLen         ������MAC�����ݳ���
*   @pcInData           ������MAC������
* Output:
*   @pcMac              MACֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:  ���������MAC���ݲ�������pos-mac�㷨����MAC
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenZPKMac(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iInDataLen,
        char    *pcInData,
        char    *pcMac/*out*/)
{
    int     rv = 0;
    unsigned char aucInData[1024 * 2] = {0};

    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invalid, it must be 0-2048.", iKeyIdx);
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcKeyCipherByLmk) != 16 && strlen(pcKeyCipherByLmk) != 33)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk'length = [%d] is invalid. It must be 16 or 33 characters.",
                    strlen(pcKeyCipherByLmk));
            return HAR_PARAM_LEN;
        }
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iInDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    if(pcMac == NULL)
    {
        LOG_ERROR("Parameter ERROR, pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** �ú�����MACȡֵ��ʽ�̶�Ϊ8 ***/
    rv = HSM_RCL_ZpkGenCbcMac(
                0,
                iKeyIdx,
                pcKeyCipherByLmk,
                (unsigned char*)"0000000000000000",
                16,
                aucInData,
                iInDataLen,
                8,
                pcMac);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_TranslatePin
* Function:   PIN����ת����
* Input:
*   @iSrcKeyIdx         Դ��Կ����
*   pcSrcpcKeyCipherByLmk        Դ��Կ���ģ�����Դ��Կ����ֵΪ0ʱ���ò�����Ч
*   iDstKeyIdx          Ŀ����Կ����
*   pcDstpcKeyCipherByLmk        Ŀ����Կ���ģ�����Ŀ����Կ����ֵΪ0ʱ���ò�����Ч
*   pcSrcPan            Դ�˺�
*   pcDstPan            Ŀ���˺�
*   iSrcPinBlkFmt       ԴPINBLOCK��ʽ
*   iDstPinBlkFmt       Ŀ��PINBLOCK��ʽ
*   pcSrcPinBlkCipher   ԴPINBLOCK����
* Output:
*   @pcDstPinBlkCipher   Ŀ��PINBLOCK����
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:  ����������˺š�PIK��Ҫ�أ���PIN��ָ��һ��������PIK����ת��Ϊ����һ��������PIK���ܡ�
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_TranslatePin(
        int     iSrcKeyIdx,
        char    *pcSrcpcKeyCipherByLmk,
        int     iDstKeyIdx,
        char    *pcDstpcKeyCipherByLmk,
        char    *pcSrcPan,
        char    *pcDstPan,
        int     iSrcPinBlkFmt,
        int     iDstPinBlkFmt,
        char    *pcSrcPinBlkCipher,
        char    *pcDstPinBlkCipher/*out*/)
{
    int rv = HAR_OK;

    rv = Tools_CheckKeyValidity_1(iSrcKeyIdx, pcSrcpcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcKeyIdx = [%d] or pcSrcpcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iSrcKeyIdx, pcSrcpcKeyCipherByLmk, rv);
        return rv;
    }

    rv = Tools_CheckKeyValidity_1(iDstKeyIdx, pcDstpcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iDstKeyIdx = [%d] or pcDstpcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iDstKeyIdx, pcDstpcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcSrcPan == NULL)
    {
        LOG_ERROR("Parameter pcSrcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcSrcPan) != 12 && strlen(pcSrcPan) != 18)
    {
        LOG_ERROR("Parameter pcSrcPan'length = [%d] is invalid. It must be 12 or 18 characters.", strlen(pcSrcPan));
        return HAR_PARAM_LEN;
    }

    if(pcDstPan == NULL)
    {
        LOG_ERROR("Parameter pcDstPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcDstPan) != 12 && strlen(pcDstPan) != 18)
    {
        LOG_ERROR("Parameter pcDstPan'length = [%d] is invalid. It must be 12 or 18 characters.", strlen(pcDstPan));
        return HAR_PARAM_LEN;
    }

    if(pcSrcPinBlkCipher == NULL)
    {
        LOG_ERROR("Parameter pcSrcPinBlkCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcSrcPinBlkCipher) != 16 && strlen(pcSrcPinBlkCipher) != 32)
    {
        LOG_ERROR("Parameter pcSrcPinBlkCipher'length = [%d] is invalid. It must be 16 or 32 characters.",
                strlen(pcSrcPinBlkCipher));
        return HAR_PARAM_LEN;
    }

    if(pcDstPinBlkCipher == NULL)
    {
        LOG_ERROR("Parameter pcDstPinBlkCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** ����ת����ָ��� ***/
    rv = HSM_RCL_TransferCipherPin_Zpk2Zpk(
            iSrcKeyIdx,                 /*** Դ��Կ���� ***/
            pcSrcpcKeyCipherByLmk,      /*** Դ��Կ���� ***/
            iDstKeyIdx,                 /*** Ŀ����Կ���� ***/
            pcDstpcKeyCipherByLmk,      /*** Ŀ����Կ���� ***/
            iSrcPinBlkFmt,              /*** ԴPINBLOCK��ʽ ***/
            iDstPinBlkFmt,              /*** Ŀ��PINBLOCK��ʽ ***/
            pcSrcPan,                   /*** Դ�˺� ***/
            pcDstPan,                   /*** Ŀ���˺� ***/
            pcSrcPinBlkCipher,          /*** ԴPINBLOCK���� ***/
            pcDstPinBlkCipher);         /*** Ŀ��PINBLOCK���� ***/
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_EncryptPIN
* Function:   ����PIN����
* Input:
*   @iKeyIdx             ��Կ����
*   @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @pcPinText           PIN
*   @iPinBlkFmt          PIN���ʽ
*   @pcPan               �˺�
* Output:
*   @pcPinBlkCipher   PIN������
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:  �Ѱ�ANSIX9.8��ʽ��֯��PIN��������ָ����PIK���м���
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_EncryptPIN(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPinText,
        int     iPinBlkFmt,
        char    *pcPan,
        char    *pcPinBlkCipher/*out*/)
{
    int     rv = HAR_OK;
    char    szLmkPin[129] = {0};
    char    szPinText[16] = {0};

    rv = Tools_CheckKeyValidity_1(iKeyIdx, pcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPinText == NULL)
    {
        LOG_ERROR("Parameter pcPinText = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPinText) != 6)
    {
        LOG_ERROR("Parameter pcPinText length = [%d] is invalid. It must be 6 characters.", strlen(pcPinText));
        return HAR_PARAM_LEN;
    }
    memcpy(szPinText, pcPinText, 6);

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 12 && strlen(pcPan) != 18 && strlen(pcPan) != 0)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid, Its length must be 0 or 12 or 18.", pcPan);
        return HAR_PARAM_LEN;
    }

    if(pcPinBlkCipher == NULL)
    {
        LOG_ERROR("Parameter pcPinBlkCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** call BA LMK����һ������PIN�� ***/
    rv = HSM_RCL_EncryptPin_LMK(szPinText, pcPan, szLmkPin);
    if(rv)
    {
        LOG_ERROR("HSM_RCL_EncryptPin_LMK failed, return code = [%d].", rv);
        return rv;
    }

    /*** call JG ��PIN��LMK����ת��ΪZPK���� ***/
    rv = HSM_RCL_TransferCipherPin_Lmk2Zpk(hSessionHandle, iKeyIdx, pcKeyCipherByLmk, iPinBlkFmt, pcPan, szLmkPin, pcPinBlkCipher);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_Generate_Zmk
* Function:   �������ZMK
* Input:
*   @hSessionHandle      �Ự���
*   @iKeyIdx             ��Կ����
*   @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @cZmkScheme          ZMK�㷨��ʶ
* Output:
*   @pcZmkCipherByZmk    ZMK���ܵ�ZMK��Կ����
*   @pcZmkCipherByLmk    LMK���ܵ�ZMK��Կ����
*   @pcZmkCv             ZMKУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:  �Ѱ�ANSIX9.8��ʽ��֯��PIN��������ָ����PIK���м���
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_Generate_Zmk(
        void *hSessionHandle,
        int iKeyIdx,
        char *pcKeyCipherByLmk,
        char cZmkScheme,
        char *pcZmkCipherByZmk,
        char *pcZmkCipherByLmk,
        char *pcZmkCv)
{
    int     rv = HAR_OK;
    char    szKeyCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cZmkScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cZmkScheme = [%c] is invalid.", cZmkScheme);
        return rv;
    }

    if(pcZmkCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcZmkCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcZmkCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcZmkCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcZmkCv == NULL)
    {
        LOG_ERROR("Parameter pcZmkCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
            hSessionHandle,
            1,
            "000",
            cZmkScheme,
            iKeyIdx,
            szKeyCipher,
            cZmkScheme,
            '0',
            0,
            NULL,
            pcZmkCipherByLmk,
            pcZmkCipherByZmk,
            pcZmkCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_Generate_Pik
* Function:   �������PIK
* Input:
*   @hSessionHandle      �Ự���
*   @iKeyIdx             ��Կ����
*   @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @cPikScheme          PIK�㷨��ʶ
* Output:
*   @pcPikCipherByZmk    ZMK���ܵ�PIK��Կ����
*   @pcPikCipherByLmk    LMK���ܵ�PIK��Կ����
*   @pcPikCv             PIKУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_Generate_Pik(
        void *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cPikScheme,
        char    *pcPikCipherByZmk/*OUT*/,
        char    *pcPikCipherByLmk/*OUT*/,
        char    *pcPikCv/*OUT*/ )
{

    int     rv = HAR_OK;
    char    szKeyCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cPikScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cPikScheme = [%c] is invalid.", cPikScheme);
        return rv;
    }

    if(pcPikCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcPikCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcPikCv == NULL)
    {
        LOG_ERROR("Parameter pcPikCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
            hSessionHandle,
            1,
            "001",
            cPikScheme,
            iKeyIdx,
            szKeyCipher,
            cPikScheme,
            '0',
            0,
            NULL,
            pcPikCipherByLmk,
            pcPikCipherByZmk,
            pcPikCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenerateMak
* Function:   �������MAK
* Input:
*   @hSessionHandle      �Ự���
*   @iKeyIdx             ��Կ����
*   @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @cMakScheme          MAK�㷨��ʶ
* Output:
*   @pcMakCipherByZmk    ZMK���ܵ�MAK��Կ����
*   @pcMakCipherByLmk    LMK���ܵ�MAK��Կ����
*   @pcMakCv             MAKУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenerateMak(
        void *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cMakScheme,
        char    *pcMakCipherByZmk/*out*/,
        char    *pcMakCipherByLmk/*out*/,
        char    *pcMakCv/*out*/)
{
    int     rv = HAR_OK;
    char    szKeyCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cMakScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cMakScheme = [%c] is invalid.", cMakScheme);
        return rv;
    }

    if(pcMakCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcMakCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcMakCv == NULL)
    {
        LOG_ERROR("Parameter pcMakCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
            hSessionHandle,
            1,
            "008",
            cMakScheme,
            iKeyIdx,
            szKeyCipher,
            cMakScheme,
            '0',
            0,
            NULL,
            pcMakCipherByLmk,
            pcMakCipherByZmk,
            pcMakCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_Generate_Zek
* Function:   �������ZEK
* Input:
*   @iKeyIdx             ��Կ����
*   @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @cZekScheme          ZEK�㷨��ʶ
* Output:
*   @pcZekCipherByZmk    ZMK���ܵ�ZEK��Կ����
*   @pcZekCipherByLmk    LMK���ܵ�ZEK��Կ����
*   @pcZekCv             ZEKУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_Generate_Zek(
        void *hSessionHandle,
        int  iKeyIdx,
        char *pcKeyCipherByLmk,
        char cZekScheme,
        char *pcZekCipherByZmk/*out*/,
        char *pcZekCipherByLmk/*out*/,
        char *pcZekCv/*out*/)
{
    int     rv = HAR_OK;
    char    szKeyCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cZekScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cZekScheme = [%c] is invalid.", cZekScheme);
        return rv;
    }

    if(pcZekCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcZekCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcZekCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcZekCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcZekCv == NULL)
    {
        LOG_ERROR("Parameter pcZekCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
            hSessionHandle,
            1,
            "00A",
            cZekScheme,
            iKeyIdx,
            szKeyCipher,
            cZekScheme,
            '0',
            0,
            NULL,
            pcZekCipherByLmk,
            pcZekCipherByZmk,
            pcZekCv);

    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_ImportPik
* Function:   ����PIK
* Input:
*   @iKeyIdx             ��Կ����
*   @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @cPikScheme          PIK�㷨��ʶ
*   @pcPikCipherByZmk    ZMK���ܵ�PIK��Կ����
* Output:
*   @pcPikCipherByLmk    LMK���ܵ�PIK��Կ����
*   @pcPikCv             PIKУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_ImportPik(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cPikScheme,
        char    *pcPikCipherByZmk,
        char    *pcPikCipherByLmk/*OUT*/,
        char    *pcPikCv/*OUT*/ )
{
    int     rv = HAR_OK;
    char    szKeyCipher[33 + 1] = {0};
    char    szPikCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cPikScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cPikScheme = [%c] is invalid.", cPikScheme);
        return rv;
    }

    if(pcPikCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_KEY_CIPHER;
    }

    if((strlen(pcPikCipherByZmk) != 16) && (strlen(pcPikCipherByZmk) != 32) && (strlen(pcPikCipherByZmk) != 33))
    {
        LOG_ERROR("Parameter pcPikCipherByZmk length = [%d] is invalid.", strlen(pcPikCipherByZmk));
        return HAR_PARAM_KEY_CIPHER;
    }

    if(strlen(pcPikCipherByZmk) == 16)
    {
        memcpy(szPikCipher, pcPikCipherByZmk, 16);
    }
    else if(strlen(pcPikCipherByZmk) == 32)
    {
        memcpy(szPikCipher, "X", 1);
        memcpy(szPikCipher + 1, pcPikCipherByZmk, 32);
    }
    else if(strlen(pcPikCipherByZmk) == 33)
    {
        memcpy(szPikCipher, pcPikCipherByZmk, 33);
    }

    if(pcPikCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcPikCv == NULL)
    {
        LOG_ERROR("Parameter pcPikCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_ImportKey_A6(hSessionHandle,"001", iKeyIdx, szKeyCipher, szPikCipher, cPikScheme, '0', 0, NULL, pcPikCipherByLmk, pcPikCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_ImportMak
* Function:   ����MAK
* Input:
*   @iKeyIdx             ��Կ����
*   @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @cMakScheme          MAK�㷨��ʶ
*   @pcMakCipherByZmk    ZMK���ܵ�MAK��Կ����
* Output:
*   @pcMakCipherByLmk    LMK���ܵ�MAK��Կ����
*   @pcMakCv             MAKУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_ImportMak(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cMakScheme,
        char    *pcMakCipherByZmk,
        char    *pcMakCipherByLmk/*OUT*/,
        char    *pcMakCv/*OUT*/)
{
    int     rv = HAR_OK;
    char    szKeyCipher[33 + 1] = {0};
    char    szMakCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cMakScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cMakScheme = [%c] is invalid.", cMakScheme);
        return rv;
    }

    if(pcMakCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_KEY_CIPHER;
    }

    if((strlen(pcMakCipherByZmk) != 16) && (strlen(pcMakCipherByZmk) != 32) && (strlen(pcMakCipherByZmk) != 33))
    {
        LOG_ERROR("Parameter pcMakCipherByZmk length = [%d] is invalid.", strlen(pcMakCipherByZmk));
        return HAR_PARAM_KEY_CIPHER;
    }

    if(strlen(pcMakCipherByZmk) == 16)
    {
        memcpy(szMakCipher, pcMakCipherByZmk, 16);
    }
    else if(strlen(pcMakCipherByZmk) == 32)
    {
        memcpy(szMakCipher, "X", 1 );
        memcpy(szMakCipher + 1, pcMakCipherByZmk, 32);
    }
    else if(strlen(pcMakCipherByZmk) == 33)
    {
        memcpy(szMakCipher, pcMakCipherByZmk, 33);
    }

    if(pcMakCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcMakCv == NULL)
    {
        LOG_ERROR("Parameter pcMakCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_ImportKey_A6(hSessionHandle, "008", iKeyIdx, szKeyCipher, szMakCipher, cMakScheme, '0', 0, NULL, pcMakCipherByLmk, pcMakCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_EncryptData
* Function:   ͨ�����ݼ���
* Input:
*    @iKeyIdx                    ��Կ����
*    @pcKeyCipherByLmk           ��Կ����
*    @iEncMode                   �㷨ģʽ
*    @iSessionKeyMode            �Ự��Կ����ģʽ
*    @pcSessionKeyData           �Ự��Կ����
*    @iPaddingMode               �������ģʽ
*    @pcInData                   ���������
*    @pcIv                       ��ʼ������
* Output:
*    @pcOutData                  ��������
*
* Return:       0 for success, other is error
* Description:  ͨ�����ݼ���,ʹ�õ���Կ����DEK/ZEK -- 00A
*
* Date:         2014.7.24
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_EncryptData(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iEncMode,
        int     iDeriveNum,
        char    *pcDeriveData,
        int     iSessionKeyMode,
        char    *pcSessionKeyData,
        int     iPaddingMode,
        char    *pcInData,
        char    *pcIv,
        char    *pcOutData)
{
    int     rv = HAR_OK;
    int     iOutDataLen = 0;
    int     iInDataLen = 0;
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};

    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        LOG_ERROR( "Parameter iKeyIdx[%d] Invalid, Must be 0-2048.", iKeyIdx );
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcKeyCipherByLmk) != 16
                && strlen(pcKeyCipherByLmk) != 17
                && strlen(pcKeyCipherByLmk) != 33
                && strlen(pcKeyCipherByLmk) != 49)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk'length = [%d] is invalid. It must be 16, 17, 33 or 49.", strlen(pcKeyCipherByLmk));
            return HAR_PARAM_LEN;
        }
    }

    if(iEncMode != 0 && iEncMode != 1)
    {
        LOG_ERROR("Parameter iEncMode = [%d] is invalid. It must be 0 or 1.", iEncMode);
        return HAR_PARAM_ENC_MODE;
    }

    if(iDeriveNum < 0 || iDeriveNum > 3)
    {
        LOG_ERROR("Parameter iDeriveNum = [%d] is invalid. It must be 0-3.", iDeriveNum);
        return HAR_PARAM_DERIVE_NUM;
    }

    if(iDeriveNum != 0)
    {
        if(pcDeriveData == NULL)
        {
            LOG_ERROR("Parameter pcDeriveData = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if((int)strlen(pcDeriveData) != 32 * iDeriveNum)
        {
            LOG_ERROR("Parameter pcDeriveData'length = [%d] is invalid. It must be %d characters.", 32 * iDeriveNum);
            return HAR_PARAM_LEN;
        }
    }

    rv = Tools_CheckSessionKeyDataValidity(iSessionKeyMode, pcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSessionKeyMode or pcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iPaddingMode = [%d] is invalid.", iPaddingMode);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter error: pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iInDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed.");
        return HAR_HEX_TO_BYTE;
    }

    if(iEncMode == 1)
    {
        if(pcIv == NULL)
        {
            LOG_ERROR("Parameter error: pcIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if((strlen(pcIv) != 16 && strlen(pcIv) != 32))
        {
            LOG_ERROR("Parameter error, pcIv'length = [%d] is invalid. It must be 16 or 32 characters", pcIv);
            return HAR_PARAM_VALUE;
        }
    }

    if(pcOutData == NULL)
    {
        LOG_ERROR("Parameter error: pcOutData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_IC_SymmKeyEncryptData(
            hSessionHandle,
            iEncMode,
            "00A",
            iKeyIdx,
            pcKeyCipherByLmk,
            pcDeriveData,
            iSessionKeyMode,
            pcSessionKeyData,
            iPaddingMode,
            pcIv,
            aucInData,
            iInDataLen,
            aucOutData,
            &iOutDataLen);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    rv = Tools_ConvertByte2HexStr(aucOutData, iOutDataLen, pcOutData);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Byte data conversion to hexadecimalstring failure.");
        return HAR_BYTE_TO_HEX;
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_DecryptData
* Function:   ͨ�����ݽ���
* Input:
*    @iKeyIdx                    ��Կ����
*    @pcKeyCipherByLmk           ��Կ����
*    @iEncMode                   �㷨ģʽ
*    @iSessionKeyMode            �Ự��Կ����ģʽ
*    @pcSessionKeyData           �Ự��Կ����
*    @iPaddingMode               �������ģʽ
*    @pcInData                   �������������
*    @pcIv                       ��ʼ������
* Output:
*    @pcOutData                  ��������
*
* Return:       0 for success, other is error
* Description:  ͨ�����ݽ��ܣ�ʹ�õ���Կ����DEK/ZEK -- 00A
*
* Date:         2014.7.24
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_DecryptData(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iEncMode,
        int     iDeriveNum,
        char    *pcDeriveData,
        int     iSessionKeyMode,
        char    *pcSessionKeyData,
        int     iPaddingMode,
        char    *pcInData,
        char    *pcIv,
        char    *pcOutData)
{
    int     rv = HAR_OK;
    int     iOutDataLen = 0;
    int     iDataLen = 0;
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};

    if(iKeyIdx < 0|| iKeyIdx > 2048)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invaild, it must be 0 - 2048.", iKeyIdx);
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            LOG_ERROR("pcKeyCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcKeyCipherByLmk) != 17 && strlen(pcKeyCipherByLmk) != 33 && strlen(pcKeyCipherByLmk) != 49)
        {
            LOG_ERROR("pcKeyCipherByLmk = [%s] is invalid.Its length must be 17, 33 or 49.", pcKeyCipherByLmk);
            return HAR_PARAM_LEN;
        }
    }

    if(iEncMode != 0 && iEncMode != 1)
    {
        LOG_ERROR("iEncMode = [%d] invalid, It must be 0 or 1.", iEncMode);
        return HAR_PARAM_ENC_MODE;
    }

    if(iDeriveNum < 0 || iDeriveNum > 3)
    {
        LOG_ERROR("iDeriveNum = [%d] invalid, DispCnt must be 0-3.", iDeriveNum);
        return HAR_PARAM_DERIVE_NUM;
    }

    if(iDeriveNum != 0)
    {
        if(pcDeriveData == NULL || (int)strlen(pcDeriveData) != 32 * iDeriveNum)
        {
            LOG_ERROR("pcDeriveData = [%s] invalid, pcDeriveData'length must be %d.", pcDeriveData, 32 * iDeriveNum);
            return HAR_PARAM_DERIVE_NUM;
        }
    }

    rv = Tools_CheckSessionKeyDataValidity(iSessionKeyMode, pcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSessionKeyMode or pcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iPaddingMode = [%d] is invalid.", iPaddingMode);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcInData) % 2 != 0)
    {
        LOG_ERROR("Parameter ERROR, pcInData'length = [%d] is invalid. Its length must be multiples of 2.", strlen(pcInData));
        return HAR_PARAM_LEN;
    }

    /*** ����ת�� ***/
    iDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    if(iEncMode == 1)
    {
        if(pcIv == NULL)
        {
            LOG_ERROR("pcIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if((strlen(pcIv) != 16 && strlen(pcIv) != 32))
        {
            LOG_ERROR("pcIv = [%s] is invalid.", pcIv);
            return HAR_PARAM_VALUE;
        }
    }

    if(pcOutData == NULL)
    {
        LOG_ERROR( "pcOutData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_IC_SymmKeyDecryptData(
            hSessionHandle,
            iEncMode,
            "00A",
            iKeyIdx,
            pcKeyCipherByLmk,
            pcDeriveData,
            iSessionKeyMode,
            pcSessionKeyData,
            iPaddingMode,
            pcIv,
            aucInData,
            iDataLen,
            aucOutData/*out*/,
            &iOutDataLen/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    rv = Tools_ConvertByte2HexStr(aucOutData, iOutDataLen, pcOutData);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Byte data conversion to hexadecimalstring failure.");
        return HAR_BYTE_TO_HEX;
    }

    return 0;
}

/***************************************************************************
* Subroutine: Tass_Decrypt_PIN
* Function:   ����PIN
* Input:
*   @iKeyIdx             ��Կ����
*   @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @pcPinBlkCipher      PIN������
*   @iPinBlkFmt          PIN���ʽ
*   @pcPan               ��PAN
* Output:
*   @pcPinText           PIN����
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_Decrypt_PIN(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPinBlkCipher,
        int     iPinBlkFmt,
        char    *pcPan,
        char    *pcPinText/*out*/)
{
    int     rv = HAR_OK;
    char    szLmkPin[129] = {0};
    char    szPin[129] = {0};

    rv = Tools_CheckKeyValidity_1(iKeyIdx, pcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    rv = Tools_CheckKeyValidity_1(iKeyIdx, pcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPinBlkCipher == NULL)
    {
        LOG_ERROR("Parameter pcPinBlkCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 12 && strlen(pcPan) != 18)
    {
        LOG_ERROR("Parameter pcPan[%s] Invalid, pcPan'length must be 12 or 18.", pcPan);
        return HAR_PARAM_LEN;
    }

    /*** call JE ת���� ***/
    rv = HSM_RCL_TransferCipherPin_Zpk2Lmk(hSessionHandle,iKeyIdx, pcKeyCipherByLmk, iPinBlkFmt, pcPan, pcPinBlkCipher, szLmkPin/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code1 = [%d], [%#010X].", rv, rv);
        return rv;
    }
    /*** call NG ����PIN�� ***/
    rv = HSM_RCL_DecryptPin_LMK(hSessionHandle,szLmkPin, pcPan, pcPinText/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code2 = [%d], [%#010X].", rv, rv);
        return rv;
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenUnionMac_IV
* Function:   ��������MAC����IV��
* Input:
*   @iKeyIdx             ��Կ����
*   @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @pcIV                ��ʼ������
*   @iMacDataLen         ������MAC������
*   @pcMacData           ������MAC�����ݵĳ���
* Output:
*   @pcMac               MACֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenUnionMac_IV(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcIV,
        int     iMacDataLen,
        char    *pcMacData,
        char    *pcMac/*out*/)
{
    int     rv = HAR_OK;
    int     iDataLen = 0;
    char    szKeyCipher[49 + 1] = {0};
    unsigned char aucData[1024 * 4] = {0};
    char    szIV[32 + 1] = {0};
    char    szKeyType[3 + 1] = {0};
    char    szKeyScheme[1 + 1] = {0};
    char    szKeyCv[16 + 1] = {0};
    char    szKeyLabel[16 + 1] = {0};
    char    szTime[64 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcMacData == NULL)
    {
        LOG_ERROR("Parameter pcMacdata = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(iMacDataLen != (int)strlen(pcMacData))
    {
        LOG_ERROR("Parameter iMacDataLen = [%d] is invalid.", iMacDataLen);
        return HAR_PARAM_LEN;
    }

    iDataLen = Tools_ConvertHexStr2Byte(pcMacData, strlen(pcMacData), aucData);
    if(iDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcMacData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    if(pcMac == NULL)
    {
        LOG_ERROR("Parameter pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(iKeyIdx > 0)
    {
        rv = HSM_IC_GetKeyInfo(
                    iKeyIdx,
                    szKeyType,
                    szKeyScheme,
                    szKeyCv,
                    szKeyLabel,
                    szTime);
        if(rv)
        {
            LOG_ERROR("HSM_IC_GetKeyInfo failed, error code = [%d].", rv);
            return rv;
        }

        if(!strcmp(szKeyScheme, "P") || !strcmp(szKeyScheme, "L") || !strcmp(szKeyScheme, "R"))
        {
            if(pcIV == NULL)
            {
                strcpy(szIV, "00000000000000000000000000000000");
            }
            else
            {
                if(strlen(pcIV) != 32)
                {
                    LOG_ERROR("Parameter pcIV length = [%d] is invalid. It must be 32 characters.", strlen(pcIV));
                    return HAR_PARAM_LEN;
                }

                strcpy(szIV, pcIV);
            }
        }
        else
        {
            if(pcIV == NULL)
            {
                strcpy(szIV, "0000000000000000");
            }
            else
            {
                if(strlen(pcIV) != 16)
                {
                    LOG_ERROR("Parameter pcIV length = [%d] is invalid. It must be 16 characters.", strlen(pcIV));
                    return HAR_PARAM_LEN;
                }

                strcpy(szIV, pcIV);
            }
        }
    }
    else
    {
        if(szKeyCipher[0] == 'P' || szKeyCipher[0] == 'L' || szKeyCipher[0] == 'R')
        {
            if(pcIV == NULL)
            {
                strcpy(szIV, "00000000000000000000000000000000");
            }
            else
            {
                if(strlen(pcIV) != 32)
                {
                    LOG_ERROR("pcIV length = [%d] is invalid. It must be 32 characters.", strlen(pcIV));
                    return HAR_PARAM_LEN;
                }

                strcpy(szIV, pcIV);
            }
        }
        else
        {
            if(pcIV == NULL)
            {
                strcpy(szIV, "0000000000000000");
            }
            else
            {
                if(strlen(pcIV) != 16)
                {
                    LOG_ERROR("Parameter pcIV length = [%d] is invalid. It must be 16 characters.", strlen(pcIV));
                    return HAR_PARAM_LEN;
                }

                strcpy(szIV, pcIV);
            }
        }
    }

    rv =  HSM_IC_GenerateMac_SM4(
                1,
                "008",
                iKeyIdx,
                szKeyCipher,
                "",
                0,                  /*** �Ựģʽ ***/
                "",                 /*** �Ự���� ***/
                2,
                aucData,            /*** ��������� ***/
                iDataLen,           /*** ��������ݳ��� ***/
                szIV,
                pcMac);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenerateKey
* Function:   ���������Կ
* Input:
*   @iZmkIdx             ��Կ����
*   @pcZmkCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @pcKeyType           ��Կ����
*   @cScheme             �㷨��ʶ
* Output:
*   @pcKeyCipherByZmk    ZMK���ܵ���Կ����
*   @pcKeyCipherByLmk    LMK���ܵ���Կ����
*   @pcCkv               ��ԿУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenerateKey(
        void *hSessionHandle,
        int     iZmkIdx,
        char    *pcZmkCipherByLmk,
        char    *pcKeyType,
        char    cScheme,
        char    *pcKeyCipherByZmk/*out*/,
        char    *pcKeyCipherByLmk/*out*/,
        char    *pcCkv/*out*/)
{
    int rv = HAR_OK;

    rv = Tools_CheckKeyValidity_1(iZmkIdx, pcZmkCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iZmkIdx = [%d] or pcZmkCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iZmkIdx, pcZmkCipherByLmk, rv);
        return rv;
    }

    rv = Toos_CheckKeyType(pcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcKeyType = [%s] is invalid.", pcKeyType);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cScheme = [%c] is invalid.", cScheme);
        return rv;
    }

    if(pcKeyCipherByZmk == NULL)
    {
        LOG_ERROR("pcKeyCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcCkv == NULL)
    {
        LOG_ERROR("pcCkv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
        hSessionHandle,
        1,                  /*** ��Կ����ģʽ ***/
        pcKeyType,
        cScheme,
        iZmkIdx,
        pcZmkCipherByLmk,
        cScheme,
        'N',               /*** ��Կ�洢��ʶ ***/
        0,
        "",                /*** ��Կ��ǩ ***/
        pcKeyCipherByLmk/*out*/,
        pcKeyCipherByZmk/*out*/,
        pcCkv/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_AcceptKey
* Function:   ������Կ
* Input:
*   @iZmkIdx             ��Կ����
*   @pcZmkCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @pcKeyCipherByZmk    ZMK���ܵ���Կ����
*   @pcKeyType           ��Կ����
*   @cScheme             �㷨��ʶ
* Output:
*   @pcKeyCipherByLmk    LMK���ܵ���Կ����
*   @pcCkv               ��ԿУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_AcceptKey(
        void    *hSessionHandle,
        int     iZmkIdx,
        char    *pcZmkCipherByLmk,
        char    *pcKeyCipherByZmk,
        char    *pcKeyType,
        char    cScheme,
        char    *pcKeyCipherByLmk/*out*/,
        char    *pcCkv/*out*/)
{
    int rv = HAR_OK;

    rv = Tools_CheckKeyValidity_1(iZmkIdx, pcZmkCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iZmkIdx = [%d] or pcZmkCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iZmkIdx, pcZmkCipherByLmk, rv);
        return rv;
    }

    if(pcKeyCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByZmk = [%s] is  invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcKeyCipherByZmk) != 16 && strlen(pcKeyCipherByZmk) != 33 && strlen(pcKeyCipherByZmk) != 49)
    {
        LOG_ERROR("Parameter pcKeyCipherByZmk length = [%d] is invalid. It must be 16, 33 or 49 characters.", strlen(pcKeyCipherByZmk));
        return HAR_PARAM_LEN;
    }

    rv = Toos_CheckKeyType(pcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcKeyType = [%s] is invalid.", pcKeyType);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cScheme = [%c] is invalid.", cScheme);
        return rv;
    }

    if(pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcCkv == NULL)
    {
        LOG_ERROR("Parameter pcCkv = [%s] invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_ImportKey_A6(
            hSessionHandle,
            pcKeyType,
            iZmkIdx,
            pcZmkCipherByLmk,
            pcKeyCipherByZmk,
            cScheme,
            'N',
            0,
            "",
            pcKeyCipherByLmk/*OUT*/,
            pcCkv/*OUT*/ );
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_ExportKey
* Function:   ������Կ
* Input:
*   @iZmkIdx             ��Կ����
*   @pcZmkCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @pcKeyType           ��Կ����
*   @iKeyIdx             ����������Կ����
*   @pcKeyCipherByLmk    LMK���ܵĴ�������Կ����
*   @cScheme             �㷨��ʶ
* Output:
*   @pcKeyCipherByZmk    ZMK���ܵ���Կ����
*   @pcCkv               ��ԿУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_ExportKey(
        int     iZmkIdx,
        char    *pcZmkCipherByLmk,
        char    *pcKeyType,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cScheme,
        char    *pcKeyCipherByZmk/*out*/,
        char    *pcKcv/*out*/)
{
    int rv = HAR_OK;

    rv = Tools_CheckKeyValidity_1(iZmkIdx, pcZmkCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iZmkIdx = [%d] or pcZmkCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iZmkIdx, pcZmkCipherByLmk, rv);
        return rv;
    }

    rv = Toos_CheckKeyType(pcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcKeyType = [%s] is invalid.", pcKeyType);
        return rv;
    }

    rv = Tools_CheckKeyValidity_1(iKeyIdx, pcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cScheme = [%c] is invalid.", cScheme);
        return rv;
    }

    if(pcKeyCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcKcv == NULL)
    {
        LOG_ERROR("Parameter pcKcv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_ExportKey_A8(
        pcKeyType,
        iZmkIdx,
        pcZmkCipherByLmk,
        iKeyIdx,
        pcKeyCipherByLmk,
        cScheme,
        pcKeyCipherByZmk/*out*/,
        pcKcv/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_TransferCipher
* Function:   ����ת����
* Input:
*   @iSrcKeyIdx             Դ��Կ����
*   @pcSrcKeyCipherByLmk    Դ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
*   @iSrcEncMode            Դ�����㷨ģʽ
*   @iSrcDispCnt            Դ��Կ��ɢ����
*   @pcSrcDispData          Դ��Կ��ɢ����
*   @iSrcSessionKeyMode     Դ�Ự��Կ����ģʽ
*   @pcSrcSessionKeyData    Դ�Ự��Կ����
*   @iSrcPaddingMode        Դ�������ģʽ
*   @pcSrcIv                Դ��ʼ������
*   @iDstKeyIdx             Ŀ����Կ����
*   @pcDstKeyCipherByLmk    Ŀ����Կ����
*   @iDstEncMode            Ŀ�ļ����㷨ģʽ
*   @iDstDispCnt            Ŀ����Կ��ɢ����
*   @pcDstDispData          Ŀ����Կ��ɢ����
*   @iDstSessionKeyMode     Ŀ�ĻỰ��Կ����ģʽ
*   @pcDstSessionKeyData    Ŀ�ĻỰ��Կ����
*   @iDstPaddingMode        Ŀ���������ģʽ
*   @pcDstIv                Ŀ�ĳ�ʼ������
* Output:
*   @pcDstCipher            ת���ܺ����������
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.08
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_TransferCipher(
        int     iSrcKeyIdx,
        char    *pcSrcKeyCipherByLmk,
        int     iSrcEncMode,
        int     iSrcDispCnt,
        char    *pcSrcDispData,
        int     iSrcSessionKeyMode,
        char    *pcSrcSessionKeyData,
        int     iSrcPaddingMode,
        char    *pcSrcIv,
        char    *pcSrcCipher,
        int     iDstKeyIdx,
        char    *pcDstKeyCipherByLmk,
        int     iDstEncMode,
        int     iDstDispCnt,
        char    *pcDstDispData,
        int     iDstSessionKeyMode,
        char    *pcDstSessionKeyData,
        int     iDstPaddingMode,
        char    *pcDstIv,
        char    *pcDstCipher/*out*/)
{
    int     rv = HAR_OK;
    int     iSrcCipherLen = 0;
    int     iDstCipherLen = 0;
    unsigned char aucSrcCipher[2048] = {0};
    unsigned char aucDstCipher[2048] = {0};

    rv = Tools_CheckKeyValidity_1(iSrcKeyIdx, pcSrcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcKeyIdx = [%d] or pcSrcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iSrcKeyIdx, pcSrcKeyCipherByLmk, rv);
        return rv;
    }

    if(iSrcEncMode < 0 || iSrcEncMode > 3)
    {
        LOG_ERROR("Parameter iSrcEncMode = [%d] is invalid. It must be 0, 1, 2 or 3.", iSrcEncMode);
        return HAR_PARAM_VALUE;
    }

    if(iSrcDispCnt < 0 || iSrcDispCnt > 8)
    {
        LOG_ERROR("Parameter iSrcDispCnt = [%d] is invalid. It must be 0 -- 8.", iSrcDispCnt);
        return HAR_PARAM_VALUE;
    }

    if(pcSrcDispData == NULL)
    {
        LOG_ERROR("Parameter pcSrcDispData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcSrcDispData) % 32 != 0 || (32 * iSrcDispCnt != (int)strlen(pcSrcDispData)))
    {
        LOG_ERROR("Parameter pcSrcDispData length = [%d] is invalid. It must be multiple of 32.", strlen(pcSrcDispData));
        return HAR_PARAM_LEN;
    }

    rv = Tools_CheckSessionKeyDataValidity(iSrcSessionKeyMode, pcSrcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcSessionKeyMode or pcSrcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iSrcPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcPaddingMode = [%d] is invalid.", iSrcPaddingMode);
        return rv;
    }

    if(iSrcEncMode)
    {
        if(pcSrcIv == NULL)
        {
            LOG_ERROR("Parameter pcSrcIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }
        if(strlen(pcSrcIv) != 16 && strlen(pcSrcIv) != 32)
        {
            LOG_ERROR("Parameter pcSrcIv length = [%d] is invalid. It must be 16 or 32 characters.", strlen(pcSrcIv));
            return HAR_PARAM_LEN;
        }
    }

    if(pcSrcCipher == NULL)
    {
        LOG_ERROR("Parameter pcSrcCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcSrcCipher) % 2 != 0)
    {
        LOG_ERROR("Parameter pcSrcCipher length = [%d] is invalid.", strlen(pcSrcCipher));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcSrcCipher) > 4096)
    {
        LOG_ERROR("Parameter pcSrcCipher length = [%d] is invalid. It must be less than 4096.", strlen(pcSrcCipher));
        return HAR_PARAM_LEN;
    }

    rv = Tools_CheckHex(pcSrcCipher);
    if(rv)
    {
        LOG_ERROR("Parameter pcSrcCipher = [%s] is invalid. It must be hex string.", pcSrcCipher);
        return HAR_PARAM_VALUE;
    }

    rv = Tools_CheckKeyValidity_1(iDstKeyIdx, pcDstKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iDstKeyIdx = [%d] or pcDstKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iDstKeyIdx, pcDstKeyCipherByLmk, rv);
        return rv;
    }

    if(iDstEncMode < 0 || iDstEncMode > 3)
    {
        LOG_ERROR("Parameter iDstEncMode = [%d] is invalid. It must be 0, 1, 2 or 3.", iDstEncMode);
        return HAR_PARAM_VALUE;
    }

    if(iDstDispCnt < 0 || iDstDispCnt > 8)
    {
        LOG_ERROR("Parameter iDstDispCnt = [%d] is invalid. It must be 0 -- 8.", iDstDispCnt);
        return HAR_PARAM_VALUE;
    }

    if(pcDstDispData == NULL)
    {
        LOG_ERROR("Parameter pcDstDispData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcDstDispData) % 32 != 0 || (32 * iDstDispCnt != (int)strlen(pcDstDispData)))
    {
        LOG_ERROR("Parameter pcDstDispData length = [%d] is invalid. It must be multiple of 32.", strlen(pcDstDispData));
        return HAR_PARAM_LEN;
    }

    rv = Tools_CheckSessionKeyDataValidity(iDstSessionKeyMode, pcDstSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iDstSessionKeyMode or pcDstSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iDstPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iDstPaddingMode = [%d] is invalid.", iDstPaddingMode);
        return rv;
    }

    if(iDstEncMode)
    {
        if(pcDstIv == NULL)
        {
            LOG_ERROR("Parameter pcDstIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }
        if(strlen(pcDstIv) != 16 && strlen(pcDstIv) != 32)
        {
            LOG_ERROR("Parameter pcDstIv length = [%d] is invalid. It must be 16 or 32 characters.", strlen(pcDstIv));
            return HAR_PARAM_LEN;
        }
    }

    if(pcDstCipher == NULL)
    {
        LOG_ERROR("Parameter pcDstCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = Tools_ConvertHexStr2Byte(pcSrcCipher, strlen(pcSrcCipher), aucSrcCipher);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Parameter [pcSrcCipher] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    rv = HSM_IC_SymmKeyTransferCipher(
        iSrcEncMode,
        "00A",
        iSrcKeyIdx,
        pcSrcKeyCipherByLmk,
        pcSrcDispData,
        iSrcSessionKeyMode,
        pcSrcSessionKeyData,
        iSrcPaddingMode,
        pcSrcIv,
        iDstEncMode,
        "00A",
        iDstKeyIdx,
        pcDstKeyCipherByLmk,
        pcDstDispData,
        iDstSessionKeyMode,
        pcDstSessionKeyData,
        iDstPaddingMode,
        pcDstIv,
        aucSrcCipher,
        iSrcCipherLen,
        aucDstCipher/*out*/,
        &iDstCipherLen/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    rv = Tools_ConvertByte2HexStr(aucDstCipher, iDstCipherLen, pcDstCipher);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Byte data conversion to hexadecimalstring failure.");
        rv = HAR_BYTE_TO_HEX;
    }

    return rv;
}



/***************************************************************************
* Subroutine: Tass_Encrypt_OfflinePin
* Function:   �ѻ�PIN����
* Input:
*   @iKeyIdx            ��Կ����
*   @pcKeyCipherByLmk   ��Կ���ģ�������Կ����ֵΪ0ʱ�ò�����Ч
*   @pcPan              ��PAN��
*   @pcAtc              TAC
*   @pcPlaintextPin     PIN����
* Output:
*   @pcCipherPin        PIN����
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_Encrypt_OfflinePin(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcAtc,
        char    *pcPlaintextPin,
        char    *pcCipherPin/*out*/)
{
    int rv = HAR_OK;

    rv = Tools_CheckKeyValidity_1(iKeyIdx, pcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcAtc == NULL)
    {
        LOG_ERROR("Parameter pcAtc = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcAtc) != 4)
    {
        LOG_ERROR("Parameter pcAtc'length = [%d] is invalid. It must be 4 characters.", strlen(pcAtc));
        return HAR_PARAM_LEN;
    }

    if(pcPlaintextPin == NULL)
    {
        LOG_ERROR("Parameter pcPlaintextPin = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPlaintextPin) < 4 || strlen(pcPlaintextPin) > 12)
    {
        LOG_ERROR("Parameter pcPlaintextPin'length = [%d] is invalid. It must be 4 -- 12 characters.", strlen(pcPlaintextPin));
        return HAR_PARAM_LEN;
    }

    if(pcCipherPin == NULL)
    {
        LOG_ERROR("Parameter pcCipherPin = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** ���õײ�ָ��ӿ� ***/
    rv = HSM_IC_OfflinePin_PlaintextPin(
                iKeyIdx,
                pcKeyCipherByLmk,
                pcPan,
                pcAtc,
                "41",
                pcPlaintextPin,     /*** PIN���� ***/
                "",
                "000000000000",
                pcCipherPin/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_KeyTypeConversion
* Function:   ��Կ����ת��
* Input:
*   @iSrcKeyIdx            Դ��Կ����
*   @pcSrcKeyCipherByLmk   Դ��Կ���ģ�������Կ����ֵΪ0ʱ�ò�����Ч
*   @pcSrcKeyType          Դ��Կ����
*   @pcDstKeyType          Ŀ����Կ����
* Output:
*   @pcDstKeyCipherByLmk   Ŀ����Կ����
*   @pcDstKeyCv            Ŀ����ԿУ��ֵ
*
* Return:       �ɹ�����0��������ʾʧ��
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_KeyTypeConversion(
        int     iSrcKeyIdx,
        char    *pcSrcKeyCipherByLmk,
        char    *pcSrcKeyType,
        char    *pcDstKeyType,
        char    *pcDstKeyCipherByLmk/*out*/,
        char    *pcDstKeyCv/*out*/)
{
    int rv = HAR_OK;

    char cDstScheme = 'X';
    char pcKeyType[4] = {0};
    char pcKeyScheme[2] = {0};
    char pcKeyCv[17] = {0};
    char pcKeyLabel[32] = {0};
    char pcTime[32] = {0};

    rv = Tools_CheckKeyValidity_2(iSrcKeyIdx, pcSrcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcKeyIdx = [%d] or pcSrcKeyCipherByLmk = [%s] is invalid, reutrn code = [%#010X].",
                iSrcKeyIdx, pcSrcKeyCipherByLmk, rv);
    }

    rv = Toos_CheckKeyType(pcSrcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcSrcKeyType = [%s] is invalid.", pcSrcKeyType);
        return rv;
    }

    rv = Toos_CheckKeyType(pcDstKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcDstKeyType = [%s] is invalid.", pcDstKeyType);
        return rv;
    }

    if(pcDstKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcDstKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcDstKeyCv == NULL)
    {
        LOG_ERROR("Parameter pcDstKeyCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(iSrcKeyIdx)
    {
        rv = HSM_IC_GetKeyInfo(
            iSrcKeyIdx,
            pcKeyType,
            pcKeyScheme,
            pcKeyCv,
            pcKeyLabel,
            pcTime );
        if(rv)
        {
            LOG_ERROR("Tass hsm api return code1 = [%d], [%#010X].", rv, rv);
            return rv;
        }
        cDstScheme = pcKeyScheme[0];
    }
    else
    {
        cDstScheme = *pcSrcKeyCipherByLmk;
    }

    /*** ������Կ ***/
    rv = HSM_RCL_KeyTypeConversion(
            pcSrcKeyType,
            iSrcKeyIdx,
            pcSrcKeyCipherByLmk,
            pcDstKeyType,
            cDstScheme,
            pcDstKeyCipherByLmk/*out*/,
            pcDstKeyCv/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code2 = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_SetPrintFormat
* Function:   �����豸��ӡ��ʽ
* Input:
*    @pcFormatStr               ��ӡ��ʽ��Ϣ
* Output:
*    ��
*
* Return:       0 for success, other is error
* Description:
* Author:       Luo Cangjian
* Date:         2015.6.08
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_SetPrintFormat(char *pcFormatStr)
{
    int rv = HAR_OK;
    char szFormatData[512 + 1] = {0};

    if(pcFormatStr == NULL)
    {
        strcpy(szFormatData, ">L>010��Կ�ɷ�>025^P>L>L>010У��ֵ��>025^T>L>L>010��ע��Ϣ��>025^0>F");
    }
    else
    {
        if(strlen(pcFormatStr) > 512)
        {
            LOG_ERROR("Error, pcFormatStr length = [%d] is invalid, it must be less than 512 characters.", strlen(pcFormatStr));
            return HAR_PARAM_LEN;
        }
        strcpy(szFormatData, pcFormatStr);
    }

    /*** װ�ش�ӡ�����ݸ�ʽ ***/
    rv = HSM_RCL_LoadFormatData(szFormatData);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenPrintRandkey
* Function:   ���������Կ����ӡ���
* Input:
*    @pcKeyType                 ��Կ����
*    @cKeyScheme                �㷨��ʶ
*    @pcMarkInfo                ��ӡ��Ϣ
* Output:
*    @pcKeyCipherByLmk          ��Կ����
*    @pcKeyCv                   ��ԿУ��ֵ
*
* Return:       0 for success, other is error
* Description:
* Author:       Luo Cangjian
* Date:         2015.6.08
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_GenPrintRandkey(
        char    *pcKeyType,
        char    cKeyScheme,
        char    *pcMarkInfo,
        char    *pcKeyCipherByLmk,
        char    *pcKeyCv)
{
    int rv = HAR_OK;
    char pcPrintDomain[512 + 8] = {0};

    rv = Toos_CheckKeyType(pcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcKeyType = [%s] is invalid.", pcKeyType);
        return rv;
    }

    /*** �ж��㷨��ʶ�Ƿ���ȷ ***/
    rv = Tools_CheckSchemeValidity(cKeyScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cKeyScheme = [%c] is invalid.", cKeyScheme);
        return rv;
    }

    if(pcMarkInfo != NULL)
    {
        if(strlen(pcMarkInfo) > 512)
        {
            LOG_ERROR("Error, pcMarkInfo length = [%d] is invalid, it must be less than 512 characters.", strlen(pcMarkInfo));
            return HAR_PARAM_LEN;
        }

        strcpy(pcPrintDomain, pcMarkInfo);
        strcat(pcPrintDomain, ";");
    }

    if(pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Error, pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcKeyCv == NULL)
    {
        LOG_ERROR("Error, pcKeyCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenAndPrintKey(
                0,
                pcKeyType,
                cKeyScheme,
                0,
                30,
                10,
                pcPrintDomain,
                pcKeyCipherByLmk,
                pcKeyCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

