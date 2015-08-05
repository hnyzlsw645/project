/*----------------------------------------------------------------------|
|    hsmapi.c                                                           |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机金融交易通用接口                        |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-05. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History: TODO:密钥长度，以及数据长度的判断还需进一步检查。  |
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
#include "hsmapi_ic.h"
#include "hsmapi_racal.h"
#include "hsmapi_asym.h"
#include "hsmsocket.h"
#include "internal_structs.h"

/***************************************************************************
* Subroutine: SDF_OpenDevice
* Function:   打开设备句柄
* Input:
*    @pphDeviceHandle    设备句柄
*    @pcIp               IP地址
*    @iPort              端口号
*    @iMsgHeadLen        消息头长度
* Output:
*    无
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
int SDF_OpenDevice(void **phDeviceHandle, char *ipaddr, int port )
{
    int rt=0;
    Devicestruct *pDeviceStruct;

#ifdef TASS_DEBUG
    Log_Debug("%s", "Start...");
#endif

    if(ipaddr == NULL)
    {
        return HAR_PARAM_ISNULL;
    }

    if(port < 0)
    {
        return HAR_PARAM_VALUE;
    }

    if( *phDeviceHandle != NULL && ((Devicestruct*)(*phDeviceHandle))->status == 1 )
    {
        SDF_CloseDevice( phDeviceHandle );
    }

    pDeviceStruct = (Devicestruct*)malloc( sizeof(Devicestruct) );

    memset( pDeviceStruct, 0, sizeof(Devicestruct) );
    strncpy( pDeviceStruct->ip, ipaddr, 16 );
    pDeviceStruct->port = port;

    pDeviceStruct->sockfd = TCP_ConnectHsm( pDeviceStruct->ip, pDeviceStruct->port );
    if( (pDeviceStruct->sockfd) <= 0 )
    {
        LOG_ERROR( "%s, Error TCP_ConnectHsm return [%d].",
                __func__, pDeviceStruct->sockfd );
        rt = HAR_SOCK_CONNECT;
    }
    else
    {
        pDeviceStruct->status = 1;
        *phDeviceHandle = pDeviceStruct;
        rt = HAR_OK;
    }

#ifdef TASS_DEBUG
    Log_Debug("%s", "End.\n");
#endif

    return rt;
}


/***************************************************************************
* Subroutine: SDF_CloseDevice
* Function:   关闭设备句柄
* Input:
*    @phDeviceHandle    设备句柄
* Output:
*    无
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
int SDF_CloseDevice(void *hDeviceHandle)
{
    int rt=0;
    Devicestruct *pDeviceStruct = (Devicestruct*)hDeviceHandle;

#ifdef TASS_DEBUG
    Log_Debug("%s", "Start...");
#endif

    if( pDeviceStruct != NULL && pDeviceStruct->status == 1 )
    {
        pDeviceStruct = (Devicestruct*)hDeviceHandle;
        TCP_DisconnectHsm( pDeviceStruct->sockfd );
        pDeviceStruct->status = 2;
        free(pDeviceStruct);
    }

#ifdef TASS_DEBUG
    Log_Debug("%s", "End.\n");
#endif

    return rt;
}


/***************************************************************************
* Subroutine: SDF_OpenSession
* Function:   打开会话句柄
* Input:
*    @phDeviceHandle      设备句柄
*    @pphSessionHandle    会话句柄
* Output:
*    无
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle)
{
    int rt=0;
    Devicestruct* pDeviceStruct = (Devicestruct*)hDeviceHandle;
    Sessionstruct* pSessionStruct = NULL;

#ifdef TASS_DEBUG
    Log_Debug("%s", "Start...");
#endif

    if( pDeviceStruct == NULL || pDeviceStruct->status != 1 )
    {
        rt = HAR_DEVICEHANDLE_INVALID;
        LOG_ERROR( "%s, Error [%#X], DeviceHandle Inalid.",
                __func__, rt );
        return rt;
    }

    if( *phSessionHandle == NULL || ((Sessionstruct*)*phSessionHandle)->status != 1 )
    {
        pSessionStruct = (Sessionstruct*)malloc(sizeof(Sessionstruct));
        pSessionStruct->device = (Devicestruct*)hDeviceHandle;
        pSessionStruct->status = 1;
        pSessionStruct->hashCtx.m_uiMechanism = -1;
        *phSessionHandle = (void*)pSessionStruct;

    }
    if ( ((Sessionstruct*)*phSessionHandle)->status == 1 && ((Sessionstruct*)*phSessionHandle)->device != hDeviceHandle )
    {
        pSessionStruct->device = (Devicestruct*)hDeviceHandle;
    }

#ifdef TASS_DEBUG
    Log_Debug("%s", "End.\n");
#endif

    return rt;
}

/***************************************************************************
* Subroutine: SDF_CloseSession
* Function:   关闭会话句柄
* Input:
*    @phSessionHandle    会话句柄
* Output:
*    无
*
* Return:       0 for success, other is error
* Description:  关闭会话句柄
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
int SDF_CloseSession(void *hSessionHandle)
{
    int rt=0;
    Sessionstruct* pSessionStruct = (Sessionstruct*)hSessionHandle;

#ifdef TASS_DEBUG
    Log_Debug("%s", "Start...");
#endif

    if( pSessionStruct != NULL && pSessionStruct->status == 1 )
    {
        if( pSessionStruct->hashCtx.m_uiMechanism != -1 )
        {
            free(pSessionStruct->hashCtx.pucData);
            free(pSessionStruct->hashCtx.pucHash);
            pSessionStruct->hashCtx.m_uiMechanism = -1;
        }
        pSessionStruct->status = 2;
        pSessionStruct->device = NULL;
        free(pSessionStruct);
    }

#ifdef TASS_DEBUG
    Log_Debug("%s", "End.\n");
#endif

    return rt;
}



/***************************************************************************
 *   Subroutine: Tass_GenSm2Key
 *   Function:   随机生成RSA密钥对，并使用ZMK加密导出
 *   Input:
 *     @hSessionHandle         会话句柄
 *     @zmkIndex               密钥索引
 *     @zmk_Lmk                保护RSA密钥分量的保护密钥
 *     @zmk_disData            ZMK分散参数，NULL时不分散
 *     @mode                   加密算法模式
 *   Output:
 *     @SM2_D_ZMK              私钥分量D密文 
 *     @SM2_PUBKEY             DER编码公钥
 *     @SM2_LMK               LMK下加密的私钥
 *   Return:            成功返回0，其他表示失败
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
    //定义变量
    int rv = HAR_OK;
    int piDerPublicKeyLen = 0;
         int piPrivateKeyLen_Lmk = 0;
         char SM2PUBKEY[512] = {0};
         char SM2LMK[512] = {0};
         char SM2DZMK[512] = {0};
    int piPrivateKeyLen_Tk = 0;
    int len = 0;
    //检查参数
    if(zmkIndex >0 && strlen(zmk_Lmk) >=16 )
    {
        zmkIndex = 0;
    }
    if(strlen(zmk_disData) % 32 != 0)
    {
        LOG_ERROR("%s","zmk_disData is error,it should be n*32H");
        return rv;
    }
    if(mode <0 || mode >2)
    {
        mode = 0;
    }
        
    //分散参数
          int iTkDeriveNumber = zmk_disData == NULL ? 0 : strlen(zmk_disData)/32;
    
    //生成SM2
      rv = HSM_SM2_GenerateNewKeyPair(
                  hSessionHandle,
                     9999, "",/**产生sm2密钥的索引，标签**/
                     SM2PUBKEY,/**新生成的SM2公钥，DER编码**/ &piDerPublicKeyLen,
                   SM2LMK,/**LMK下加密的SM2私钥密文**/  &piPrivateKeyLen_Lmk );
             
         //导出密钥
    rv = HSM_SM2_ExportByTK(
                  hSessionHandle,mode,
                  "000",/**KEK**/
                  zmkIndex,/**<=0使用下一个参数,否则使用索引**/ zmk_Lmk,/**保护密钥**/
                  iTkDeriveNumber, zmk_disData,
                  0,/*要被导出的sm2索引*/
                  SM2PUBKEY, piDerPublicKeyLen,
                  SM2LMK, piPrivateKeyLen_Lmk,
                  SM2DZMK, &piPrivateKeyLen_Tk/*out*/ );
        
    len = Tools_ConvertByte2HexStr(SM2PUBKEY,piDerPublicKeyLen,SM2_PUBKEY);
        if(!len)
    {
        LOG_ERROR("%s","SM2_PUBKEY Convert Hex fail");
        return rv;
    }
    
    len = Tools_ConvertByte2HexStr(SM2LMK,strlen(SM2LMK),SM2_LMK);
       
    if(!len)
    {
        LOG_ERROR("%s","SM2_LMK Convert Hex fail");
        return rv;
    }
     
    len = Tools_ConvertByte2HexStr(SM2DZMK,piPrivateKeyLen_Tk,SM2_D_ZMK);
    if(!len)
    {
        LOG_ERROR("%s","SMK_D_ZMK Convert Hex fail");
    }
   return rv;

}


/***************************************************************************
 *    Subroutine: Tass_DeriveKeyExportedByRsa
 *    Function:   将ZMK分散产生子密钥，然后用保护密钥将子密钥加密保护导出  
 *    Input:
 *       @hSessionHandle         会话句柄
 *       @pcZmkCipher_Lmk        待分散的zmk
 *       @pcPublicKey            保护公钥，Der编码的RSA公钥
 *       @pcDisData              分散因子
 *    Output:
 *       @pcSubKeyCipher_TK      子密钥密文
 *       @pcSubKeyCipher_Lmk     LMK加密的子密钥密文
 *       @pcSubKeyCv             子密钥校验值
 *    Return:            成功返回0，其他表示失败
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
     //此处有问题
     rv = HSM_IC_ExportCipherKey(
                  hSessionHandle,
                  0,
                  "000",/*保护密钥类型*/
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
 * Function:   随机生成RSA密钥对，并使用ZMK加密导出
 * Input:
 *   @hSessionHandle  会话句柄
 *   @RsaLen          Rsa密钥模长
 *   @zmkIndex        保护密钥分散因子
 *   @zmk_Lmk         保护密钥
 *   @zmk_disData     保护密钥分散因子
 *   @mode            加密算法模式 0：ECB 01:CBC
 * Output:
 *   @Rsa_D_ZMK       RSA密钥D分量
 *   @Rsa_P_ZMK       RSA密钥P分量
 *   @Rsa_Q_ZMK       RSA密钥Q分量
 *   @Rsa_DP_ZMK      RSA密钥DP分量
 *   @Rsa_DQ_ZMK      RSA密钥DQ分量
 *   @Rsa_QINV_ZMK    RSA密钥QINV分量
 *   @Rsa_N           RSA_N
 *   @Rsa_E           RSA_E
 *   @Rsa_LMK         RSA_LMK
 * Return:            成功返回0，其他表示失败
 * Description:
 * Author:       Luo Cangjian
 * Date:         2015.06.05
 * ModifyRecord:
 * *************************************************************************/
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
      char *Rsa_DP_ZMK/*out*/,
      char *Rsa_DQ_ZMK/*out*/,
      char *Rsa_QINV_ZMK/*out*/,
      char *Rsa_N/*out*/,
      char *Rsa_E/*out*/,
      char *Rsa_LMK/*out*/)
{
    //定义变量
    int rv = HAR_OK;
          unsigned char pucDerPublicKey[512+32] = {0};
          char szDerPubKeyHex[1024] = {0};
          int piDerPublicKeyLen = 0;
          unsigned char pucPrivateKey_Lmk[512+32] = {0};
          unsigned char *piDerPublicKey[2048] = {0};
          int piPublicKey_mLen = 0;
          int piPublicKey_eLen = 0;
          int piPrivateKey_dLen = 0;
          int piPrivateKey_pLen = 0;
          int piPrivateKey_qLen = 0;
          int piPrivateKey_dpLen = 0;
          int piPrivateKey_dqLen = 0;
          int piPrivateKey_qInvLen = 0;
          char Rsa_N_m[512] = {0};//公钥
          char Rsa_E_m[512] = {0};//指数
          char Rsa_D_ZMK_m[512] = {0};
          char Rsa_P_ZMK_m[512] = {0};
          char Rsa_Q_ZMK_m[512] = {0};
          char Rsa_DP_ZMK_m[512] = {0};
          char Rsa_DQ_ZMK_m[512] = {0};
          char Rsa_QINV_ZMK_m[512] = {0};
    int piPrivateKeyLen_Lmk = 0;
    //检查参数
    if(RsaLen < 1024 || RsaLen >4096)
    {
        LOG_ERROR("%s","RsaLen is error,it should between 2048 and 4096");
        return rv;
    }    

    if(strlen(zmk_disData) % 32 != 0)
    {
        LOG_ERROR("%s","zmk_disData is error,it should be n*32H");
        return rv;
    }
    if(mode <0 || mode >2)
    {
        mode = 0;
    }
        //分散参数
          int iTkDeriveNumber = zmk_disData == NULL ? 0 : strlen(zmk_disData)/32;
          unsigned char Rsa_LMK_m[2048] = {0};
      rv = HSM_RSA_GenerateNewKeyPair(
           hSessionHandle,
           0, /**密钥索引，0表示不存储**/
           NULL, /**RSA密钥标签**/
           RsaLen, /**密钥模长**/
           NULL, /**公钥指数E ，默认为65537**/
           pucDerPublicKey/*out*/, 
           &piDerPublicKeyLen/*out*/,
           Rsa_LMK_m/*out*/,/**LMK下加密的RSA私钥密文**/ 
           &piPrivateKeyLen_Lmk/*out*/ );
    
    if(rv)
        {
              LOG_ERROR("%s","GenerateNewKeyPair is error");
              return rv;
        }
        
    int Rsa_N_Len = 0;
    int Rsa_E_Len = 0;
    unsigned char OutBuf[1024] = {0};
    int len = Tools_ConvertByte2HexStr(pucDerPublicKey,piDerPublicKeyLen, szDerPubKeyHex);
        //私钥转码
    len = Tools_ConvertByte2HexStr(Rsa_LMK_m,piPrivateKeyLen_Lmk, Rsa_LMK);
        
    //解密DER编码公钥
        rv =  Tools_DDer(szDerPubKeyHex,Rsa_N,&Rsa_N_Len,Rsa_E,&Rsa_E_Len);
       
     if(rv)
        {
           LOG_ERROR("%s","pucDerPublicKey Convert is error");
           return rv;
        }
      
    rv = HSM_RSA_ExportRSAKey(
               hSessionHandle,
               mode,  "000",
               zmkIndex, zmk_Lmk,/**保护密钥索引，保护密钥，索引为0则使用密钥值**/
               iTkDeriveNumber, zmk_disData,
               0,
               Rsa_LMK_m/*被导出私钥数据*/, piPrivateKeyLen_Lmk/*私钥长度*/,
               ""/*拓展标识*/, "",/*PAD标识*/
               1/*公钥输出格式，1为DER编码(模 、指数序列)*/,
              "",/*初始化向量*/
               piDerPublicKey/*OUT*/, &piDerPublicKeyLen/*OUT*/,
               Rsa_N_m/*OUT*/, &piPublicKey_mLen/*OUT*/,
               Rsa_E_m/*OUT*/, &piPublicKey_eLen/*OUT*/,
               Rsa_D_ZMK_m/*OUT*/, &piPrivateKey_dLen/*OUT*/,
               Rsa_P_ZMK_m/*OUT*/, &piPrivateKey_pLen/*OUT*/,
               Rsa_Q_ZMK_m/*OUT*/, &piPrivateKey_qLen/*OUT*/,
               Rsa_DP_ZMK_m/*OUT*/, &piPrivateKey_dpLen/*OUT*/,
               Rsa_DQ_ZMK_m/*OUT*/, &piPrivateKey_dqLen/*OUT*/,
               Rsa_QINV_ZMK_m/*OUT*/, &piPrivateKey_qInvLen/*OUT*/);  

    if(rv)
    {
              LOG_ERROR("%s","Hsmapi ExportRSAKey is error");
              return rv;
    }
    //转码
    len = Tools_ConvertByte2HexStr(Rsa_D_ZMK_m,piPrivateKey_dLen,Rsa_D_ZMK); 
    if(len == -1)
    {
              LOG_ERROR("%s","Rsa_D_ZMK Convert Hex fail");
              return rv;
    }
    len = Tools_ConvertByte2HexStr(Rsa_P_ZMK_m,piPrivateKey_pLen,Rsa_P_ZMK); 
    if(len == -1)
    {
              LOG_ERROR("%s","Rsa_P_ZMK Convert Hex fail");
              return rv;
    }
    len = Tools_ConvertByte2HexStr(Rsa_Q_ZMK_m,piPrivateKey_qLen,Rsa_Q_ZMK); 
    if(len == -1)
    {
              LOG_ERROR("%s","Rsa_P_ZMK Convert Hex fail");
              return rv;
    }
    len = Tools_ConvertByte2HexStr(Rsa_DP_ZMK_m,piPrivateKey_dpLen,Rsa_DP_ZMK); 
    if(len == -1)
    {
              LOG_ERROR("%s","Rsa_DP_ZMK Convert Hex fail");
              return rv;
    }

    len = Tools_ConvertByte2HexStr(Rsa_DQ_ZMK_m,piPrivateKey_dqLen,Rsa_DQ_ZMK); 
    if(len == -1)
    {
              LOG_ERROR("%s","Rsa_DQ_ZMK Convert Hex fail");
              return rv;
    }
    len = Tools_ConvertByte2HexStr(Rsa_QINV_ZMK_m,piPrivateKey_qInvLen,Rsa_QINV_ZMK);
    if(len == -1)
    {
              LOG_ERROR("%s","Rsa_QINV_ZMK COnvert Hex fail");
              return rv;
    }

    return rv; 
}

/***************************************************************************
 * Subroutine: Tass_PubKey_Oper
 * Function:   RSA/SM2公钥加密运算接口
 * Input:
 *   @hSessionHandle  会话句柄
 *   @keytype         密钥类型
 *   @indata          输入数据，与公钥等长
 *   @RSAPubKeyE      RSA公钥
 *   @RSAPubKeyN      RSA公钥
 *   @SM2PubKey       SM2公钥
 * Output:
 *   @outdata         加密后数据
 *
 * Return:            成功返回0，其他表示失败
 * Description:
 * Author:       Luo Cangjian
 * Date:         2015.06.05
 * ModifyRecord:
 * *************************************************************************/
HSMAPI int 
Tass_PubKey_Oper(
     void *hSessionHandle,
     int  keytype,
     char *indata,
     char *RSAPubKeyE,
     char *RSAPubKeyN,
     char *SM2PubKey,
     char *outdata/*out*/)
{
    //变量定义
    int rv = HAR_OK;
    char aucInData[2048*2] = {0};
    unsigned char publicDer[512+32] = {0}; 
    int publicDerLen = 512+32;
    unsigned char pucInput[1024*2] = {0};
    unsigned char pucOutput[1024*2] = {0};
    int piOutputLength = 0;
    int len = 0;    
    unsigned char SM2PubKey_temp[1024] = {0};

    //检查参数
    if(keytype != 0 && keytype != 1)
    {
        keytype = 0;
    }
    
    int indataLen =  Tools_ConvertHexStr2Byte(indata,strlen(indata),pucInput);
    if(indataLen == -1)
    {
        LOG_ERROR("%s","indata Convert Byte fail");
        return HAR_HEX_TO_BYTE;
    }
    
    
    
    if(keytype == 0)
    {
                
      //Der编码
        rv =  Tools_Der(RSAPubKeyN,RSAPubKeyE,publicDer,&publicDerLen);
        if(strlen(RSAPubKeyN) != strlen(indata))
        {
            LOG_ERROR("%s","indata length is error,it should equals publicDerLen");
            return rv;
        }
        //Tools_PrintBuf("der public key ", publicDer, publicDerLen);
    //加密数据
        rv = HSM_RSA_EncryptData( 
                    hSessionHandle,
                    0,/**不填充**/
                    0, /**RSA密钥索引**/
                    publicDer, publicDerLen,/**公钥及公钥长度**/
                    pucInput, indataLen,/**输入数据**/
                    pucOutput/*out*/, &piOutputLength/*out*/ );

    }
    else if(keytype == 1)
    {
            if(SM2PubKey == NULL)
        {
            LOG_ERROR("%s","SM2_PUBKEY is NULL");
            return rv;
        }
        //转码
        Tools_ConvertHexStr2Byte(SM2PubKey,strlen(SM2PubKey),SM2PubKey_temp);
        int sm2DerLen = Tools_GetFieldDerBufLength(SM2PubKey_temp);
        if(sm2DerLen == HAR_DER_DECODE)
        {
            LOG_ERROR("","get sm2DerLength failed");
             return rv;
        }
        rv = HSM_SM2_EncryptData(
                    hSessionHandle,0,
                    SM2PubKey_temp, sm2DerLen,
                    pucInput, indataLen,
                    pucOutput/*out*/, &piOutputLength/*out*/ );
    }
    else
    {
            LOG_ERROR("%s", "keytype is error");
            return rv;
    }
      
    if(rv)
    {
        LOG_ERROR("%s","EncryptData is error");
        return rv;
    }
    //转码
    len = Tools_ConvertByte2HexStr(pucOutput, piOutputLength, outdata);
    if(!len)
    {
        LOG_ERROR("%s","The outdata of Tass_PubKey_Oper  Convert Hex fail");
        return rv;
    }
  return rv;
}


/***************************************************************************
 * Subroutine: Tass_PRIVATE_Oper
 * Function:   私钥解密运算接口。
 * Input:
 *   @hSessionHandle  会话句柄
 *   @keytype         密钥类型,0为rsa,1为sm2
 *   @Rsa_LMK         rsa本地密钥
 *   @SM2_LMK         sm2本地密钥
 *   @indata          外部送入数据
 * Output:
 *   @outdata         私钥解密后数据
 *
 * Return:            成功返回0，其他表示失败
 * Description:
 * Author:       Luo Cangjian
 * Date:         2015.06.05
 * ModifyRecord:
 * *************************************************************************/
HSMAPI int 
Tass_PRIVATE_Oper(
     void *hSessionHandle,
     int   keytype,
     char *Rsa_LMK,
     char *SM2_LMK,
     char *indata,
     char *outdata/*out*/)
 
{
  //定义变量
    int   rv = HAR_OK;
    int   piOutputLength = 0;
    char  aucInData[2048*2] = {0};
    int   len = 0;
    char  Rsa_LMK_temp[1024] = {0};
    char  SM2_LMK_temp[1024] = {0};
    char  outdata_temp[2048] = {0};

    if(keytype != 1)
    {
        keytype = 0;
    }
    if(strlen(indata) <=0 || strlen(indata) > 2048)
    {
        LOG_ERROR("%s","indata is error,it should between 0----2048");
        return HAR_PARAM_LEN;
    }
    //转码    
    len = Tools_ConvertHexStr2Byte(indata,strlen(indata),aucInData);

    if(len == -1)
    {
        LOG_ERROR("%s","indata Covert Byte failed");
        return HAR_HEX_TO_BYTE;
    }    
    
   if(keytype == 0)
    {
      int RsaLen = Tools_ConvertHexStr2Byte(Rsa_LMK,strlen(Rsa_LMK),Rsa_LMK_temp);
      if(RsaLen == -1)
      {
        LOG_ERROR("%s","Rsa_LMK Covert Byte failed");
        return HAR_HEX_TO_BYTE;
      }
      rv = HSM_RSA_DecryptData(hSessionHandle,
                0,/**不填充**/
                9999,/**0或9999时下面两个参数可有效**/ 
                Rsa_LMK_temp, RsaLen,/**私钥及私钥长度**/
                aucInData, len,/**待解密的数据及长度**/
                outdata_temp/*out*/, &piOutputLength/*out*/ );
     }
     else if(keytype == 1)
     {
        if(strlen(indata) < 184 || strlen(indata) > 1996*2)
        {
            LOG_ERROR("%s","indata length is error ,it should between 96 and 1996 bytes ");
            return HAR_PARAM_LEN;
        }
        int sm2Len = Tools_ConvertHexStr2Byte(SM2_LMK,strlen(SM2_LMK),SM2_LMK_temp);
        if(sm2Len == -1)
        {
            LOG_ERROR("%s","SM2_LMK Covert Byte failed");
            return HAR_HEX_TO_BYTE;
        }
        rv = HSM_SM2_DecryptData(hSessionHandle,
               9999, /**SM2密钥索引，<=0或=9999时下述2个参数有效**/
               SM2_LMK_temp, /**LMK加密的SM2私钥**/
               sm2Len, /**LMK加密的SM2私钥长度**/
               aucInData, len,
               outdata_temp/*out*/, &piOutputLength/*out*/ );
     }
     else
     {
            LOG_ERROR("%s", "keytype is error");
            return HAR_PARAM_KEY_TYPE;
     }    

     if(rv)
     {
        LOG_ERROR("%s","DecryptData is fail");
        return rv;
     } 
     len = Tools_ConvertByte2HexStr(outdata_temp, piOutputLength, outdata);
     if(len == -1)
     {
        LOG_ERROR("%s","outdata Convert Hex is failed");
        return HAR_BYTE_TO_HEX;
     }
  return rv;

}

/***************************************************************************
* Subroutine: SDF_GenerateRandom
* Function:   产生随机数
* Input:
*   @hSessionHandle  会话句柄
*   @iRandomLen      随机数字节数
* Output:
*   @pcRandom        随机数据（十进制字符串）
*
* Return:            成功返回0，其他表示失败
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
SDF_GenerateRandom(void *hSessionHandle, int iRandomLen, char *pcRandom/*out*/)
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
 * Subroutine: Tass_DecryptTrackData
 * Function:   使用ZEK解密磁道数据。
 * Input:
 *   @hSessionHandle  会话句柄
 *   @iKeyIdx         密钥索引
 *   @pcKey_LMK       密钥密文
 *   @pcTrackText     磁道密文
 *   @iTrackTextLen   磁道密文长度
 *   @iAlgId          解密模式
 *   @pcIV            初始化IV 
 * Output:
 *   @pcTrackCipher   磁道明文
 *
 * Return:            成功返回0，其他表示失败
 * Description:
 * Author:       Luo Cangjian
 * Date:         2015.06.05
 * ModifyRecord:
 * *************************************************************************/
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
    int rv = HAR_OK;
    int iOutDataLen = 0;
    int iInDataLen = 0;
    int len = 0;
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};
    int piOutputLength= 0;
    //检查参数    
    if(strlen(pcTrackCipher)%2 != 0)
    {
        LOG_ERROR("%s","pcTrackCipher length is error");
        return HAR_PARAM_LEN;
    }
    if(iAlgId == 2 && strlen(pcIV) == 0)
    {
        LOG_ERROR("%s","the pcIV length is error");
        return HAR_PARAM_IV;
    }
    len =  Tools_ConvertHexStr2Byte(pcTrackCipher,strlen(pcTrackCipher),aucInData);
    if(len == -1)
    {
        LOG_ERROR("%s","PcTrackCipher Convert Byte fail");
        return HAR_HEX_TO_BYTE;
    }
    rv = HSM_IC_SymmKeyDecryptData(hSessionHandle,
                iAlgId,/**算法模式**/
                "00A",/**密钥类型**/
                iKeyIdx, pcKey_LMK,/**密钥**/
                "",/**分散因子**/ 
                0, "",/**会话密钥**/
                iPadFlg, pcIV,/**填充模式**/
                aucInData, len,
                aucOutData/*out*/, &piOutputLength/*out*/ );
    if(rv)
    {
        LOG_ERROR("%s","DecyptData failed");
        return rv;
    }

    len = Tools_ConvertByte2HexStr(aucOutData, piOutputLength, pcTrackText);
    if(len == -1)
    {
        LOG_ERROR("%s","pcTrackText Convert HexStr fail");
        return HAR_BYTE_TO_HEX;
    }
   return rv;
    
}




/*************************************************************************
 * Subroutine: Tass_EncryptTrackData
 * Function:   使用ZEK加密磁道数据。
 * Input:
 *   @hSessionHandle  会话句柄
 *   @iKeyIdx         密钥索引
 *   @pcKey_LMK       密钥密文
 *   @pcTrackText     磁道密文
 *   @iTrackTextLen   磁道密文长度
 *   @iAlgId          解密模式
 *   @pcIV            初始化IV 
 * Output:
 *   @pcTrackCipher   磁道密文
 *
 * Return:            成功返回0，其他表示失败
 * Description:
 * Author:       Luo Cangjian
 * Date:         2015.06.05
 * ModifyRecord:
 * *************************************************************************/
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
    int     len = 0;
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};
    int piOutputLength = 0;
    if(strlen(pcTrackText)%2 != 0)
    {
        LOG_ERROR("%s","the length of pcTrackText is error");
        return HAR_PARAM_LEN;
    }
    if(iAlgId == 2 && strlen(pcIV) == 0)
    {
        LOG_ERROR("%s","pcIV length is error");
        return HAR_PARAM_IV;
    }
    if(strlen(pcTrackCipher)%2 != 0)
    {
        LOG_ERROR("%s","pcTrackCipher length is error");
        return HAR_PARAM_LEN;
    }
    //输入数据转为二进制
    //输入数据转化
    len =  Tools_ConvertHexStr2Byte(pcTrackText,strlen(pcTrackText),aucInData);
    if(len == -1)
    {
        LOG_ERROR("%s","pcTrackText Convert byte fail");
        return HAR_HEX_TO_BYTE;
    }
    rv = HSM_IC_SymmKeyEncryptData(hSessionHandle,
                iAlgId,/**算法模式**/
                "00A",/**密钥类型**/
                iKeyIdx, pcKey_LMK,/**加密数据的密钥**/
                "",/**分散参数**/
                0, "",/**会话密钥**/
                iPadFlg, pcIV,/**填充模式及初始向量**/
                aucInData, len,/**磁道明文，及长度**/
                aucOutData/*out*/, &piOutputLength/*out*/ );
    //转为十六进制 
    len = Tools_ConvertByte2HexStr(aucOutData, piOutputLength, pcTrackCipher);
    if(len == -1)
    {
        
        LOG_ERROR("%s","pcTrackCipher Covert HexStr fail");
        return HAR_BYTE_TO_HEX;
    }
    return rv;
} 




/***************************************************************************
* Subroutine: Tass_VerifyARQC
* Function:   验证ARQC/TC
* Input:
*    @iKeyIdx               密钥索引
*    @pcKeyCipherByLmk      密钥密文
*    @pcPan                 PAN
*    @pcATC                 ATC
*    @pcTransData           交易数据
*    @pcARQC                待验证的ARQC
* Output:
*    无
*
* Return:      成功返回0，其他表示失败
* Description: 分散MDK源密钥产生卡片主密钥UDK，根据ATC值计算交易会话密钥SDK；
*              填充交易数据，使用SDK计算其MAC值，与输入的ARQC对比。
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
* Function:   计算ARPC
* Input:
*    @iKeyIdx               密钥索引
*    @pcKeyCipherByLmk      密钥密文，仅当索引号为0时有效
*    @pcPan                 卡号和卡序列号
*    @pcATC                 应用交易计数器，用于计算交易会话密钥
*    @pcARQC                ARQC
*    @pcARC                 ARC
* Output:
*    @pcARPC                输出的ARPC
*
* Return:       成功返回0，其他表示失败
* Description: 分散MDK源密钥产生卡片主密钥UDK，根据ATC值计算交易会话密钥SDK；
*              组织ARPC数据，用SDK加密数据，计算ARPC。
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

    /*** 该函数模式标志应该为2 ***/
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
* Function:   验证ARQC/TC并产生ARPC
* Input:
*    @iKeyIdx               密钥索引
*    @pcKeyCipherByLmk      密钥密文，仅当索引号为0时有效
*    @pcPan                 卡号和卡序列号
*    @pcATC                 应用交易计数器，用于计算交易会话密钥
*    @pcTransData           ARQC数据
*    @pcARQC                ARQC
*    @pcARC                 ARC
* Output:
*    @pcARPC                输出的ARPC
*
* Return:       成功返回0，其他表示失败
* Description: 分散MDK源密钥产生卡片主密钥UDK，根据ATC值计算交易会话密钥SDK；
*              填充交易数据，使用SDK计算其MAC值，与输入的ARQC对比并生成ARPC。
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

    /*** 该函数模式标志应该为1 ***/
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
* Function:   脚本加密
* Input:
*    @iKeyIdx               密钥索引
*    @pcKeyCipherByLmk      密钥密文，仅当索引号为0时有效
*    @pcPan                 卡号和卡序列号
*    @pcATC                 应用交易计数器，用于计算交易会话密钥
*    @pcTransData           脚本数据
* Output:
*    @pcDataCipher          脚本数据密文
*
* Return:       成功返回0，其他表示失败
* Description: 分散MDK源密钥产生卡片主密钥UDK，根据ATC值计算交易会话密钥SDK；
*              对输入数据进行填充，使用SDK进行加密运算,输出密文数据。
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

    /*** 脚本加密 ***/
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
* Function:   脚本MAC
* Input:
*    @iKeyIdx               密钥索引
*    @pcKeyCipherByLmk      密钥密文，仅当索引号为0时有效
*    @pcPan                 卡号和卡序列号
*    @pcATC                 应用交易计数器，用于计算交易会话密钥
*    @pcTransData           脚本数据
* Output:
*    @pcMAC                 脚本数据MAC
*
* Return:       成功返回0，其他表示失败
* Description: 分散MDK源密钥产生卡片主密钥UDK，根据ATC值计算交易会话密钥SDK；
*              对输入数据进行填充，使用SDK进行MAC运算，输出.
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

    /*** 计算脚本MAC ***/
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
* Function:   IC数据加密
* Input:
*   @iKeyIdx                 密钥索引
*   @pcKeyCipherByLmk        密钥密文，仅当索引号为0时该参数有效
*   @iEncMode                加密算法模式
*   @iDeriveNum              密钥分散级数
*   @pcDeriveData            密钥分散因子
*   @iSessionKeyMode         会话密钥模式
*   @pcSessionKeyData        会话密钥因子
*   @iPaddingMode            数据填充模式
*   @pcInData                输入数据
*   @pcIv                    IV向量
* Output:
*   @pcOutData               数据密文
*
* Return:       成功返回0，其他表示失败
* Description: 由应用系统确定密钥分散的模式，产生过程密钥，对指定的数据进行加密
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
            iEncMode,               /*** 加密算法模式 ***/
            "109",                  /*** 密钥类型 ***/
            iKeyIdx,                /*** 密钥索引 ***/
            szKeyCipher,            /*** 密钥密文 ***/
            pcDeriveData,           /*** 密钥分散因子 ***/
            iSessionKeyMode,        /*** 会话密钥产生模式 ***/
            pcSessionKeyData,       /*** 会话密钥因子 ***/
            iPaddingMode,           /*** 数据填充模式 ***/
            pcIv,                   /*** 初始化向量 ***/
            aucInData,              /*** 待加密的数据 ***/
            iInDataLen,             /*** 待加密的数据长度 ***/
            aucOutData,             /*** 输出的密钥密文 ***/
            &iOutDataLen);          /*** 输出的密钥密文字节数 ***/
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
* Function:   通用MAC/TAC计算
* Input:
*   @iKeyIdx                密钥索引
*   @pcKeyCipherByLmk       密钥密文，仅当索引值为0时该参数有效
*   @iMode                  算法标识
*   @iMacType               MAC取值方式
*   @iDeriveNum             密钥分散级数
*   @pcDeriveData           密钥分散因子
*   @iSessionKeyMode        会话密钥模式
*   @pcSessionKeyData       会话密钥因子
*   @iPaddingMode           数据填充模式
*   @pcInData               输入数据
*   @iInDataLen             输入数据长度
*   @pcIv                   IV向量
* Output:
*   @pcMac                  数据MAC
*
* Return:      成功返回0，其他表示失败
* Description: 使用IC卡交易密钥分散后的验证IC产生的过程密钥，计算交易数据的MAC或TAC，用于交易系统和发卡过程。
*              可自定义MAC算法模式、取值模式，支持多种密钥类型，自定义数据PADDING规则、计算MAC的IV数据等。
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

    /*** 该函数的MAC取值方式固定为8；***/
    rv = HSM_IC_GeneralGenerateMac(
            iMode,                          /*** MAC算法模式 ***/
            iMacType,                       /*** MAC取值方式 ***/
            "008",                          /*** 密钥类型 ***/
            iKeyIdx,                        /*** 密钥索引 ***/
            szKeyCipher,                    /*** 密钥密文 ***/
            pcDeriveData,                   /*** 分散因子 ***/
            iSessionKeyMode,                /*** 会话密钥产生模式 ***/
            pcSessionKeyData,               /*** 会话密钥因子 ***/
            iPaddingMode,                   /*** 数据填充模式 ***/
            aucInData,                      /*** 待计算MAC的数据 ***/
            iInDataLen,                     /*** 待计算MAC的数据长度 ***/
            pcIv,                           /*** 初始化向量 ***/
            pcMac,                          /*** 输出的MAC ***/
            szMacCiher);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenVerifyCvn
* Function:   产生或校验CVN
* Input:
*   @iKeyIdx            密钥索引，当密钥索引为0,时，采用密文方式
*   @pcKeyCipherByLmk   LMK下机密的密钥密文
*   @iMode              生成校验标识: 0-生成, 1-校验
*   @pcPan              帐号
*   @pcValidity         有效期
*   @pcServiceCode      服务代码
*   @pcCvn              CVN，仅当iMode = 1时该参数有效
* Output:
*   @pcCvn              CVN，仅当iMode = 0时该参数有效
*
* Return:       成功返回0，其他表示失败
* Description: 根据输入CVN数据和CVK产生CVN或校验CVN
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

    /*** 产生CVV,call CW  ***/
    if(iMode == 0)
    {
        rv = HSM_RCL_GenerateCVV(iKeyIdx, pcKeyCipherByLmk, pcPan, pcValidity, pcServiceCode, pcCvn);
        if(rv)
        {
            LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        }

    }/*** 校验时候为传入参数,校验CVV,call CY ***/
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
* Function:   产生ANSIX9.19MAC
* Input:
*   @hSessionHandle     会话句柄
*   @iKeyIdx            密钥索引
*   pcKeyCipherByLmk    密钥密文，仅当索引值为0时该参数有效
*   iInDataLen          计算MAC值的数据长度
*   pcInData            计算MAC值的数据
* Output:
*   @pcMac              MAC值
*
* Return:       成功返回0，其他表示失败
* Description: 根据输入的MAC数据采用标准的ANSIX9.19算法产生MAC
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
    char szKeyCipher[512] = {0};
    char aucData[512] = {0};

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
            3,                          /**算法模式**/
            "008",                      /**密钥类型**/
            iKeyIdx,                    /**计算mac的密钥**/
            pcKeyCipherByLmk,           /***计算mac的密钥**/
            "",                         /**密钥分散因子**/
            0,                          /*** 会话模式 ***/
            "",                         /*** 会话因子 ***/
            2,                          /****填充模式***/
            aucData,                   /*** 输入的数据 ***/
            iInDataLen,                 /*** 输入的数据长度 ***/
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
* Function:   计算银联MAC（在线分发ZAK/TAK时验证密钥的有效性）
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文，仅当索引值为0时，该参数有效
*   @iInDataLen         待计算MAC的数据长度
*   @pcInData           待计算MAC的数据
* Output:
*   @pcMac              MAC值
*
* Return:       成功返回0，其他表示失败
* Description:  根据输入的MAC数据和MAK采用银联算法产生MAC
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

    /*** 该函数的MAC取值方式固定为8 ***/
    rv =  HSM_IC_GenerateMac(
                hSessionHandle,
                1,
                "008",
                iKeyIdx,
                szKeyCipher,
                "",
                0,                       /*** 会话模式 ***/
                "",                      /*** 会话因子 ***/
                2,
                aucInData,               /*** 输入的数据 ***/
                iDataLen,                /*** 输入的数据长度 ***/
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
* Function:   计算银联ZPK-MAC（在线分发ZPK时验证密钥的有效性）
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文，仅当索引值为0时，该参数有效
*   @iInDataLen         待计算MAC的数据长度
*   @pcInData           待计算MAC的数据
* Output:
*   @pcMac              MAC值
*
* Return:       成功返回0，其他表示失败
* Description:  根据输入的MAC数据采用银联pos-mac算法产生MAC
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

    /*** 该函数的MAC取值方式固定为8 ***/
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
* Function:   PIN密文转加密
* Input:
*   @iSrcKeyIdx         源密钥索引
*   pcSrcpcKeyCipherByLmk        源密钥密文，仅当源密钥索引值为0时，该参数有效
*   iDstKeyIdx          目的密钥索引
*   pcDstpcKeyCipherByLmk        目的密钥密文，仅当目的密钥索引值为0时，该参数有效
*   pcSrcPan            源账号
*   pcDstPan            目的账号
*   iSrcPinBlkFmt       源PINBLOCK格式
*   iDstPinBlkFmt       目标PINBLOCK格式
*   pcSrcPinBlkCipher   源PINBLOCK密文
* Output:
*   @pcDstPinBlkCipher   目标PINBLOCK密文
*
* Return:       成功返回0，其他表示失败
* Description:  根据输入的账号、PIK等要素，把PIN从指定一个机构的PIK加密转换为另外一个机构的PIK加密。
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

    /*** 调用转加密指令函数 ***/
    rv = HSM_RCL_TransferCipherPin_Zpk2Zpk(
            iSrcKeyIdx,                 /*** 源密钥索引 ***/
            pcSrcpcKeyCipherByLmk,      /*** 源密钥密文 ***/
            iDstKeyIdx,                 /*** 目的密钥索引 ***/
            pcDstpcKeyCipherByLmk,      /*** 目的密钥密文 ***/
            iSrcPinBlkFmt,              /*** 源PINBLOCK格式 ***/
            iDstPinBlkFmt,              /*** 目标PINBLOCK格式 ***/
            pcSrcPan,                   /*** 源账号 ***/
            pcDstPan,                   /*** 目的账号 ***/
            pcSrcPinBlkCipher,          /*** 源PINBLOCK密文 ***/
            pcDstPinBlkCipher);         /*** 目标PINBLOCK密文 ***/
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_EncryptPIN
* Function:   加密PIN明文
* Input:
*   @iKeyIdx             密钥索引
*   @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @pcPinText           PIN
*   @iPinBlkFmt          PIN块格式
*   @pcPan               账号
* Output:
*   @pcPinBlkCipher   PIN块密文
*
* Return:       成功返回0，其他表示失败
* Description:  把按ANSIX9.8格式组织的PIN的明文用指定的PIK进行加密
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

    /*** call BA LMK加密一个明文PIN码 ***/
    rv = HSM_RCL_EncryptPin_LMK(szPinText, pcPan, szLmkPin);
    if(rv)
    {
        LOG_ERROR("HSM_RCL_EncryptPin_LMK failed, return code = [%d].", rv);
        return rv;
    }

    /*** call JG 将PIN由LMK加密转换为ZPK加密 ***/
    rv = HSM_RCL_TransferCipherPin_Lmk2Zpk(hSessionHandle, iKeyIdx, pcKeyCipherByLmk, iPinBlkFmt, pcPan, szLmkPin, pcPinBlkCipher);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_Generate_Zmk
* Function:   随机生成ZMK
* Input:
*   @hSessionHandle      会话句柄
*   @iKeyIdx             密钥索引
*   @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @cZmkScheme          ZMK算法标识
* Output:
*   @pcZmkCipherByZmk    ZMK加密的ZMK密钥密文
*   @pcZmkCipherByLmk    LMK加密的ZMK密钥密文
*   @pcZmkCv             ZMK校验值
*
* Return:       成功返回0，其他表示失败
* Description:  把按ANSIX9.8格式组织的PIN的明文用指定的PIK进行加密
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

    /*** 判断算法标识是否正确 ***/
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
* Function:   随机生成PIK
* Input:
*   @hSessionHandle      会话句柄
*   @iKeyIdx             密钥索引
*   @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @cPikScheme          PIK算法标识
* Output:
*   @pcPikCipherByZmk    ZMK加密的PIK密钥密文
*   @pcPikCipherByLmk    LMK加密的PIK密钥密文
*   @pcPikCv             PIK校验值
*
* Return:       成功返回0，其他表示失败
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

    /*** 判断算法标识是否正确 ***/
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
* Subroutine: Tass_Generate_Mak
* Function:   随机生成MAK
* Input:
*   @hSessionHandle      会话句柄
*   @iKeyIdx             密钥索引
*   @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @cMakScheme          MAK算法标识
* Output:
*   @pcMakCipherByZmk    ZMK加密的MAK密钥密文
*   @pcMakCipherByLmk    LMK加密的MAK密钥密文
*   @pcMakCv             MAK校验值
*
* Return:       成功返回0，其他表示失败
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_Generate_Mak(
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

    /*** 判断算法标识是否正确 ***/
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
* Function:   随机生成ZEK
* Input:
*   @iKeyIdx             密钥索引
*   @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @cZekScheme          ZEK算法标识
* Output:
*   @pcZekCipherByZmk    ZMK加密的ZEK密钥密文
*   @pcZekCipherByLmk    LMK加密的ZEK密钥密文
*   @pcZekCv             ZEK校验值
*
* Return:       成功返回0，其他表示失败
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

    /*** 判断算法标识是否正确 ***/
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
* Function:   导入PIK
* Input:
*   @iKeyIdx             密钥索引
*   @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @cPikScheme          PIK算法标识
*   @pcPikCipherByZmk    ZMK加密的PIK密钥密文
* Output:
*   @pcPikCipherByLmk    LMK加密的PIK密钥密文
*   @pcPikCv             PIK校验值
*
* Return:       成功返回0，其他表示失败
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

    /*** 判断算法标识是否正确 ***/
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
* Function:   导入MAK
* Input:
*   @iKeyIdx             密钥索引
*   @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @cMakScheme          MAK算法标识
*   @pcMakCipherByZmk    ZMK加密的MAK密钥密文
* Output:
*   @pcMakCipherByLmk    LMK加密的MAK密钥密文
*   @pcMakCv             MAK校验值
*
* Return:       成功返回0，其他表示失败
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

    /*** 判断算法标识是否正确 ***/
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
* Function:   通用数据加密
* Input:
*    @iKeyIdx                    密钥索引
*    @pcKeyCipherByLmk           密钥密文
*    @iEncMode                   算法模式
*    @iSessionKeyMode            会话密钥产生模式
*    @pcSessionKeyData           会话密钥因子
*    @iPaddingMode               数据填充模式
*    @pcInData                   输入的数据
*    @pcIv                       初始化向量
* Output:
*    @pcOutData                  数据密文
*
* Return:       0 for success, other is error
* Description:  通用数据加密,使用的密钥类型DEK/ZEK -- 00A
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
* Function:   通用数据解密
* Input:
*    @iKeyIdx                    密钥索引
*    @pcKeyCipherByLmk           密钥密文
*    @iEncMode                   算法模式
*    @iSessionKeyMode            会话密钥产生模式
*    @pcSessionKeyData           会话密钥因子
*    @iPaddingMode               数据填充模式
*    @pcInData                   输入的数据密文
*    @pcIv                       初始化向量
* Output:
*    @pcOutData                  数据明文
*
* Return:       0 for success, other is error
* Description:  通用数据解密，使用的密钥类型DEK/ZEK -- 00A
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

    /*** 数据转换 ***/
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
* Function:   解密PIN
* Input:
*   @iKeyIdx             密钥索引
*   @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @pcPinBlkCipher      PIN块密文
*   @iPinBlkFmt          PIN块格式
*   @pcPan               卡PAN
* Output:
*   @pcPinText           PIN明文
*
* Return:       成功返回0，其他表示失败
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

    /*** call JE 转加密 ***/
    rv = HSM_RCL_TransferCipherPin_Zpk2Lmk(hSessionHandle,iKeyIdx, pcKeyCipherByLmk, iPinBlkFmt, pcPan, pcPinBlkCipher, szLmkPin/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code1 = [%d], [%#010X].", rv, rv);
        return rv;
    }
    /*** call NG 解密PIN码 ***/
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
* Function:   计算银联MAC（带IV）
* Input:
*   @iKeyIdx             密钥索引
*   @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @pcIV                初始化向量
*   @iMacDataLen         待计算MAC的数据
*   @pcMacData           待计算MAC的数据的长度
* Output:
*   @pcMac               MAC值
*
* Return:       成功返回0，其他表示失败
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
                0,                  /*** 会话模式 ***/
                "",                 /*** 会话因子 ***/
                2,
                aucData,            /*** 输入的数据 ***/
                iDataLen,           /*** 输入的数据长度 ***/
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
* Function:   产生随机密钥
* Input:
*   @iZmkIdx             密钥索引
*   @pcZmkCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @pcKeyType           密钥类型
*   @cScheme             算法标识
* Output:
*   @pcKeyCipherByZmk    ZMK加密的密钥密文
*   @pcKeyCipherByLmk    LMK加密的密钥密文
*   @pcCkv               密钥校验值
*
* Return:       成功返回0，其他表示失败
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

    /*** 判断算法标识是否正确 ***/
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
        1,                  /*** 密钥产生模式 ***/
        pcKeyType,
        cScheme,
        iZmkIdx,
        pcZmkCipherByLmk,
        cScheme,
        'N',               /*** 密钥存储标识 ***/
        0,
        "",                /*** 密钥标签 ***/
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
* Function:   导入密钥
* Input:
*   @iZmkIdx             密钥索引
*   @pcZmkCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @pcKeyCipherByZmk    ZMK加密的密钥密文
*   @pcKeyType           密钥类型
*   @cScheme             算法标识
* Output:
*   @pcKeyCipherByLmk    LMK加密的密钥密文
*   @pcCkv               密钥校验值
*
* Return:       成功返回0，其他表示失败
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

    /*** 判断算法标识是否正确 ***/
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
* Function:   导出密钥
* Input:
*   @iZmkIdx             密钥索引
*   @pcZmkCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
*   @pcKeyType           密钥类型
*   @iKeyIdx             待导出的密钥索引
*   @pcKeyCipherByLmk    LMK加密的待导出密钥密文
*   @cScheme             算法标识
* Output:
*   @pcKeyCipherByZmk    ZMK加密的密钥密文
*   @pcCkv               密钥校验值
*
* Return:       成功返回0，其他表示失败
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

    /*** 判断算法标识是否正确 ***/
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
* Function:   数据转加密
* Input:
*   @iSrcKeyIdx             源密钥索引
*   @pcSrcKeyCipherByLmk    源密钥密文，仅当索引值为0时，该参数有效
*   @iSrcEncMode            源加密算法模式
*   @iSrcDispCnt            源密钥分散级数
*   @pcSrcDispData          源密钥分散因子
*   @iSrcSessionKeyMode     源会话密钥产生模式
*   @pcSrcSessionKeyData    源会话密钥因子
*   @iSrcPaddingMode        源数据填充模式
*   @pcSrcIv                源初始化向量
*   @iDstKeyIdx             目的密钥索引
*   @pcDstKeyCipherByLmk    目的密钥密文
*   @iDstEncMode            目的加密算法模式
*   @iDstDispCnt            目的密钥分散级数
*   @pcDstDispData          目的密钥分散因子
*   @iDstSessionKeyMode     目的会话密钥产生模式
*   @pcDstSessionKeyData    目的会话密钥因子
*   @iDstPaddingMode        目的数据填充模式
*   @pcDstIv                目的初始化向量
* Output:
*   @pcDstCipher            转加密后的数据密文
*
* Return:       成功返回0，其他表示失败
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
* Function:   脱机PIN加密
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文，仅当密钥索引值为0时该参数有效
*   @pcPan              卡PAN号
*   @pcAtc              TAC
*   @pcPlaintextPin     PIN明文
* Output:
*   @pcCipherPin        PIN密文
*
* Return:       成功返回0，其他表示失败
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

    /*** 调用底层指令接口 ***/
    rv = HSM_IC_OfflinePin_PlaintextPin(
                iKeyIdx,
                pcKeyCipherByLmk,
                pcPan,
                pcAtc,
                "41",
                pcPlaintextPin,     /*** PIN明文 ***/
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
* Function:   密钥类型转换
* Input:
*   @iSrcKeyIdx            源密钥索引
*   @pcSrcKeyCipherByLmk   源密钥密文，仅当密钥索引值为0时该参数有效
*   @pcSrcKeyType          源密钥类型
*   @pcDstKeyType          目的密钥类型
* Output:
*   @pcDstKeyCipherByLmk   目的密钥密文
*   @pcDstKeyCv            目的密钥校验值
*
* Return:       成功返回0，其他表示失败
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

    /*** 导出密钥 ***/
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
* Function:   设置设备打印格式
* Input:
*    @pcFormatStr               打印格式信息
* Output:
*    无
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
        strcpy(szFormatData, ">L>010密钥成分>025^P>L>L>010校验值：>025^T>L>L>010备注信息：>025^0>F");
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

    /*** 装载打印的数据格式 ***/
    rv = HSM_RCL_LoadFormatData(szFormatData);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_GenPrintRandkey
* Function:   随机生成密钥并打印输出
* Input:
*    @pcKeyType                 密钥类型
*    @cKeyScheme                算法标识
*    @pcMarkInfo                打印信息
* Output:
*    @pcKeyCipherByLmk          密钥密文
*    @pcKeyCv                   密钥校验值
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

    /*** 判断算法标识是否正确 ***/
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


/**
 * @brief   
 *
 * @param   hSessionHandle
 * @param   iKeyIdx         保护密钥索引
 * @param   pcKey_LMK       保护密钥密文 
 * @param   pcDisData       被导出的密钥的分散因子 
 * @param   iZmkIdx         被导出的密钥索引
 * @param   pcZmkKey_LMK    被导出的密钥密文
 * @param   pcZmk_ZMK       保护密钥加密的密钥密文 
 * @param   pcZmk_LMK       LMK加密机的密钥密文
 * @param   pcZmkCv         密钥校验值
 *
 * @return  
 */
HSMAPI int
Tass_Disper_Zmk(
    void *hSessionHandle, 
    int  iTkIdx,
    char *pcTkCipherByLmk,
    char *pcDisData,
    int  iZmkIdx,
    char *pcZmkCipherByLmk,
    char *pcSubZmkCipherByZmk/*out*/,
    char *pcSubZmkCipherByLmk/*out*/, 
    char *pcSubZmkCv/*out*/)
{
    int  rv = HAR_OK;
    int iDstKeyDeriveNumber = 0;
    char szSubZmkCipherByLmk[64 + 1] = {0};

    if(iTkIdx < 0 || iTkIdx > 2048)
    {
        LOG_ERROR("Parameter: iTkIdx = [%d] is invalid, it must be 0 - 2048.", iTkIdx);
        return HAR_PARAM_KEY_ID;
    }

    if(iTkIdx == 0)
    {
        if(pcTkCipherByLmk == NULL)
        {
            LOG_ERROR("Parameter: pcTkCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }
    }

    if(pcDisData == NULL)
    {
        LOG_ERROR("Parameter: pcDisData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcDisData) % 2 != 0)
    {
         LOG_ERROR("Parameter: pcDisData'length = [%d] is invalid.", strlen(pcDisData));
         return HAR_PARAM_DERIVE_DATA;
    }
    iDstKeyDeriveNumber = strlen(pcDisData)/32;

    if(iZmkIdx < 0 || iZmkIdx > 2048)
    {
        LOG_ERROR("Parameter: iZmkIdx = [%d] is invalid, it must be 0 - 2048.", iZmkIdx);
        return HAR_PARAM_KEY_ID;
    }

    if(iZmkIdx == 0)
    {
        if(pcZmkCipherByLmk == NULL)
        {
            LOG_ERROR("Parameter: pcZmkCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }
    }

    /*** 分散ZMK密钥，并用保护密钥保护导出 ***/
    rv = HSM_IC_ExportCipherKey(
        hSessionHandle,
        0,                  /*** 加密算法模式0-ECB ***/
        "000",              /*** 保护密钥类型 ***/
        iTkIdx,             /*** 保护密钥索引 ***/
        pcTkCipherByLmk,    /*** 保护密钥密文 ***/
        0,                  /*** 源密钥分散级数 ***/
        "",                 /*** 源密钥分散因子 ***/
        0,                  /*** 会话密钥产生模式 ***/
        "",                 /*** 会话密钥因子 ***/
        "000",              /*** 被导出的密钥类型 ***/
        iZmkIdx,            /*** 被导出密钥索引 ***/
        pcZmkCipherByLmk,   /*** 被导出密钥的密文 ***/
        iDstKeyDeriveNumber,/*** 被导出的密钥分散级数 ***/
        pcDisData,          /*** 分散因子 ***/
        "",
        pcSubZmkCipherByZmk/*out*/,  /*** 保护导出的密钥密文  ***/
        pcSubZmkCv/*out*/); /*** 密钥校验值 ***/
    if(rv)
    {
        LOG_ERROR("==========> iDstKeyDeriveNumber = [%d], len = [%d], pcDisData = [%s]\n", iDstKeyDeriveNumber, strlen(pcDisData), pcDisData);
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    //TODO 此处有待于改进，需要增加对国密算法的支持
    if(strlen(pcSubZmkCipherByZmk) >= 32)
    {
        strcpy(szSubZmkCipherByLmk, "X");
        strcat(szSubZmkCipherByLmk, pcSubZmkCipherByZmk);
    }
    else
    {
        strcat(szSubZmkCipherByLmk, pcSubZmkCipherByZmk);
    }

    /*** 将ZMK加密的密钥转为LMK加密的密钥 ***/
    rv = HSM_RCL_ImportKey_A6(
        hSessionHandle,
        "000",
        iTkIdx,                    /*** 保护密钥索引ZMK ***/
        pcTkCipherByLmk,           /*** 保护密钥密文ZMK ***/
        szSubZmkCipherByLmk,
        strlen(szSubZmkCipherByLmk) >= 32 ? 'X':'Z',  //TODO 此处要支持国密算法
        'N',
         0,
        "",
        pcSubZmkCipherByLmk,      /*** LMK加密的分散后的ZMK密钥密文 ***/
        pcSubZmkCv/*OUT*/);       /*** 分散后的ZMK密钥校验值 ***/
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


