/*----------------------------------------------------------------------|
|    hsmapi.h                                                           |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机金融交易通用接口                        |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-05. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSM_API_H__
#define __HSM_API_H__

#ifdef WIN32
#define HSMAPI _declspec (dllexport)
#else
#define HSMAPI
#endif

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************
 * Subroutine: Tass_HsmApiInit
 * Function:   通过指定配置文件的方式初始化接口
 * Input:
 *    @pcConfigFilePath      配置文件路径
 * Output:
 *    无
 *
 * Return:       0 for success, other is error
 * Description:
 *
 * Author:       Luo Cangjian
 * Date:         2015.05.29
 * ModifyRecord:
 ***************************************************************************/
int Tass_HsmApiInit(char *pcConfigFilePath);

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
int SDF_OpenDevice(void **pphDeviceHandle, char *pcIp, int iPort, int iMsgHeadLen);

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
int SDF_CloseDevice(void *phDeviceHandle);

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
int SDF_OpenSession(void *phDeviceHandle, void **pphSessionHandle);

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
int SDF_CloseSession(void *phSessionHandle);

/***************************************************************************
* Subroutine: Tass_GenerateRandom 
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
Tass_GenerateRandom(void *hSessionHandle, int iRandomLen, char *pcRandom/*out*/);

/***************************************************************************
* Subroutine: Tass_Gen_ANSI_Mac
* Function:   产生ANSIX9.19MAC
* Input:
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
        void *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iInDataLen,
        char    *pcInData,
        char    *pcMac/*out*/);

/***************************************************************************
 *  Subroutine: Tass_Generate_Zmk
 *  Function:   随机生成ZMK
 *  Input:
 *    @hSessionHandle      会话句柄
 *    @iKeyIdx             密钥索引
 *    @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
 *    @cZmkScheme          ZMK算法标识
 *  Output:
 *    @pcZmkCipherByZmk    ZMK加密的ZMK密钥密文
 *    @pcZmkCipherByLmk    LMK加密的ZMK密钥密文
 *    @pcZmkCv             ZMK校验值
 * 
 *  Return:       成功返回0，其他表示失败
 *  Description:  把按ANSIX9.8格式组织的PIN的明文用指定的PIK进行加密
 *  Author:       Luo Cangjian
 *  Date:         2015.06.05
 *  ModifyRecord:
 * *************************************************************************/
HSMAPI int
Tass_Generate_Zmk(
        void *hSessionHandle,
        int iKeyIdx,
        char *pcKeyCipherByLmk,
        char cZmkScheme,
        char *pcZmkCipherByZmk,
        char *pcZmkCipherByLmk,
        char *pcZmkCv);
/***************************************************************************
 *  Subroutine: Tass_Generate_Pik
 *  Function:   随机生成PIK
 *  Input:
 *    @hSessionHandle      会话句柄
 *    @iKeyIdx             密钥索引
 *    @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
 *    @cPikScheme          PIK算法标识
 *  Output:
 *    @pcPikCipherByZmk    ZMK加密的PIK密钥密文
 *    @pcPikCipherByLmk    LMK加密的PIK密钥密文
 *    @pcPikCv             PIK校验值
 * 
 *  Return:       成功返回0，其他表示失败
 *  Description:
 *  Author:       Luo Cangjian
 *  Date:         2015.06.05
 *  ModifyRecord:
 * *************************************************************************/
HSMAPI int
Tass_Generate_Pik(
        void *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cPikScheme,
        char    *pcPikCipherByZmk/*OUT*/,
        char    *pcPikCipherByLmk/*OUT*/,
        char    *pcPikCv/*OUT*/ );

/***************************************************************************
 *  Subroutine: Tass_Generate_Mak
 *  Function:   随机生成MAK
 *  Input:
 *    @hSessionHandle      会话句柄
 *    @iKeyIdx             密钥索引
 *    @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
 *    @cMakScheme          MAK算法标识
 *  Output:
 *    @pcMakCipherByZmk    ZMK加密的MAK密钥密文
 *    @pcMakCipherByLmk    LMK加密的MAK密钥密文
 *    @pcMakCv             MAK校验值
 * 
 *  Return:       成功返回0，其他表示失败
 *  Description:
 *  Author:       Luo Cangjian
 *  Date:         2015.06.05
 *  ModifyRecord:
 * **************************************************************************/
HSMAPI int
Tass_Generate_Mak(
        void *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cMakScheme,
        char    *pcMakCipherByZmk/*out*/,
        char    *pcMakCipherByLmk/*out*/,
        char    *pcMakCv/*out*/);

/***************************************************************************
 *  Subroutine: Tass_Generate_Zek
 *  Function:   随机生成ZEK
 *  Input:
 *    @hSessionHandle      会话句柄
 *    @iKeyIdx             密钥索引
 *    @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
 *    @cZekScheme          ZEK算法标识
 *  Output:
 *    @pcZekCipherByZmk    ZMK加密的ZEK密钥密文
 *    @pcZekCipherByLmk    LMK加密的ZEK密钥密文
 *    @pcZekCv             ZEK校验值
 * 
 *  Return:       成功返回0，其他表示失败
 *  Description:
 *  Author:       Luo Cangjian
 *  Date:         2015.06.05
 *  ModifyRecord:
 *  *************************************************************************/
HSMAPI int
Tass_Generate_Zek(
        void *hSessionHandle,
        int  iKeyIdx,
        char *pcKeyCipherByLmk,
        char cZekScheme,
        char *pcZekCipherByZmk/*out*/,
        char *pcZekCipherByLmk/*out*/,
        char *pcZekCv/*out*/);
/***************************************************************************
 *  Subroutine: Tass_Decrypt_PIN
 *  Function:   解密PIN
 *  Input:
 *    @iKeyIdx             密钥索引
 *    @pcKeyCipherByLmk    密钥密文，仅当索引值为0时，该参数有效
 *    @pcPinBlkCipher      PIN块密文
 *    @iPinBlkFmt          PIN块格式
 *    @pcPan               卡PAN
 *  Output:
 *    @pcPinText           PIN明文
 * 
 *  Return:       成功返回0，其他表示失败
 *  Description:
 *  Author:       Luo Cangjian
 *  Date:         2015.06.05
 *  ModifyRecord:
 * *************************************************************************/
HSMAPI int
Tass_Decrypt_PIN(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPinBlkCipher,
        int     iPinBlkFmt,
        char    *pcPan,
        char    *pcPinText/*out*/);

/***************************************************************************
 * * Subroutine: Tass_Disper_Zmk
 * * Function:   由一个ZMK分散生成另外一个子密钥，并通过ZMK密钥加密保护导出
 * * Input:
 * *   @hSessionHandle  会话句柄
 * *   @iKeyIdx         密钥索引
 * *   @pcKey_LMK       密钥密文
 * *   @pcDisData       分散参数
 * * Output:
 * *   @pcZmk_LMK       ZMK密文
 * *   @pcZmk_ZMK       ZMK保护分散的子密钥导出
 * *   @pcZmkCv         密钥校验值
 * *
 * * Return:            成功返回0，其他表示失败
 * * Description:
 * * Author:       Luo Cangjian
 * * Date:         2015.06.05
 * * ModifyRecord:
 * * *************************************************************************/
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
    char *pcZmkCv/*out*/);

 /***************************************************************************
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
     char *pcTrackCipher/*out*/);

/***************************************************************************
 * * Subroutine: Tass_DecryptTrackData
 * * Function:   使用ZEK解密磁道数据。
 * * Input:
 * *   @hSessionHandle  会话句柄
 * *   @iKeyIdx         密钥索引
 * *   @pcKey_LMK       密钥密文
 * *   @pcTrackText     磁道密文
 * *   @iTrackTextLen   磁道密文长度
 * *   @iAlgId          解密模式
 * *   @pcIV            初始化IV 
 * * Output:
 * *   @pcTrackCipher   磁道明文
 * *
 * * Return:            成功返回0，其他表示失败
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
     char *pcTrackText/*out*/);

 /***************************************************************************
 * Subroutine: Tass_PRIVATE_Oper
 * Function:   私钥解密运算接口。
 * Input:
 *   @hSessionHandle  会话句柄
 *   @keytype         密钥类型
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
     int keytype,
     char *Rsa_LMK,
     char *SM2_LMK,
     char *indata,
     char *outdata/*out*/);

/***************************************************************************
 *    Subroutine: Tass_PubKey_Oper
 *    Function:   RSA/SM2公钥加密运算接口
 *    Input:
 *      @hSessionHandle  会话句柄
 *      @keytype         识别RSA或SM2
 *      @indata          输入数据需要为公钥等长数据
 *      @RSAPubKeyE      公钥模
 *      @RSAPubKeyN      指数
 *      @SM2_PUBKEY      SM2公钥
 *    Output:
 *      @outdata         加密后的数据
 *   
 *    Return:            成功返回0，其他表示失败
 *    Description:
 *    Author:       Luo Cangjian
 *    Date:         2015.06.05
 *    ModifyRecord:
 **************************************************************************/
HSMAPI int 
Tass_PubKey_Oper(
     void *hSessionHandle,
     int keytype,
     char *indata,
     char *RSAPubKeyE,
     char *RSAPubKeyN,
     char *SM2_PUBKEY,
     char *outdata/*out*/);

/***************************************************************************
 * Subroutine: Tass_GenRSAKey
 * Function:   随机生成RSA密钥对，并使用ZMK加密导出
 * Input:
 *   @hSessionHandle  会话句柄
 *   @RsaLen          Rsa密钥长度
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
     char Rsa_DP_ZMK/*out*/,
     char *Rsa_DQ_ZMK/*out*/,
     char *Rsa_QINV_ZMK/*out*/,
     char *Rsa_N/*out*/,
     char *Rsa_E/*out*/,
     char *Rsa_LMK/*out*/);

/***************************************************************************
 *     Subroutine: Tass_DeriveKeyExportedByRsa
 *     Function:   将ZMK分散产生子密钥，然后用保护密钥将子密钥加密保护导出
 *     Input:
 *       @hSessionHandle         会话句柄
 *       @pcZmkCipher_Lmk        待分散的zmk
 *       @pcPublicKey            保护公钥，Der编码的RSA公钥
 *       @pcDisData              分散因子
 *     Output:
 *       @pcSubKeyCipher_TK      子密钥密文
 *       @pcSubKeyCipher_Lmk     LMK加密的子密钥密文
 *       @pcSubKeyCv             子密钥校验值
 *     Return:            成功返回0，其他表示失败
 *     Description:
 *     Author:       Luo Cangjian
 *     Date:         2015.06.05
 *     ModifyRecord:
 **************************************************************************/
HSMAPI int 
Tass_DeriveKeyExportedByRsa(
     void *hSessionHandle,
     char *pcZmkCipher_Lmk,
     char *pcPublicKey,
     char *pcDisData,
     char *pcSubKeyCipher_TK/*out*/,
     char *pcSubKeyCipher_Lmk/*out*/,
     char *pcSubKeyCv/*out*/);

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
 *     @SM2_D_ZMK       
 *     @SM2_PUBKEY
 *     @SM2_LMK
 *   Return:            成功返回0，其他表示失败
 *   Description:
 *   Author:       Luo Cangjian
 *   Date:         2015.06.05
 *   ModifyRecord:
 *****************************************************************************/
HSMAPI int 
Tass_GenSm2Key(
     void *hSessionHandle,
     int zmkIndex,
     char *zmk_Lmk,
     char *zmk_disData,
     int mode,
     char *SM2_D_ZMK/*out*/,
     char *SM2_PUBKEY/*out*/,
     char *SM2_LMK/*out*/);

#ifdef __cplusplus
}
#endif

#endif    /*** __HSM_API_H__ ***/
