/*----------------------------------------------------------------------|
|    hsmapi.h                                                           |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310��������ڽ���ͨ�ýӿ�                        |
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
 * Function:   ͨ��ָ�������ļ��ķ�ʽ��ʼ���ӿ�
 * Input:
 *    @pcConfigFilePath      �����ļ�·��
 * Output:
 *    ��
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
* Function:   ���豸���
* Input:
*    @pphDeviceHandle    �豸���
*    @pcIp               IP��ַ
*    @iPort              �˿ں�
*    @iMsgHeadLen        ��Ϣͷ����
* Output:
*    ��
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
* Function:   �ر��豸���
* Input:
*    @phDeviceHandle    �豸���
* Output:
*    ��
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
* Function:   �򿪻Ự���
* Input:
*    @phDeviceHandle      �豸���
*    @pphSessionHandle    �Ự���
* Output:
*    ��
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
* Function:   �رջỰ���
* Input:
*    @phSessionHandle    �Ự���
* Output:
*    ��
*
* Return:       0 for success, other is error
* Description:  �رջỰ���
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
int SDF_CloseSession(void *phSessionHandle);

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
Tass_GenerateRandom(void *hSessionHandle, int iRandomLen, char *pcRandom/*out*/);

/***************************************************************************
* Subroutine: Tass_Gen_ANSI_Mac
* Function:   ����ANSIX9.19MAC
* Input:
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
        void *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iInDataLen,
        char    *pcInData,
        char    *pcMac/*out*/);

/***************************************************************************
 *  Subroutine: Tass_Generate_Zmk
 *  Function:   �������ZMK
 *  Input:
 *    @hSessionHandle      �Ự���
 *    @iKeyIdx             ��Կ����
 *    @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
 *    @cZmkScheme          ZMK�㷨��ʶ
 *  Output:
 *    @pcZmkCipherByZmk    ZMK���ܵ�ZMK��Կ����
 *    @pcZmkCipherByLmk    LMK���ܵ�ZMK��Կ����
 *    @pcZmkCv             ZMKУ��ֵ
 * 
 *  Return:       �ɹ�����0��������ʾʧ��
 *  Description:  �Ѱ�ANSIX9.8��ʽ��֯��PIN��������ָ����PIK���м���
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
 *  Function:   �������PIK
 *  Input:
 *    @hSessionHandle      �Ự���
 *    @iKeyIdx             ��Կ����
 *    @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
 *    @cPikScheme          PIK�㷨��ʶ
 *  Output:
 *    @pcPikCipherByZmk    ZMK���ܵ�PIK��Կ����
 *    @pcPikCipherByLmk    LMK���ܵ�PIK��Կ����
 *    @pcPikCv             PIKУ��ֵ
 * 
 *  Return:       �ɹ�����0��������ʾʧ��
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
 *  Function:   �������MAK
 *  Input:
 *    @hSessionHandle      �Ự���
 *    @iKeyIdx             ��Կ����
 *    @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
 *    @cMakScheme          MAK�㷨��ʶ
 *  Output:
 *    @pcMakCipherByZmk    ZMK���ܵ�MAK��Կ����
 *    @pcMakCipherByLmk    LMK���ܵ�MAK��Կ����
 *    @pcMakCv             MAKУ��ֵ
 * 
 *  Return:       �ɹ�����0��������ʾʧ��
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
 *  Function:   �������ZEK
 *  Input:
 *    @hSessionHandle      �Ự���
 *    @iKeyIdx             ��Կ����
 *    @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
 *    @cZekScheme          ZEK�㷨��ʶ
 *  Output:
 *    @pcZekCipherByZmk    ZMK���ܵ�ZEK��Կ����
 *    @pcZekCipherByLmk    LMK���ܵ�ZEK��Կ����
 *    @pcZekCv             ZEKУ��ֵ
 * 
 *  Return:       �ɹ�����0��������ʾʧ��
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
 *  Function:   ����PIN
 *  Input:
 *    @iKeyIdx             ��Կ����
 *    @pcKeyCipherByLmk    ��Կ���ģ���������ֵΪ0ʱ���ò�����Ч
 *    @pcPinBlkCipher      PIN������
 *    @iPinBlkFmt          PIN���ʽ
 *    @pcPan               ��PAN
 *  Output:
 *    @pcPinText           PIN����
 * 
 *  Return:       �ɹ�����0��������ʾʧ��
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
 * Function:   ʹ��ZEK���ܴŵ����ݡ�
 * Input:
 *   @hSessionHandle  �Ự���
 *   @iKeyIdx         ��Կ����
 *   @pcKey_LMK       ��Կ����
 *   @pcTrackText     �ŵ�����
 *   @iTrackTextLen   �ŵ����ĳ���
 *   @iAlgId          ����ģʽ
 *   @pcIV            ��ʼ��IV 
 * Output:
 *   @pcTrackCipher   �ŵ�����
 *
 * Return:            �ɹ�����0��������ʾʧ��
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
     char *pcTrackText/*out*/);

 /***************************************************************************
 * Subroutine: Tass_PRIVATE_Oper
 * Function:   ˽Կ��������ӿڡ�
 * Input:
 *   @hSessionHandle  �Ự���
 *   @keytype         ��Կ����
 *   @Rsa_LMK         rsa������Կ
 *   @SM2_LMK         sm2������Կ
 *   @indata          �ⲿ��������
 * Output:
 *   @outdata         ˽Կ���ܺ�����
 *
 * Return:            �ɹ�����0��������ʾʧ��
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
 *    Function:   RSA/SM2��Կ��������ӿ�
 *    Input:
 *      @hSessionHandle  �Ự���
 *      @keytype         ʶ��RSA��SM2
 *      @indata          ����������ҪΪ��Կ�ȳ�����
 *      @RSAPubKeyE      ��Կģ
 *      @RSAPubKeyN      ָ��
 *      @SM2_PUBKEY      SM2��Կ
 *    Output:
 *      @outdata         ���ܺ������
 *   
 *    Return:            �ɹ�����0��������ʾʧ��
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
 *     Function:   ��ZMK��ɢ��������Կ��Ȼ���ñ�����Կ������Կ���ܱ�������
 *     Input:
 *       @hSessionHandle         �Ự���
 *       @pcZmkCipher_Lmk        ����ɢ��zmk
 *       @pcPublicKey            ������Կ��Der�����RSA��Կ
 *       @pcDisData              ��ɢ����
 *     Output:
 *       @pcSubKeyCipher_TK      ����Կ����
 *       @pcSubKeyCipher_Lmk     LMK���ܵ�����Կ����
 *       @pcSubKeyCv             ����ԿУ��ֵ
 *     Return:            �ɹ�����0��������ʾʧ��
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
