/*----------------------------------------------------------------------|
|    hsmapi_asym.h                                                      |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310������ӿڷǶԳ��㷨���������              |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-04. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSMAPI_ASYM_H__
#define __HSMAPI_ASYM_H__

/*** ------------------------ Asymmetric Function API ----------------------- ***/

/*
 * HSM_SM2_GenerateNewKeyPair, ����һ���µ�SM2��Կ��
 * iKeyIndex                IN          Ҫ������SM2��Կ������<=0��=9999ʱ��ʶ���洢
 * pcKeyLabel               IN          SM2��Կ��ǩ������iKeyIndex>0��!=9999ʱ��Ч;
 * pucDerPublicKey          OUT         �����ɵ�SM2��Կ��DER����
 * piDerPublicKeyLen        OUT         �����ɵ�SM2��Կ����
 * pucPrivateKey_Lmk        OUT         LMK�¼��ܵ�SM2˽Կ����
 * piPrivateKeyLen_Lmk      OUT         LMK�¼��ܵ�SM2˽Կ���ĳ���
 */
 int HSM_SM2_GenerateNewKeyPair(
    void *hSessionHandle,  int iKeyIndex, char *pcKeyLabel,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ );

/*
 * HSM_SM2_LoadKeyPair, װ��һ��SM2��Կ�Ե�������ڴ洢
 * iKeyIndex                IN        Ҫ�����SM2��Կ����
 * pcKeyLabel               IN        Ҫ�����SM2��Կ��ǩ
 * pucDerPublicKey          IN        Ҫ�����SM2��Կ��DER����
 * piDerPublicKeyLen        IN        Ҫ�����SM2��Կ����
 * pucPrivateKey_Lmk        IN        LMK�¼��ܵ�SM2˽Կ����
 * piPrivateKeyLen_Lmk      IN        LMK�¼��ܵ�SM2˽Կ���ĳ���
 */
int HSM_SM2_LoadKeyPair(
    int iKeyIndex, char *pcKeyLabel,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk );

/*
 * HSM_SM2_GetPublicKey, ��ȡһ��SM2��Կ�Ĺ�Կ
 * iKeyIndex                IN          Ҫ������Կ��SM2��Կ����
 * pucDerPublicKey          OUT         ������SM2��Կ��DER����
 * piDerPublicKeyLen        OUT         ������SM2��Կ����
 */
int HSM_SM2_GetPublicKey( int iKeyIndex,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/ );

/*
 * HSM_SM2_EncryptData, SM2��Կ��������
 * iKeyIndex                IN          SM2��Կ������<=0��=9999ʱ����2��������Ч
 * pucDerPublicKey          IN          DER�����SM2��Կ����iKeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen         IN          DER�����SM2��Կ���ȣ���iKeyIndex=9999ʱ��Ч
 * pucInput                 IN          Ҫ���ܵ��������ݣ����֧��136�ֽڵļ�������
 * iInputLength             IN          Ҫ���ܵ��������ݳ��ȣ����136
 * pucOutput                OUT         ���ܺ���������
 * piOutputLength           OUT         ���ܺ��������ݳ���
 */
int HSM_SM2_EncryptData(
	void *hSessionHandle,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ );

/*
 * HSM_SM2_DecryptData, SM2˽Կ��������
 * iKeyIndex                IN          SM2��Կ������<=0��=9999ʱ����2��������Ч
 * pucPrivateKey_Lmk        IN          LMK���ܵ�SM2˽Կ����iSm2KeyIndex=9999ʱ��Ч
 * iPrivateKeyLen_Lmk       IN          LMK���ܵ�SM2˽Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucInput                 IN          Ҫ���ܵ���������
 * iInputLength             IN          Ҫ���ܵ��������ݳ���
 * pucOutput                OUT         ���ܺ���������
 * piOutputLength           OUT         ���ܺ��������ݳ���
 */
int HSM_SM2_DecryptData(void *hSessionHandle,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ );

/*
 * HSM_SM2_GenerateSignature, SM2˽Կ�����ݽ�������ǩ��
 * iKeyIndex                IN          SM2��Կ������<=0��=9999ʱ����4��������Ч
 * pucDerPublicKey          IN          DER�����SM2��Կ����iKeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen         IN          DER�����SM2��Կ���ȣ���iKeyIndex=9999ʱ��Ч
 * pucPrivateKey_Lmk        IN          LMK���ܵ�SM2˽Կ����iSm2KeyIndex=9999ʱ��Ч
 * iPrivateKeyLen_Lmk       IN          LMK���ܵ�SM2˽Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucUserId                IN          �û���ʶ
 * iUserIdLength            IN          �û���ʶ����
 * pucInput                 IN          ��ǩ������������
 * iInputLength             IN          ��ǩ�����������ݳ���
 * pucSignature             OUT         ���������ǩ��
 * piSignatureLength        OUT         ���������ǩ������
 */
int HSM_SM2_GenerateSignature(
    int iKeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucUserId, int iUserIdLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ );

/*
 * HSM_SM2_VerifySignature, SM2��Կ��֤���ݵ�ǩ��
 * iKeyIndex                IN        SM2��Կ������<=0��=9999ʱ����2��������Ч
 * pucDerPublicKey          IN        DER�����SM2��Կ����iKeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen         IN        DER�����SM2��Կ���ȣ���iKeyIndex=9999ʱ��Ч
 * pucUserId                IN        �û���ʶ
 * iUserIdLength            IN        �û���ʶ����
 * pucInput                 IN        ����֤ǩ������������
 * iInputLength             IN        ����֤ǩ�����������ݳ���
 * pucSignature             IN        ����֤������ǩ��
 * iSignatureLength         IN        ����֤������ǩ������
 */
int HSM_SM2_VerifySignature(
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucUserId, int iUserIdLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature, int iSignatureLength );

/*
 * HSM_SM2_ExportByTK, ������Կ��KEK/MDK���ɷ�ɢ�ɲ���ɢ����������һ��SM2��Կ��
 * iMode                    IN        0�CECB, 1�CCBC
 * pcTkType                 IN        ������Կ���ͣ�"000"�CKEK;  "109"�CMDK;
 * iTkIndex                 IN        ������Կ������<=0, ʹ��pcTk_Lmk����������ʹ������ָ������Կ
 * pcTk_Lmk                 IN        LMK���ܵı�����Կ���ġ���iTkIndex<=0ʱ��Ч
 * iTkDeriveNumber          IN        ������Կ�ķ�ɢ����
 * pcTkDeriveData           IN        ������Կ�ķ�ɢ���ӣ�ÿ��32H
 * iSm2KeyIndex             IN        Ҫ��������SM2��Կ������<=0��=9999ʱ����4��������Ч
 * pucDerPublicKey          IN        DER�����SM2��Կ����iSm2KeyIndex=9999ʱ��Ч
 * iDerPublicKeyLen         IN        DER�����SM2��Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucPrivateKey_Lmk        IN        LMK���ܵ�SM2˽Կ����iSm2KeyIndex=9999ʱ��Ч
 * iPrivateKeyLen_Lmk       IN        LMK���ܵ�SM2˽Կ���ȣ���iSm2KeyIndex=9999ʱ��Ч
 * pucPrivateKey_Tk         OUT       ������Կ���ܵ�SM2˽Կ����
 * piPrivateKeyLen_Tk       OUT       ������Կ���ܵ�SM2˽Կ���ĳ���
 */
int HSM_SM2_ExportByTK(
    void *hSessionHandle,  int iMode, char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iSm2KeyIndex, 
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucPrivateKey_Tk/*out*/, int *piPrivateKeyLen_Tk/*out*/ );

/*
 * HSM_SM2_ImportByTK, ������Կ��KEK/MDK���ɷ�ɢ�ɲ���ɢ����������һ��SM2��Կ��
 * iMode                   IN        0�CECB, 1�CCBC
 * pcTkType                IN        ������Կ���ͣ�"000"�CKEK;  "109"�CMDK;
 * iTkIndex                IN        ������Կ������<=0, ʹ��pcTk_Lmk����������ʹ������ָ������Կ
 * pcTk_Lmk                IN        LMK���ܵı�����Կ���ġ���iTkIndex<=0ʱ��Ч
 * iTkDeriveNumber         IN        ������Կ�ķ�ɢ����
 * pcTkDeriveData          IN        ������Կ�ķ�ɢ���ӣ�ÿ��32H
 * iSm2KeyIndex            IN        Ҫ�������SM2��Կ������<=0��=9999ʱ��ʶ���洢
 * pucDerPublicKey         IN        Ҫ�������DER�����SM2��Կ
 * iDerPublicKeyLen        IN        Ҫ�������DER�����SM2��Կ����
 * pucPrivateKey_Tk        IN        ������Կ���ܵ�SM2˽Կ
 * iPrivateKeyLen_Tk       IN        ������Կ���ܵ�SM2˽Կ����
 * pucPrivateKey_Lmk       OUT       LMK���ܵ�SM2˽Կ����
 * piPrivateKeyLen_Lmk     OUT       LMK���ܵ�SM2˽Կ���ĳ���
 */
int HSM_SM2_ImportByTK(
    int iMode, char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iSm2KeyIndex, char *pcSm2KeyLabel,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Tk, int iPrivateKeyLen_Tk,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ );

/*
 * HSM_SM2_GeneratePublicKeyMac, ����Ȩ������ΪSM2��Կ������ԿMAC
 * pucDerPublicKey         IN        Ҫ����MAC��SM2��Կ��DER����
 * iDerPublicKeyLen        IN        Ҫ����MAC��SM2��Կ����
 * pucAuthData             IN        ��Կ�������ݣ����ܴ�';'�ַ�
 * iAuthDataLen            IN        ��Կ�������ݳ���
 * pucMac                  OUT       SM2��Կ��MACֵ
 * piMacLen                OUT       SM2��Կ��MACֵ����
 */
int HSM_SM2_GeneratePublicKeyMac(
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac/*out*/, int *piMacLen/*out*/ );

/*
 * HSM_SM2_ExportSymmetricKey, ��SM2��Կ���ܱ�������һ���Գ���Կ
 * pcKeyType               IN        ��������Կ����Կ���ͣ�"000"�CKEK; 00A�CDEK; "109"�CMDK;
 * iKeyIndex               IN        ��������Կ��������<=0, ʹ��pcKey_Lmk����������ʹ������ָ������Կ
 * pcKey_Lmk               IN        LMK���ܵı�������Կ�����ġ���iKeyIndex<=0ʱ��Ч
 * iKeyDeriveNumber        IN        ��������Կ�ķ�ɢ����
 * pcKeyDeriveData         IN        ��������Կ�ķ�ɢ���ӣ�ÿ��32H
 * iSm2KeyIndex            IN        ��Ϊ������Կ��SM2��Կ������<=0��=9999ʱ��ʶʹ��pucDerPublicKey����
 * pucDerPublicKey         IN        ��Ϊ������Կ��DER�����SM2��Կ������iSm2KeyIndex<=0��=9999ʱ��Ч
 * iDerPublicKeyLen        IN        ��Ϊ������Կ��DER�����SM2��Կ���ȣ�����iSm2KeyIndex<=0��=9999ʱ��Ч
 * pucAuthData             IN        ��Ϊ������Կ�Ĺ�Կ�������ݣ����ܴ�';'�ַ�
 * iAuthDataLen            IN        ��Ϊ������Կ�Ĺ�Կ�������ݳ���
 * pucMac                  IN        ��Ϊ������Կ��SM2��Կ��MACֵ
 * pucCipherKey            OUT       SM2��Կ���ܵı�������Կ����
 * piCipherKeyLen          OUT       SM2��Կ���ܵı�������Կ���ĳ���
 * pcKeyCv                 OUT       ��������Կ��У��ֵ
 */
int HSM_SM2_ExportSymmetricKey(
    char *pcKeyType, int iKeyIndex, char *pcKey_Lmk,
    int iKeyDeriveNumber, char *pcKeyDeriveData,
    int iSm2KeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac,
    unsigned char *pucCipherKey/*out*/, int *piCipherKeyLen/*out*/,
    char *pcKeyCv/*out*/ );

/*
 * HSM_SM2_ImportSymmetricKey, ��SM2��Կ���ܱ�������һ���Գ���Կ
 * pcKeyType               IN        ��������Կ����Կ���ͣ�"000"�CKEK; 00A�CDEK; "109"�CMDK;
 * cKeyScheme              IN        ��������Կ���㷨��ʶ��Z/X/Y/U/T/P/L/R
 * iKeyIndex               IN        ��������Կ��������<=0, ��ʶ��Կ���洢���ڲ�
 * pcKeyLabel              IN        ��������Կ�ı�ǩ����iKeyIndex>0ʱ��Ч
 * iSm2KeyIndex            IN        ��Ϊ������Կ��SM2��Կ������<=0��=9999ʱ��ʶʹ��pucPrivateKey_Lmk����
 * pucPrivateKey_Lmk       IN        ��Ϊ������Կ��SM2˽Կ���ģ�����iSm2KeyIndex<=0��=9999ʱ��Ч
 * iPrivateKeyLen_Lmk      IN        ��Ϊ������Կ��SM2˽Կ���ĳ��ȣ�����iSm2KeyIndex<=0��=9999ʱ��Ч
 * pucCipherKey            IN        SM2��Կ���ܵı�������Կ����
 * iCipherKeyLen           IN        SM2��Կ���ܵı�������Կ���ĳ���
 * pcKey_Lmk               OUT        LMK�¼��ܵı�������Կ����
 * pcKeyCv                 OUT        ��������Կ��У��ֵ
 */
int HSM_SM2_ImportSymmetricKey(
    char *pcKeyType, char cKeyScheme,
    int iKeyIndex, char *pcKeyLabel,
    int iSm2KeyIndex,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucCipherKey, int iCipherKeyLen, 
    char *pcKey_Lmk/*out*/, char *pcKeyCv/*out*/ );

/*
 * HSM_RSA_GenerateNewKeyPair, ����һ���µ�RSA��Կ��
 * iKeyIndex               IN        Ҫ������RSA��Կ������<=0��=9999ʱ��ʶ���洢
 * pcKeyLabel              IN        RSA��Կ��ǩ������iKeyIndex>0��!=9999ʱ��Ч;
 * iModulusBits            IN        RSA��Կģ����λ��
 * iPubE                   IN        RSA��Կָ��E��3��65537
 * pucDerPublicKey         OUT       �����ɵ�RSA��Կ��DER����
 * piDerPublicKeyLen       OUT       �����ɵ�RSA��Կ����
 * pucPrivateKey_Lmk       OUT       LMK�¼��ܵ�RSA˽Կ����
 * piPrivateKeyLen_Lmk     OUT       LMK�¼��ܵ�RSA˽Կ���ĳ���
 */
int HSM_RSA_GenerateNewKeyPair(void *hSessionHandle,
    int iKeyIndex, char *pcKeyLabel,
    int iModulusBits, int iPubE,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ );

/*
 * HSM_RSA_GetPublicKey, ��ȡһ��RSA��Կ�Ĺ�Կ
 * iKeyIndex               IN        Ҫ������Կ��RSA��Կ����
 * pucDerPublicKey         OUT       ������RSA��Կ��DER����
 * piDerPublicKeyLen       OUT       ������RSA��Կ����
 */
int HSM_RSA_GetPublicKey( int iKeyIndex,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/ );

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
int HSM_RSA_EncryptData(
void *hSessionHandle,	int iPaddingMode,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ );

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
int HSM_RSA_DecryptData(void *hSessionHandle,  int iPaddingMode,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ );

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
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ );

/*
 * HSM_RSA_VerifySignature, RSA��Կ��֤���ݵ�ǩ��
 * hSession                IN        NULL or OpenSession���������
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
    unsigned char *pucSignature, int iSignatureLength );

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
    unsigned char *pucMac/*out*/, int *piMacLen/*out*/ );

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
    char *pcKeyCv/*out*/ );

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
    char *pcKey_Lmk/*out*/, char *pcKeyCv/*out*/ );


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

int HSM_RSA_ExportRSAKey(
    void *hSessionHandle,
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
    unsigned char *pucPrivateKey_qInv/*OUT*/, int *piPrivateKey_qInvLen/*OUT*/);


/*
 * HSM_RSA_ExportRSAKey     ������Կ���Գƣ����ܵ���һ��RSA��Կ
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
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ );
#endif    // __HSMAPI_ASYM_H__



