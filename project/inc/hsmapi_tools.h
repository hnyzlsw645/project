/*----------------------------------------------------------------------|
|    hsmapi_tools.h -   The header file of hsmapi_tools.c               |
|    Version :     1.0                                                  |
|    Author:       by lcj.                                              |
|    Description:                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-21. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSMAPI_TOOLS_H__
#define __HSMAPI_TOOLS_H__

#ifdef __cplusplus
extern "C" {
#endif

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_CheckNum(char *pcInData);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_CheckHex(char *pcInData);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Toos_CheckKeyType(char *pcKeyType);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertHexBuf2Int(unsigned char *pucBuffer, int iBufferLen);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertDecBuf2Int(unsigned char *pucBuffer, int iBufferLen);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertUint2Ucbuf(unsigned int uiInData, unsigned char *pucOutBuf);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldPan(int iPinFmt, char *pcPan, unsigned char *pucDst);

/***************************************************************************
* Subroutine: Tools_AddFieldKey
* Function:    ����Կ��������Կ������ӵ����������
* Input:
*   @iKeyIdx       ��Կ����
*   @pcKeyCipher   ��Կ����
* Output:
*   @pucDst        �����
*
* Return:       �ɹ�������ӵ����ݳ��ȣ����򷵻� HSMAPIERR_PARAM_VALUE
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldKey(int iKeyIdx, char *pcKeyCipher, unsigned char *pucDst);

/***************************************************************************
* Subroutine: Tools_AddFieldSavedKey
* Function:    ��Ҫ�浽�ڲ�����Կ��������Կ��ʶ��ӵ����������
* Input:
*   @iKeyIdx       ��Կ����
*   @pcKeyLabel    ��Կ��ǩ
* Output:
*   @pucDst        �����
*
* Return:       �ɹ�������ӵ����ݳ��ȣ����򷵻� HSMAPIERR_PARAM_VALUE
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldSavedKey(int iKeyIdx, char *pcKeyLabel, unsigned char *pucDst);

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
* Return:       �ɹ�������ӵ����ݳ��ȣ����򷵻� HSMAPIERR_PARAM_DERIVE_DATA
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldDeriveData(int iMode, int iDeriveNum, char *pcDeriveData, unsigned char *pucDst);

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
*               ʧ�ܷ��� HSMAPIERR_PARAM_SESSION_KEY_DATA
*                       ��HSMAPIERR_PARAM_SESSION_KEY_MODE
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldSessionData(int iMode, char *pcSessData, unsigned char *pucDst);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_GetFieldKeyLength(char *pcKeyCipher);

/***************************************************************************
* Subroutine: Tools_GetFieldDerBufLength
* Function:   ��ȡDER��������ݳ���
* Input:
*   @pucDst          ��������
* Output:
*   ��
*
* Return:       �ɹ��򷵻���Ч���ݳ���
*               ʧ�ܷ��� HSMAPIERR_DER_DECODE
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_GetFieldDerBufLength(unsigned char *pucDst);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
void Tools_PrintBuf(char *pcTitle, unsigned char *pucBuf, int iBufLen);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
void Tools_ConvertToupper(char *pcInData);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertByte2HexStr(unsigned char *pucInBuf, int iInBufLen, char *pcOutBuf);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertHexStr2Byte(char *pcInBuf, int iInBufLen, unsigned char *pucOutBuf);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_Padding_0(char *pcInData, char *pcOutData/*out*/);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_CycleXorHexStr(int iMode, char *pcInData, char *pcOutData/*out*/);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_CycleXorByteArray(int iMode, unsigned char *pucInData, int iInDataLen, unsigned char *pucOutData/*out*/);

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
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_GenDeriveData(char *pcInData, char *pcOutData/*out*/);

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
int Tools_CheckSchemeValidity(char cScheme);

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
int Tools_CheckKeyValidity(int iKeyIdx, char *pcKeyCipherByLmk, char *pcOutData);

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
int Tools_CheckKeyValidity_1(int iKeyIdx, char *pcKeyCipherByLmk);

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
int Tools_CheckKeyValidity_2(int iKeyIdx, char *pcKeyCipherByLmk);

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
int Tools_CheckKeyValidity_3(int iKeyIdx, char *pcKeyCipherByLmk, char *pcOutData);

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
int Tools_CheckSessionKeyDataValidity(int iSessionKeyMode, char *pcSessionKeyData);

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
int Tools_CheckPaddingModeValidity(int iPaddingMode);

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
int Tools_Der(char *N, char *E, unsigned char *pubkeyDer,int *pubkeyDerLen);
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
 *************************************************************************/
int Tools_DDer(unsigned char *pubkeyDer, unsigned char *ppmodulus,
               int *modulusLen, unsigned char *pppubExp, int *pubExpLen);

#ifdef __cplusplus
}
#endif

#endif /*__HSMAPI_TOOLS_H__*/


