/*----------------------------------------------------------------------|
|    hsmapi_define.h                                                    |
|    Version :     1.0                                                  |
|    Author:       by lcj.                                              |
|    Description:  SJJ1310������ӿں궨���ļ�                          |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-21. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSM_API_DEFINE_H__
#define __HSM_API_DEFINE_H__

#define SOCKET_MAXDATALEN       6 * 1024 + 128
#define DEFAULT_INIFILE         "CfgTassHsmApi.ini"

/*** ϵͳ�����궨�� ***/
#ifdef WIN32
#define TASS_SPRINTF sprintf_s
#else
#define TASS_SPRINTF snprintf
#endif


/*** ���ݳ��� ***/
#define PANFMT_PIN_LMK          99
#define PANFMT_PIN4             4
#define PANFMT_DISPER           0
#define PANFMT_CVV              88

/*** �����㷨ģʽ ***/
#define ENCRYPT_MODE_ECB            0
#define ENCRYPT_MODE_CBC            1
#define ENCRYPT_MODE_CFB            2
#define ENCRYPT_MODE_OFB            3

/*** ����MACģʽ ***/
#define    MAC_MODE_ISO9797_1_1     1
#define    MAC_MODE_ISO9797_1_3     3

/*** ����HASH�㷨��ʶ ***/
#define    HASH_MODE_SHA1           1
#define    HASH_MODE_MD5            2
#define    HASH_MODE_ISO10118_2     3
#define    HASH_MODE_NOHASH         4
#define    HASH_MODE_SHA224         5
#define    HASH_MODE_SHA256         6
#define    HASH_MODE_SHA384         7
#define    HASH_MODE_SHA512         8
#define    HASH_MODE_SM3            20

/*** �����������ģʽ ***/
#define    PADDING_MODE_SYMM_PBOCENC        0
#define    PADDING_MODE_SYMM_PBOCMAC        1
#define    PADDING_MODE_SYMM_ANSIX9_19      2
#define    PADDING_MODE_SYMM_ANSIX9_23      3
#define    PADDING_MODE_SYMM_PKCS5          4
#define    PADDING_MODE_SYMM_NOPAD          5

#define    PADDING_MODE_ASYM_NOPAD          0
#define    PADDING_MODE_ASYM_PKCS1V1_5      1

/*** �Գ���Կ���� ***/
#define KEY_TYPE_KEKZMK          "000"
#define KEY_TYPE_ZPK             "001"
#define KEY_TYPE_PVKTPK          "002"
#define KEY_TYPE_CVK             "402"
#define KEY_TYPE_TAK             "003"
#define KEY_TYPE_ZAK             "008"
#define KEY_TYPE_BDK             "009"
#define KEY_TYPE_MDKMKAC         "109"
#define KEY_TYPE_MKSMI           "209"
#define KEY_TYPE_MKSMC           "309"
#define KEY_TYPE_MKDAK           "409"
#define KEY_TYPE_MKDN            "509"
#define KEY_TYPE_DEKZEK          "00A"
#define KEY_TYPE_TEK             "00B"
#define KEY_TYPE_HMAC            "10C"
#define KEY_TYPE_KMC             "011"

/*** �ǶԳ���Կ���� ***/
#define KEY_TYPE_RSA                 1
#define KEY_TYPE_ECC                 2
#define KEY_USAGE_SIGN               0
#define KEY_USAGE_ENC                1
#define KEY_USAGE_KEYEX              2

/*** �����㷨��ʶ ***/
#define KEY_SCHEME_DES           'Z'
#define KEY_SCHEME_DES2X         'X'
#define KEY_SCHEME_DES2U         'U'
#define KEY_SCHEME_DES3Y         'Y'
#define KEY_SCHEME_DES3T         'T'
#define KEY_SCHEME_SM1           'P'
#define KEY_SCHEME_SM4           'R'
#define KEY_SCHEME_AES           'L'

/*** �����붨�� ***/
#define HAR_OK                        0x00000000              /*** �����ɹ� ***/
#define HAR_BASE                      0x06000000              /*** ���������ֵ ***/
#define HAR_SOCK_INIT                 HAR_BASE + 0x00000001              /*** socket��ʼ��ʧ�� ***/
#define HAR_SOCK_CONNECT              HAR_BASE + 0x00000002              /*** socket����ʧ�� ***/
#define HAR_SOCK_SELECT               HAR_BASE + 0x00000003              /*** ������������ʧ�� ***/
#define HAR_SOCK_SEND                 HAR_BASE + 0x00000004              /*** ��������ʧ�� ***/
#define HAR_SOCK_RECV                 HAR_BASE + 0x00000005              /*** ��������ʧ�� ***/
#define HAR_SOCK_INVALID              HAR_BASE + 0x00000006              /*** ��Ч��socket ***/
#define HAR_SOCK_CREATE               HAR_BASE + 0x00000007              /*** ����socketʧ�� ***/
#define HAR_SOCK_DATA_LEN             HAR_BASE + 0x00000008              /*** ��Ч�ı������ݳ��� ***/

#define HAR_MSG_LENFLG                HAR_BASE + 0x00000009              /*** ��Ϣ���ȴ��� ***/
#define HAR_MSG_RSPCODE               HAR_BASE + 0x0000000A              /*** ��Ӧ������� ***/

#define HAR_MEM_LENLESS               HAR_BASE + 0x0000000B              /*** ���ݻ��������� ***/
#define HAR_MEM_MALLOC                HAR_BASE + 0x0000000C              /*** �ڴ�����ʧ�� ***/

#define HAR_CFGFILE_NOEXIST           HAR_BASE + 0x0000000D              /*** �Ҳ��������ļ� ***/
#define HAR_CFGFILE_OPEN              HAR_BASE + 0x0000000E              /*** �������ļ�ʧ�� ***/
#define HAR_CFGFILE_KEY_NOEXIST       HAR_BASE + 0x0000000F              /*** ���������� ***/
#define HAR_CFGFILE_VALUE_NOEXIST     HAR_BASE + 0x00000010              /*** ��ֵ������ ***/
#define HAR_CFGFILE_VALUE_INVALID     HAR_BASE + 0x00000011              /*** ��ֵ��Ч ***/

#define HAR_HEX_TO_BYTE               HAR_BASE + 0x00000012              /*** ʮ������ת������ʧ�� ***/
#define HAR_BYTE_TO_HEX               HAR_BASE + 0x00000013              /*** ������תʮ������ʧ�� ***/
#define HAR_DER_DECODE                HAR_BASE + 0x00000014              /*** der����ʧ�� ***/

#define HAR_PARAM_KEY_ID              HAR_BASE + 0x00000015              /*** ��Ч����Կ���� ***/
#define HAR_PARAM_KEY_TYPE            HAR_BASE + 0x00000016              /*** ��Ч����Կ���� ***/
#define HAR_PARAM_KEY_CIPHER          HAR_BASE + 0x00000017              /*** ��Ч����Կ���� ***/
#define HAR_PARAM_KEY_SCHEME          HAR_BASE + 0x00000018              /*** ��Ч���㷨��ʶ ***/
#define HAR_PARAM_KEY_HEADER          HAR_BASE + 0x00000019              /*** ��Ч����Կͷ ***/
#define HAR_PARAM_DERIVE_NUM          HAR_BASE + 0x0000001A              /*** ��Ч�ķ�ɢ���� ***/
#define HAR_PARAM_DERIVE_DATA         HAR_BASE + 0x0000001B              /*** ��Ч�ķ�ɢ���� ***/
#define HAR_PARAM_SESSION_KEY_MODE    HAR_BASE + 0x0000001C              /*** ��Ч�ĻỰ��Կ����ģʽ ***/
#define HAR_PARAM_SESSION_KEY_DATA    HAR_BASE + 0x0000001D              /*** ��Ч�ĻỰ��Կ���� ***/
#define HAR_PARAM_ENC_MODE            HAR_BASE + 0x0000001E              /*** ��Ч�ļ����㷨ģʽ ***/
#define HAR_PARAM_MAC_MODE            HAR_BASE + 0x0000001F              /*** ��Ч��MAC�㷨ģʽ ***/
#define HAR_PARAM_PRINT               HAR_BASE + 0x00000020              /*** ��ӡ��Կ����ش�ӡ��ʽʧ�� ***/
#define HAR_PARAM_ELEMENT_NUM         HAR_BASE + 0x00000021              /*** ��Կ�ɷݸ�����Ч ***/
#define HAR_PARAM_IV                  HAR_BASE + 0x00000022              /*** ��Ч��IVֵ ***/
#define HAR_PARAM_PAN                 HAR_BASE + 0x00000023              /*** ��Ч��PAN�� ***/
#define HAR_PARAM_PADDING_MODE        HAR_BASE + 0x00000024              /*** �������ģʽ���� ***/

#define HAR_PARAM_CHAR                HAR_BASE + 0x00000025
#define HAR_PARAM_UNKNOWN             HAR_BASE + 0x00000026              /*** δ֪�Ĵ��� ***/
#define HAR_PARAM_LEN                 HAR_BASE + 0x00000027              /*** ����ֵ������Ч ***/
#define HAR_PARAM_VALUE               HAR_BASE + 0x00000028              /*** ����ֵ������Ч ***/
#define HAR_PARAM_ISNULL              HAR_BASE + 0x00000029              /*** ����ֵΪNULL ***/

#define HAR_ALREADY_INITIALIZED       HAR_BASE + 0x0000002A              /*** ��ʼ���ѵ��� ***/
#define HAR_NOT_INITIALIZED           HAR_BASE + 0x0000002B              /*** δ���ó�ʼ�� ***/
#define HAR_OPENDEVICE                HAR_BASE + 0x0000002C              /*** ���豸ʧ�� ***/
#define HAR_OPENSESSION               HAR_BASE + 0x0000002D              /*** �����Ựʧ�� ***/
#define HAR_DEVICEHANDLE_INVALID      HAR_BASE + 0x0000002E              /*** �豸�����Ч ***/
#define HAR_SESSIONHANDLE_INVALID     HAR_BASE + 0x0000002F              /*** �Ự�����Ч ***/
#define HAR_SOCK_TIMEOUT     					HAR_BASE + 0x00000030              /*** socketͨѶ��ʱ ***/


#endif    /***  __HSM_API_DEFINE_H__ ***/

