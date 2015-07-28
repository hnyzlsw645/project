#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsmapi.h"
#include "hsmapi_init.h"

int main(void)
{
    int rv = 0;
    char pcRandom[128] = {0};
    int iRandomLen = 0;

    void *phDeviceHandle = NULL;
    void *phSessionHandle = NULL;

    //打开设备句柄
    rv = SDF_OpenDevice(&phDeviceHandle, "124.127.49.180", 8018, 8);
    if(rv)
    {
        printf("Open the device failed. return code = [%#010X].", rv);
        return rv;
    }
    else
    {
        printf("Open the device success.\n");
    }

    //打开会话句柄
    rv = SDF_OpenSession(phDeviceHandle, &phSessionHandle);
    if(rv)
    {
        printf("Open session failed, return code = [%#010X]\n", rv);
        SDF_CloseDevice(phDeviceHandle);
        return rv;
    }
    else
    {
        printf("Open the session success.\n");
    }
#if 0
    // printf("please input random len:\n");
    // scanf("%d", &iRandomLen);
    iRandomLen = 8; 
    printf("\n================================生成随机数==========================================================\n");
    //生成随机数
    rv = Tass_GenerateRandom(phSessionHandle, iRandomLen, pcRandom/*out*/);
    if(rv)
    {
        printf("return code = [%#010X].\n", rv);
        return rv;
    }

    printf("Random = [%s]\n\n", pcRandom);
    printf("\n================================获取MAC==========================================================\n");
    //获取 MAC
    char *pcInData = "abcdefABCDEF12341234";
    char pcMac[32] = {0};

    rv = Tass_GenANSIMac(
                phSessionHandle,
                32,
                "",
                strlen(pcInData),
                pcInData,
                pcMac/*out*/);
    if(rv)
    {
        printf("return code = [%#010X].\n", rv);
    }

    printf("mac = [%s]\n", pcMac);

    printf("\n================================随机生成zmk==========================================================\n");
#endif
    //随机生成ZMK
    int iKeyIdx = 0;
    char pcKeyCipherByLmk[64 + 1] = "X801617441513A2F135AB14EAAD1069DF";
    char cZmk_Scheme = 'X';
    char pcZmkCipherByZmk[64 + 1] = {};
    char pcZmkCipherByLmk[64 + 1] = {};
    char pcZmkCv[16 + 1] = {};
#if 0
    rv = Tass_GenerateZmk(
        phSessionHandle,
        iKeyIdx,
        pcKeyCipherByLmk,
        cZmk_Scheme,
        pcZmkCipherByZmk,
        pcZmkCipherByLmk,
        pcZmkCv);
    if(rv)
    {
      printf("return code = [%#010X].\n",rv);   
    }
      printf("pcZmk_Zmk = [%s]\n",pcZmkCipherByZmk);
      printf("pcZmkCipherByLmk = [%s]\n",pcZmkCipherByLmk);
      printf("pcZmkCv = [%s]\n",pcZmkCv);  


     printf("\n==============================================产生PIK======================================================\n");
    //产生PIK
    char pcPikZmk[64+1] = {0};
    char pcPikLmk[64+1] = {0};
    char pcPikCv[64+1] = {0};
    rv = Tass_GeneratePik(
        phSessionHandle,
        iKeyIdx,
        pcKeyCipherByLmk,
        'X',
        pcPikZmk/*OUT*/,
        pcPikLmk/*OUT*/,
        pcPikCv/*OUT*/ );
    if(rv)
    {
     printf("return code = [%#010X].\n",rv);
    }
     printf("pcPikZmk = [%s]\n",pcPikZmk);
     printf("pcPikLmk = [%s]\n",pcPikLmk);
     printf("pcPikCv = [%s]\n",pcPikCv);
    printf("\n================================产生MAK==========================================================\n");
    //产生MAK
    char pcMakCipherByZmk[64+1] = {};
    char pcMakCipherByLmk[64+1] = {};
    char pcMakCv[16+1] = {};
    rv = Tass_GenerateMak(
        phSessionHandle,
        iKeyIdx,
        pcKeyCipherByLmk,
        'X',
        pcMakCipherByZmk/*out*/,
        pcMakCipherByLmk/*out*/,
        pcMakCv/*out*/);
        if(rv)
        {
         printf("return code = [%#010X].\n",rv);
        }
         printf("pcMakCipherByZmk = [%s]\n",pcMakCipherByZmk);
         printf("pcMakCipherByLmk = [%s]\n",pcMakCipherByLmk);
         printf("pcMakCv = [%s]\n",pcMakCv);

    printf("\n===============================产生ZEK==============================================\n");
#endif
    //产生ZEK
    char pcZekZmk[64+1] = {};
    char pcZekLmk[64+1] = {};
    char pcZekCv[16+1] = {};
#if 0
    rv = Tass_GenerateZek(
        phSessionHandle,
        iKeyIdx,
        pcKeyCipherByLmk,
        'X',
        pcZekZmk/*out*/,
        pcZekLmk/*out*/,
        pcZekCv/*out*/);
    if(rv)
    {
      printf("return code = [%#010X].\n",rv);
    }
      printf("pcZekZmk = [%s]\n",pcZekZmk);
      printf("pkZekLmk = [%s]\n",pcZekLmk);
      printf("pkZekCv = [%s]\n",pcZekCv);

#endif
   printf("\n================================解密pin==========================================================\n"); 
   //解密pin
    char pcPinBlk[22+1] = "xa10221134657568426499";
    char pcPan[13+1] = "123456789012";
    char pcPinText[128+1] = {0};
    rv =  Tass_Decrypt_PIN(
        phSessionHandle,
        iKeyIdx,
        pcKeyCipherByLmk,
        pcPinBlk,
        1,
        pcPan,
        pcPinText/*out*/); 
    if(rv)
    {
      printf("return code = [%#010X].\n",rv);
    }
      printf("pcPinText = [%s]\n",pcZekZmk);
 //   printf("\n=====================ZMK密钥分散生成ZMK密钥，并用ZMK加密保护导出=====================================\n");

    
    int iZmkIdx = 0;
    char pcDisData[65] = "00000000000000000000000000000000";
    char pcZmkKey_ZMK[128] = "X801617441513A2F135AB14EAAD1069DF";
    char pcZmkKey_LMK[128] = "X801617441513A2F135AB14EAAD1069DF";
    char pcZmk_Lmk[128] = {};
    char pcZmk_Zmk[128] = {};
#if 0    
rv = Tass_Disper_Zmk(
      phSessionHandle,
      iKeyIdx,
      pcZmkKey_LMK,
      pcDisData,
      iZmkIdx,
      pcZmkKey_ZMK,
      pcZmk_Zmk,
      pcZmk_Lmk,
      pcZmkCv 
      ); 
rv = Tass_Disper_Zmk(
       phSessionHandle,
       iKeyIdx,
       "35AB14EAAD1069DF",
       "",
       0,
       "35AB14EAAD1069DF",
       pcZmk_Zmk,
       pcZmk_Lmk,
       pcZmkCv
       );
 
 if(rv)
   {
     printf("return code = [%#010X].\n",rv);
   }
     printf("pcZmk_Zmk = [%s]\n",pcZmk_Zmk);
     printf("pcZmk_Lmk = [%s]\n",pcZmk_Lmk);
     printf("pcZmkCv = [%s]\n",pcZmkCv);
#endif
#if 0
   printf("\n================================磁道加密==========================================================\n");
     char pcTrackText[] = "801617441513A2F135AB14EAAD1069DF";
     int  iTrackTextLen = strlen(pcTrackText);
     char pcIv[] = "0000000000000000";
     char pcTrackCipher[128] = {};
     rv = Tass_EncryptTrackData(
       phSessionHandle,
       iKeyIdx,
       pcZmkKey_LMK,
       pcTrackText,
       iTrackTextLen,
       1,
       0,
       pcIv,
       pcTrackCipher/*out*/);
       if(rv)
       {  
        printf("return code = [%#010X].\n",rv);
       }  
        printf("pcTrackCipher = [%s]\n",pcTrackCipher);

    printf("\n================================磁道解密==========================================================\n");
     rv = Tass_EncryptTrackData(
       phSessionHandle,
       iKeyIdx,
       pcZmkKey_LMK,
       pcTrackCipher,
       iTrackTextLen,
       1,  
       0,  
       pcIv,
       pcTrackText/*out*/);
       if(rv)
       {   
        printf("return code = [%#010X].\n",rv);
       }   
        printf("pcTrackText = [%s]\n",pcTrackText);

     printf("\n================================RSA/SM2私钥解密==========================================================\n");
             
       char indata[2048*2] = "B6A247544CC482A8497973D418D5C17DECC8B9DC3E723498FE8C7";
       char outdata[2048*2] = {};
       char Rsa_lmk[1024] = "801617441513A2F135AB14EAAD1069DF";
       char SM2_lmk[1024] = "801617441513A2F135AB14EAAD1069DF";
       rv = Tass_DecryptOper(
           phSessionHandle,
           1,
           Rsa_lmk,
           SM2_lmk,
           indata,
           outdata/*out*/);
       if(rv)
       {   
        printf("return code = [%#010X].\n",rv);
       }   
        printf("outdata = [%s]\n",outdata);
#endif

    printf("\n================================测试der编码==========================================================\n");
    //对RSA公钥的模、指数序列做DER编码
    char N[512] = "00C2E686B080F67E76C749B8FB5D69BD305275BF43F70027A161AD651E66997785F24F6E1B6F71A0C2B0D03627AF0EE8AD6CA8B8949800EB28A44D4EA7ED0BCB739ECF4EB7234046BAEBBF8E5576EBD4E592D8D6AB592569D7E274E61A6277518134B35D161C18266126D4520F9D45DF85FAE97FBE78AC0F48C348BA06C8C1FBD3";
    char E[12] = "010001";//指数，十六进制
    unsigned char pubkeyDer[512 + 32] = {0};
    int pubkeyDerLen = 512 + 32;
    rv = Tools_Der(
      N,
      E,
      pubkeyDer,
      &pubkeyDerLen
     );
   Tools_PrintBuf("public key\n", pubkeyDer, pubkeyDerLen);
   Tools_PrintBuf("public key\n", pubkeyDer, pubkeyDerLen+8);
   Tools_PrintBuf("public key\n", pubkeyDer);
   Tools_PrintBuf("public keyLen\n","--",pubkeyDerLen);   
#if 0
   printf("\n================================RSA/SM2公钥加密==========================================================\n");
             

       char outdata1[1024*2] = {0};
       rv = Tass_PubKeyOper(
                phSessionHandle,
                0,
                indata,
                E,
                N,
                "",
                outdata1/*out*/);
       if(rv)
       {   
        printf("return code = [%#010X].\n",rv);
       }   
        printf("outdata1 = [%s]\n",outdata1);
#endif

   printf("\n================================随机生成RSA密钥==========================================================\n");
       char zmkDisData[33] = "00000000000000000000000000000000";
       
      char Rsa_D_ZMK[1024] = {0};
      char Rsa_P_ZMK[1024]= {0};
     char Rsa_Q_ZMK[1024] = {0};
     char *Rsa_DP_ZMK = '0';
     char Rsa_DQ_ZMK[1024] = {0};
     char Rsa_QINV_ZMK[1024] = {0};
     char Rsa_N[1024] = {0};
     char Rsa_E[1024] = {0};
     char Rsa_LMK[1024] = {0};
      rv = Tass_GenRSAKey(
                phSessionHandle,
                1024,
                9999,
                pcZmkKey_LMK,
                zmkDisData ,
                0 ,
     Rsa_D_ZMK/*out*/,
     Rsa_P_ZMK/*out*/,
     Rsa_Q_ZMK/*out*/,
     Rsa_DP_ZMK/*out*/,
     Rsa_DQ_ZMK/*out*/,
     Rsa_QINV_ZMK/*out*/,
     Rsa_N/*out*/,
     Rsa_E/*out*/,
     Rsa_LMK/*out*/); 
       if(rv)
       {
        printf("return code = [%#010X].\n",rv);
       }
        printf("rsadzmk = [%x]\n",Rsa_DQ_ZMK);
        printf("rsapzmk = [%x]\n",Rsa_P_ZMK);
        printf("rsaqzmk = [%x]\n",Rsa_Q_ZMK);
        printf("rsadpzmk = [%x]\n",Rsa_DP_ZMK);
        printf("rsadqzmk = [%x]\n",Rsa_DQ_ZMK);
        printf("rsaqinvzmk = [%x]\n",Rsa_QINV_ZMK);
        printf("rsan = [%x]\n",Rsa_N);
        printf("rsae = [%x]\n",Rsa_E);
        printf("rsalmk = [%x]\n",Rsa_LMK);

   printf("\n================================随机生成SM2密钥==========================================================\n");

     char SM2_D_ZMK[1024] = {0};
     char SM2_PUBKEY[1024] = {0};
     char SM2_LMK[1024] = {0};
     rv = Tass_GenSm2Key(
     phSessionHandle,
     9999,
     pcZmkKey_LMK,
     zmkDisData,
     0,
     SM2_D_ZMK/*out*/,
     SM2_PUBKEY/*out*/,
     SM2_LMK/*out*/);  
     if(rv)
       {
        printf("return code = [%#010X].\n",rv);
       }
        printf("SM2_D_ZMK = [%s]\n",SM2_D_ZMK);
        printf("SM2_PUBKEY = [%s]\n",SM2_PUBKEY);
        printf("SM2_LMK = [%s]\n",SM2_LMK);
#if 0
printf("==========================解密DER=================================\n");
        char derdata[1024] = "30818902818100C2E686B080F67E76C749B8FB5D69BD305275BF43F70027A161AD651E66997785F24F6E1B6F71A0C2B0D03627AF0EE8AD6CA8B8949800EB28A44D4EA7ED0BCB739ECF4EB7234046BAEBBF8E5576EBD4E592D8D6AB592569D7E274E61A6277518134B35D161C18266126D4520F9D45DF85FAE97FBE78AC0F48C348BA06C8C1FBD30203010001";
     unsigned char derdata1[1024] = {0};     
     int len = Tools_ConvertHexStr2Byte(derdata,strlen(derdata),derdata1);
     unsigned char ppmodulus[1024] = {0};
     unsigned char pppubExp[1024] = {0};
     int modulusLen = 0;
     int pubExpLen = 0; 

	unsigned char *pE = NULL;
	unsigned char *pM = NULL;
 
     rv = DDer_Pubkey_Pkcs1(
               derdata1, len,
               &pM,&modulusLen,
               &pE,&pubExpLen
              );
    
   rv = Tools_DDer(
          derdata,
          ppmodulus,&modulusLen,
          pppubExp,&pubExpLen
             );
     if(rv)
     {
	printf("return code = [%#010X].", rv);
	return 0;
     }
printf("ppmodulus = [%s]\n",ppmodulus);
printf("pppubExp = [%s]\n",pppubExp);
 
        Tools_PrintBuf("ppmodulus_tool",ppmodulus,modulusLen);
        Tools_PrintBuf("pppubExp_tool",pppubExp,modulusLen);
	Tools_PrintBuf("ppmodulus", pM, modulusLen);
	Tools_PrintBuf("pppubExp", pE, pubExpLen);
#endif
//关闭会话句柄
    SDF_CloseSession(phSessionHandle);

    //关闭设备句柄
    SDF_CloseDevice(phDeviceHandle);

    return 0;
}

