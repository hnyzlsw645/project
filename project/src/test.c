#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsmapi.h"

int rv = 0;
//Tass_Disper_Zmk
void Test_Disper_ZMK(void *hSessionHandle){
  
    int iZmkIdx =  0;
    char pcDisData[65] = "00000000000000000000000000000000";
    char pcZmkKey_ZMK[128] = "X801617441513A2F135AB14EAAD1069DF";
    char pcZmkKey_LMK[128] = "X801617441513A2F135AB14EAAD1069DF";
    char pcZmk_Lmk[128] = {};
    char pcZmk_Zmk[128] = {};

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

}

//Generate_Zmk
void Test_Generate_Zmk(void *hSessionHandle){
     //随机生成ZMK
    int iKeyIdx = 0;
    char pcKeyCipherByLmk[64 + 1] = "X801617441513A2F135AB14EAAD1069DF";
    char cZmk_Scheme = 'X';
    char pcZmkCipherByZmk[64 + 1] = {};
    char pcZmkCipherByLmk[64 + 1] = {};
    char pcZmkCv[16 + 1] = {};

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

}
//Generate_Pik
void Test_Generate_Pik(void *hSessionHandle){

}
//Generate_Mak
void Test_Generate_Mak(void *hSessionHandle){
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
}
//Generate_Zek
void Test_Generate_Zek(void *hSessionHandle){
//产生ZEK
    char pcZekZmk[64+1] = {};
    char pcZekLmk[64+1] = {};
    char pcZekCv[16+1] = {};
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
}
//SDF_GenerateRandom
void Test_GenerateRandom(void *hSessionHandle){
    //生成随机数
    int iRandomLen = 8;
    char pcRandom[128] = {0};
    rv = Tass_GenerateRandom(phSessionHandle, iRandomLen, pcRandom/*out*/);
    if(rv)
    {
        printf("return code = [%#010X].\n", rv);
        return rv;
    }

    printf("Random = [%s]\n\n", pcRandom);
}
//Tass_GenRSAKey
void Test_GenRSAKey(void *hSessionHandle){
     char zmkDisData[33] = "00000000000000000000000000000000";
       
      char Rsa_D_ZMK[1024] = {0};
      char Rsa_P_ZMK[1024]= {0};
     char Rsa_Q_ZMK[1024] = {0};
     char Rsa_DP_ZMK[1024] = {0};
     char Rsa_DQ_ZMK[1024] = {0};
     char Rsa_QINV_ZMK[1024] = {0};
     char Rsa_N[1024] = {0};
     char Rsa_E[1024] = {0};
     char Rsa_LMK[1024] = {0};
      rv = Tass_GenRSAKey(
                phSessionHandle,
                1024,
                0,
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
    printf("rsa_d_zmk= %s + %d \n",Rsa_D_ZMK,strlen(Rsa_D_ZMK));
    printf("rsa_dQ_zmk= %s + %d \n",Rsa_DQ_ZMK,strlen(Rsa_DQ_ZMK));
    printf("rsa_p_zmk= %s + %d\n",Rsa_P_ZMK,strlen(Rsa_P_ZMK));
    printf("rsa_Q_zmk= %s + %d\n",Rsa_Q_ZMK,strlen(Rsa_Q_ZMK));
    printf("rsa_QINV_zmk = %s + %d\n",Rsa_QINV_ZMK,strlen(Rsa_QINV_ZMK));
    printf("Rsa_N = %s + %d\n",Rsa_N,strlen(Rsa_N));
    printf("rsa_E = %s + %d\n",Rsa_E,strlen(Rsa_E));
    printf("rsa_dP_zmk = %s + %d\n",Rsa_DP_ZMK,strlen(Rsa_DP_ZMK));
    printf("rsa_LMK = %s + %d\n",Rsa_LMK,strlen(Rsa_LMK));
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
}
//Tass_PubKey_Oper
void Test_PubKey_Oper(void *hSessionHandle){
    char indata[512] = "C2E686B080F67E76C749B8FB5D69BD305275BF43F70027A161AD651E66997785F24F6E1B6F71A0C2B0D03627AF0EE8AD6CA8B8949800EB28A44D4EA7ED0BCB700C2E686B080F67E76C749B8FB5D69BD305275BF43F70027A161AD651E66997785F24F6E1B6F71A0C2B0D03627AF0EE8AD6CA8B8949800EB28A44D4EA7ED0BCB7";      
       char sm2pubDerKey[1024] = "3059301306072A8648CE3D020106082A811CCF5501822D0342000422FC92E6648C45FF63D9AB23261A5B34F8A2023A0A5E4568C70DD77BB224B9E051519160A838FA154B278DC1277DFED94069A9B6950EDAD1B7C987253E385128"; 
       char outdata1[1024*2] = {0};
       rv = Tass_PubKey_Oper(
                phSessionHandle,
                0,
                indata,
                E,
                N,
                sm2pubDerKey,
                outdata1/*out*/);
       if(rv)
       {   
        printf("return code = [%#010X].\n",rv);
       }   
        printf("outdata1 = [%s]\n",outdata1);
}
//Tass_PRIVATE_Oper
void Test_PRIVATE_Oper(void *hSessionHandle){
     char Rsa_lmk[1024] = "4069A9B6950EDAD1B7C987253E385128"; 
       char indata[1024] = "042A3B6B52F62B02AEDAE2DA028BD36F90E0DDF092A4722A0E76901372EB8D9F93632340C706125CB27331B163F578783FCF6BBA8AD9D68DA90EE2D05658EF8053D5FD6F1A23B1B1D8CFBDAEF9C5B9F9E13B8602364194135F179D4EB6645AA70FFC34A3740318200CBA9CDA83C098879A06DFDCC1BA8962DD0D";      
       char outdata[2048*2] = {};
       //char Rsa_lmk[1024] = "801617441513A2F135AB14EAAD1069DF";
       char SM2_lmk[1024] = "801617441513A2F135AB14EAAD1069DF";
       rv = Tass_PRIVATE_Oper(
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
}
//Tass_Decrypt_PIN
void Test_Decrypt_PIN(void *hSessionHandle){

}
//Tass_Gen_ANSI_Mac
void Test_Gen_ANSI_Mac(void *hSessionHandle){
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
}
//Tass_EncryptTrackData
void Test_EncryptTrackData(void *hSessionHandle){
    char pcTrackText[128] = "801617441513A2F135AB14EAAD1069DF";
     int  iTrackTextLen = strlen(pcTrackText);
     char pcIv[128] = "0000000000000000";
     char pcTrackCipher[256] = {};
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

}
//Tass_DecryptTrackData
void Test_DecryptTrackData(void *hSessionHandle){
     rv = Tass_DecryptTrackData(
       phSessionHandle,
       iKeyIdx,
       pcZmkKey_LMK,
       pcTrackCipher,
       strlen(pcTrackCipher),
       1,  
       0,  
       pcIv,
       pcTrackText/*out*/);
       if(rv)
       {   
        printf("return code = [%#010X].\n",rv);
       }   
        printf("pcTrackText = [%s]\n",pcTrackText);
}


int main()
{

    int rv = 0;
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

    printf("**************************************************************************\r\n\r\n");
    for( ; ; )
    {
        printf("/-------------------------------------------------\\\n");
        printf("|                SJL-06E API test                 |\n");
        printf("|-------------------------------------------------|\n");
        printf("|       1.Test_Disper_ZMK.                        |\n");
        printf("|       2.Test_Generate_Zmk.                      |\n");
        printf("|       3.Test_Generate_Pik.                      |\n");
        printf("|       4.Test_Generate_Mak.                      |\n");
        printf("|       5.Test_Generate_Zek.                      |\n");
        printf("|       6.Test_GenerateRandom.                    |\n");
        printf("|       7.Test_GenRSAKey.                         |\n");
        printf("|       12.Test_PubKey_Oper.                      |\n");
        printf("|       13.Test_PRIVATE_Oper.                     |\n");
        printf("|       14.Test_Decrypt_PIN.                      |\n");
        printf("|       15.Test_Gen_ANSI_Mac.                     |\n");
        printf("|       16.Test_EncryptTrackData                  |\n");
        printf("|       17.Test_DecryptTrackData                  |\n");
        printf("|-------------------------------------------------|\n");
        printf("|        0.other exit.                            |\n");
        printf("\\-------------------------------------------------/");
        printf( "\nPlease Select:" );
        scanf("%d", &iItem);
        switch(iItem)
        {
            case 1:
                Test_Disper_ZMK(phSessionHandle);
                break;
            case 2:
                Test_Generate_Zmk(phSessionHandle);
                break;
            case 3:
                Test_Generate_Pik(phSessionHandle);
                break;
            case 4:
                 Test_Generate_Mak(phSessionHandle);
                 break;
            case 5:
                 vTest_Generate_Zek(phSessionHandle);
                 break;
            case 6:
                 Test_GenerateRandom(phSessionHandle);
                 break;
            case 7:
                Test_GenRSAKey(phSessionHandle);
                break;
            case 12:
                Test_PubKey_Oper(phSessionHandle);
                break;
            case 13:
                Test_PRIVATE_Oper(phSessionHandle);
                break;
            case 14:
                Test_Decrypt_PIN(phSessionHandle);
                break;
            case 15:
                Test_Gen_ANSI_Mac(phSessionHandle);
                break;
            case 16:
                Test_EncryptTrackData(phSessionHandle);
                break;
            case 17:
                Test_DecryptTrackData(phSessionHandle);
                break;
            case 0:
                SDF_CloseSession(phSession);
                SDF_CloseDevice(phDevice);
                printf( "Test Finished.\n" );
                return 0;
            default:
                printf( "Invalid Input, Press <Enter> Key to Continue...\n" );
                break;
        }

        getchar();
        getchar();
    }


    return 0;
}
