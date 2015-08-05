#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsmapi.h"

int rv = 0;
//此处变量为测试变量，如需改变在方法内部重新赋值
int iKeyIdx = 0;
char pcZmkCv[128] = {0};
char pcKeyCipherByLmk[64 + 1] = "X801617441513A2F135AB14EAAD1069DF"; 
char N[1024] = "A5C1309020BE8F9590B089422DD7A12BC29A7792EAA0D721A37257D34C28F6A164E3A811DA0456789750149896647ABBC209550E8A41EA04FDCB7573B22F5BBE6585DA4D06BC6B1780AFB461869A809BC1D3E46F9DFDB8BC5B96842B0569A969A27FE704BA455EA0AA0F598B03ADF54CCAD5B4150A19277B5D440A48B2F39D0D";
char E[12] = "010001";//指数，十六进制
char pcDisData[65] = "00000000000000000000000000000000";
char pcZmkKey_LMK[128] = "X801617441513A2F135AB14EAAD1069DF";
char pcTrackCipher[128] = {};
char pcTrackText[] = "801617441513A2F135AB14EAAD1069DF";
//int  iTrackTextLen = 0;

//Tass_Disper_Zmk
void Test_Disper_ZMK(void *phSessionHandle){
    int iZmkIdx = 0;
    char pcDisData[65] = "00000000000000000000000000000000";
    char pcZmkKey_ZMK[128] = "X48864EA979EE933748864EA979EE9337";
    char pcZmkKey_LMK[128] = "X48864EA979EE933748864EA979EE9337";
    char pcZmk_Lmk[128] = {0};
    char pcZmk_Zmk[128] = {0};
    //1A+32H
    rv = Tass_Disper_Zmk(
              phSessionHandle,
              iKeyIdx,
              pcZmkKey_LMK,
              pcDisData,
              iZmkIdx,
              pcZmkKey_ZMK,
              pcZmk_Zmk,
              pcZmk_Lmk,
              pcZmkCv);
    if(rv)
    {
         printf("return code = [%#010X].\n",rv);
    }

    printf("pcZmk_Zmk = [%s]\n",pcZmk_Zmk);
    printf("pcZmk_Lmk = [%s]\n",pcZmk_Lmk);
    printf("pcZmkCv = [%s]\n",pcZmkCv);
    //16H
    rv = Tass_Disper_Zmk(
       phSessionHandle,
       iKeyIdx,
       "35AB14EAAD1069DF",
       "",
       0,
       "35AB14EAAD1069DF",
       pcZmk_Zmk,
       pcZmk_Lmk,
       pcZmkCv);
    if(rv)
    {
         printf("return code = [%#010X].\n",rv);
    }

    printf("pcZmk_Zmk = [%s]\n",pcZmk_Zmk);
    printf("pcZmk_Lmk = [%s]\n",pcZmk_Lmk);
    printf("pcZmkCv = [%s]\n",pcZmkCv);
}

//Generate_Zmk
void Test_Generate_Zmk(void *phSessionHandle){
    //随机生成ZMK
    int iKeyIdx = 0;
    char pcKeyCipherByLmk[64 + 1] = "X801617441513A2F135AB14EAAD1069DF";
    char cZmk_Scheme = 'X';
    char pcZmkCipherByZmk[64 + 1] = {};
    char pcZmkCipherByLmk[64 + 1] = {};
    char pcZmkCv[16 + 1] = {};

    rv = Tass_Generate_Zmk(
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
void Test_Generate_Pik(void *phSessionHandle){
    char pcPikZmk[512] = {0};
    char pcPikLmk[512] = {0};
    char pcPikCv[64+1] = {0};

    rv = Tass_Generate_Pik(
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
}

//Generate_Mak
void Test_Generate_Mak(void *phSessionHandle){
    //产生MAK
    char pcMakCipherByZmk[64+1] = {0};
    char pcMakCipherByLmk[64+1] = {0};
    char pcMakCv[16+1] = {0};

    rv = Tass_Generate_Mak(
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
void Test_Generate_Zek(void *phSessionHandle){
    //产生ZEK
    char pcZekZmk[64+1] = {};
    char pcZekLmk[64+1] = {};
    char pcZekCv[16+1] = {};
    rv = Tass_Generate_Zek(
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
    }

//SDF_GenerateRandom
void Test_GenerateRandom(void *phSessionHandle){
    //生成随机数
    int iRandomLen = 8;
    char pcRandom[128] = {0};
    rv = SDF_GenerateRandom(phSessionHandle, iRandomLen, pcRandom/*out*/);
    if(rv)
    {
        printf("return code = [%#010X].\n", rv);
    }

        printf("Random = [%s]\n\n", pcRandom);
}

//Tass_GenRSAKey
void Test_GenRSAKeyorSM2Key(void *phSessionHandle){
     char zmkDisData[33]     =  "00000000000000000000000000000000";
     char Rsa_D_ZMK[1024]    =  {0};
     char Rsa_P_ZMK[1024]    =  {0};
     char Rsa_Q_ZMK[1024]    =  {0};
     char Rsa_DP_ZMK[1024]   =  {0};
     char Rsa_DQ_ZMK[1024]   =  {0};
     char Rsa_QINV_ZMK[1024] =  {0};
     char Rsa_N[1024]        =  {0};
     char Rsa_E[1024]        =  {0};
     char Rsa_LMK[1024]      =  {0};
     char SM2_D_ZMK[1024]    =  {0};
     char SM2_PUBKEY[1024]   =  {0};
     char SM2_LMK[1024]      =  {0};

     int idex = 1;
     printf("%s\n", "***********please select test item***********\n" );
     printf("*********GenRSAKey : 1 *********\n");
     printf("*********GenSm2Key : 2 *********\n");
     scanf("%d",&idex);
     switch(idex){
          case 1:
                 rv = Tass_GenRSAKey(
                    phSessionHandle,
                    2048,
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
                        return;
                 }
                        printf("rsa_d_zmk[%d]   =\n [%s] \n",  strlen(Rsa_D_ZMK),    Rsa_D_ZMK );
                        printf("rsa_dQ_zmk[%d]  =\n [%s] \n",  strlen(Rsa_DQ_ZMK),   Rsa_DQ_ZMK );
                        printf("rsa_p_zmk[%d]   =\n [%s] \n",  strlen(Rsa_P_ZMK),    Rsa_P_ZMK );
                        printf("rsa_Q_zmk[%d]   =\n [%s] \n",  strlen(Rsa_Q_ZMK),    Rsa_Q_ZMK );
                        printf("rsa_QINV_zmk[%d]=\n [%s] \n",  strlen(Rsa_QINV_ZMK), Rsa_QINV_ZMK);
                        printf("Rsa_N[%d]       =\n [%s] \n",  strlen(Rsa_N),        Rsa_N );
                        printf("rsa_E[%d]       =\n [%s] \n",  strlen(Rsa_E),        Rsa_E );
                        printf("rsa_dP_zmk[%d]  =\n [%s] \n",  strlen(Rsa_DP_ZMK),   Rsa_DP_ZMK );
                        printf("rsa_LMK[%d]     =\n [%s] \n",  strlen(Rsa_LMK),      Rsa_LMK );
                break;

          case 2:
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
                          return;
                   }                    
                          printf("SM2_D_ZMK = [%s]\n",SM2_D_ZMK);             
                          printf("SM2_PUBKEY =  [%s]\n ", SM2_PUBKEY);
                          printf("SM2_LMK    =  [%s]\n ", SM2_LMK);
                  break;

          default:
                  printf("%s\n", "select item is not exist ,please select again ! ");
             break;
     }
}
//Tass_PubKey_Oper
//用RSA或SM2公钥加密数据
void Test_PubKey_Oper(void *phSessionHandle){
      char indata[1024] = "00C1309020BE8F9590B089422DD7A12BC29A7792EAA0D721A37257D34C28F6A164E3A811DA0456789750149896647ABBC209550E8A41EA04FDCB7573B22F5BBE6585DA4D06BC6B1780AFB461869A809BC1D3E46F9DFDB8BC5B96842B0569A969A27FE704BA455EA0AA0F598B03ADF54CCAD5B4150A19277B5D440A48B2F39D0D";      
      char sm2pubDerKey[1024] = "3059301306072A8648CE3D020106082A811CCF5501822D03420004FE117AC857310B66AF3330C8D96E424E579959E0B694C8AA2549B3359323484B136B15B544B3E9DBBC4192F9DF24E5461B6C4DD18D3CB30424A9710F596295A1"; 
      char outdata1[1024*2] = {0};
      int  idex = 1;
      printf("************please select test item****************\n" );
      printf("********************* rsa加密 : 1 *********************\n" );
      printf("********************* sm2加密: 2 *********************\n" );
      scanf("%d",&idex);
      switch(idex)
       {
          case 1:
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
                      return;
                }   
                      printf("outdata1 = [%s]\n",outdata1);
            break;

          case 2:
                  rv = Tass_PubKey_Oper(
                    phSessionHandle,
                    1,
                    indata,
                    E,
                    N,
                    sm2pubDerKey,
                    outdata1/*out*/);
                if(rv)
                {   
                      printf("return code = [%#010X].\n",rv);
                      return;
                }   
                      printf("outdata1 = [%s]\n",outdata1);
            break;
          default:printf("%s\n", "you select item is not exist,please select again !");
            break;
       }
      
}

//Tass_PRIVATE_Oper
void Test_PRIVATE_Oper(void *phSessionHandle){
       char Rsa_lmk[1024*2] = "0002027075A4E52F929700D3B45A896646A9DC7CFED82D35A37F2CDDC00E37BE933055D5C00E37BE933055D5E3664B6D46ED105FE260EA55AFF5BA3EE1F8EFC9E3E87D2A2B86B1FB8661855446AE7DB4E48D7D6BB5749011FC0316BCDF553625E4A21A7003927D7F3CAE67D51733ECD018455B9DC2411024D64D1E81954D1E954A510E2F59B50E4A4A3A56676B8430FF176E9E9EB09020F5D7019C03471D2961C60BF23FF4F52B5652B6D3A3ADD2A017826D7D5B25CA3E8C7558C9FACE7F1CAFB7A82759C58D3DABB12A2FF757C5D588262ECD73FCAF9C7E293D64153C50907E48DD7F74ED3D775C458E8A2739D9388162D039D5956FE4EB57FB1A757303EDD22B40AAC2DEFB0D659A93D6DF8BD82A842F930C800E0DCA786A84C851D0C9714BD9C59E02B171CEC789A976D4ADC9B1751FCB7A03038F475041682C245316DEAE622C39A5E1E30465E24EA702A241ADBC921B32768D0A8C1A1CC2DAAFA5F64812FBB3A3B57332E195AD3E1D47A4E72299AD62EE09B8CB66B90541B4319D0C7B4088172916E57AD00EA0839F3E1E632FE8BFEF93C655BF720FDBEF24535FC2F16FB9F5C09709B6123FD955F3700AB852F90FD5B48F998EDEEAF96F8344393D117949588FF976E3DF6F4530AC1ACFD20ADF3D892B4894F6EBA498CD1D8337CF05780AFB8F54FBF7E76F630F0EAFF737B06E54A311DC529131FE1BA85C2E75709161F8A211CCBFAD0E0F803CF076682539F285563FBF90616DCBEB6C2C6CB4023B79CCD1A8958FF97DA34C41A4AAF03D0144AF906C17CA4C97C38E3EFA68D08B2BD04EBD9274927095FBAE000397F901E6B22229530361ADF6592CE5DC6CBC8D87AEFAF3AABE8FD0B254B1D295EDD81940D88272A0D5";
       char rindata[259]  = "892C1E6DC9CF720FDE55554BA5F1F2B3FA052ACE5C11EC3D544922F8C27E0D6D8C8367CBCB7F1FEEA3D2A7FF36CA01219822BE47886C60A23CBFC7EF0930ABEB020747D12B9C8FE12B3B2295E76C08248C1AEE632A7BFE9ADDDFB10E9359CD0B88999196298A23C36D10D4D3D5EF5F9295DA6067CF488A073C2FCBFDA38C654E";
       char indata[1024 * 2]  = "82C485A05C5C36BE7C58842B0B9B237F75BA966D8E1138C119546AC3372AF0B4FF29784ED9A842F365073423216EBE3B6719E6E9FB708E76B6C66850399E5ED9E1CFAEAA607DB72A5599C5A78D18DA4940E23ACE79A42AF46588F6E9E2BA9552086C0295B9BFA5B038112737DDB67B36B3EE6BDA00318D86E1A765D9C99B2AEDAC53F02C1FD48F88E98DB21147328EF16E37A71C3BF22E66621188F9AFA0B8E484D7577FAC64D7F0A95E307D1263B92CC701B1C6F10A3701DBFEEBCB048617B0283E73FF0B7ACEE628886084A329FB0E1E6FB1ACD284C343D9045A389A8DA26A";      
       char outdata[2048] = {0};
       int  idex = 1;
       //char Rsa_lmk[1024] = "801617441513A2F135AB14EAAD1069DF";
       char SM2_lmk[1024] = "2B527878AC1B1AF1253BB6FDA4940CDCF35997BD33F4F3BB0695FAA3A5C2E91DFA83657B1E22EED6";
       printf("************please select test item****************\n" );
       printf("********************* rsa : 1 *********************\n" );
       printf("********************* sm2 : 2 *********************\n" );
       scanf("%d",&idex);
       switch(idex)
       {
          case 1:
                rv = Tass_PRIVATE_Oper(
                         phSessionHandle,
                         0,
                         Rsa_lmk,
                         SM2_lmk,
                         rindata,
                         outdata/*out*/);
                if(rv)
                {   
                       printf("return code = [%#010X].\n",rv);
                       return;
                }   
                       printf("outdata = [%s]\n",outdata);
            break;

          case 2:
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
                         return;
                  }   
                         printf("outdata = [%s]\n",outdata);
            break;
          default:printf("%s\n", "you select item is not exist,please select again !");
            break;
       }
       
}

//Tass_Decrypt_PIN
void Test_Decrypt_PIN(void *phSessionHandle){
  //解密pin
    char pcPinBlk[22+1] = "4AF71A4C12311DB8";
    char pcPan[13+1] = "123456789012";
    char pcPinText[128+1] = {0};

    rv =  Tass_Decrypt_PIN(
                phSessionHandle,
                0,
                "X7B4D14A7FDEAC5147B4D14A7FDEAC514",
                pcPinBlk,
                1,
                pcPan,
                pcPinText/*out*/); 
    if(rv)
    {
          printf("return code = [%#010X].\n",rv);
          return;
    }
          printf("pcPinText = [%s]\n",pcPinText);
}

//Tass_Gen_ANSI_Mac
void Test_Gen_ANSI_Mac(void *phSessionHandle){
    //获取 MAC
    char *pcInData = "000102030405060708090A0B0C0D0E0F1011";
    char pcMac[32] = {0};

    rv = Tass_Gen_ANSI_Mac(
                phSessionHandle,
                0,  /**密钥索引**/
                "X844BDDA861742AB2844BDDA861742AB2", /**密钥密文**/
                strlen(pcInData),
                pcInData,
                pcMac/*out*/);
    if(rv)
    {
         printf("return code = [%#010X].\n", rv);
         return;
    }

         printf("pcMac = [%s]\n", pcMac);
}

//Tass_EncryptTrackData
void Test_EncryptTrackData(void *phSessionHandle){
      char pcZekKey_LMK[128] = "X65E5E955CEDECC6E65E5E955CEDECC6E";
      char pcTrackText[128] = "801617441513A2F135AB14EAAD1069DF";
      int iTrackTextLen = strlen(pcTrackText);
      char pcIv[128] = "0000000000000000";
      char pcTrackCipher[256] = {};
      rv = Tass_EncryptTrackData(
                     phSessionHandle,
                     iKeyIdx,
                     pcZekKey_LMK,
                     pcTrackText,
                     iTrackTextLen,
                     1,/**算法模式 ECB:0  CBC:1**/
                     0,/**填充模式**/
                     pcIv,/**填充数据**/
                     pcTrackCipher/*out*/);
       if(rv)
       {  
              printf("return code = [%#010X].\n",rv);
              return;
       }  
              printf("pcTrackCipher = [%s]\n",pcTrackCipher);
}

//Tass_DecryptTrackData
void Test_DecryptTrackData(void *phSessionHandle){
       char pcZekKey_LMK[128] = "X65E5E955CEDECC6E65E5E955CEDECC6E";
       char pcCipher[128] = "57673E94CE7F562177378B51EF649D6C";
       char pcIv[128] = "0000000000000000";
       rv = Tass_DecryptTrackData(
                     phSessionHandle,
                     iKeyIdx,
                     pcZekKey_LMK,
                     pcCipher,
                     strlen(pcCipher),
                     1,  /**算法模式,ECB:0  CBC:1**/
                     0,  /**填充模式**/
                     pcIv,/**填充数据**/
                     pcTrackText/*out*/);
       if(rv)
       {   
              printf("return code = [%#010X].\n",rv);
              return;
       }   
              printf("pcTrackText = [%s]\n",pcTrackText);
}

int main()
{

    int rv = 0;
    int iRandomLen = 0;
    int rt = 0;
    int iItem = 0;
    void *phDeviceHandle = NULL;
    void *phSessionHandle = NULL;
    //打开设备句柄
    rv = SDF_OpenDevice(&phDeviceHandle, "192.168.19.98", 8018);
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
        printf("|                SJJ1310 API test                 |\n");
        printf("|-------------------------------------------------|\n");
        printf("|       1.Test_Disper_ZMK.                        |\n");
        printf("|       2.Test_Generate_Zmk.                      |\n");
        printf("|       3.Test_Generate_Pik.                      |\n");
        printf("|       4.Test_Generate_Mak.                      |\n");
        printf("|       5.Test_Generate_Zek.                      |\n");
        printf("|       6.Test_GenerateRandom.                    |\n");
        printf("|       7.Test_GenRSAKeyorSM2Key                  |\n");
        printf("|       8.Test_PubKey_Oper.                       |\n");
        printf("|       9.Test_PRIVATE_Oper.                      |\n");
        printf("|       10.Test_Decrypt_PIN.                      |\n");
        printf("|       11.Test_Gen_ANSI_Mac.                     |\n");
        printf("|       12.Test_EncryptTrackData                  |\n");
        printf("|       13.Test_DecryptTrackData                  |\n");
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
                 Test_Generate_Zek(phSessionHandle);
                 break;
            case 6:
                 Test_GenerateRandom(phSessionHandle);
                 break;
            case 7:
                Test_GenRSAKeyorSM2Key(phSessionHandle);
                break;
            case 8:
                Test_PubKey_Oper(phSessionHandle);
                break;
            case 9:
                Test_PRIVATE_Oper(phSessionHandle);
                break;
            case 10:
                Test_Decrypt_PIN(phSessionHandle);
                break;
            case 11:
                Test_Gen_ANSI_Mac(phSessionHandle);
                break;
            case 12:
                Test_EncryptTrackData(phSessionHandle);
                break;
            case 13:
                Test_DecryptTrackData(phSessionHandle);
                break;
            case 0:
                SDF_CloseSession(phSessionHandle);
                SDF_CloseDevice(phDeviceHandle);
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

