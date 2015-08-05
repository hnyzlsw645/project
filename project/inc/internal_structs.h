#ifndef __INTERNAL_STRUCTS_SDF06_H__
#define __INTERNAL_STRUCTS_SDF06_H__

typedef struct Device_struct{
    unsigned int status; // 0,δ��ʼ��; 1,�ѳ�ʼ��; 2,�Ѿ��ͷ�;
    int sockfd;
    char ip[16];
    unsigned int port;
}Devicestruct;

typedef struct HashState_st{
    unsigned int m_uiMechanism;
    unsigned int datalength;
    unsigned char *pucData;
    unsigned int hashlength;
    unsigned char *pucHash;
}HashCtx;

typedef struct Session_struct{
    int status; // 0,δ��ʼ��; 1,�ѳ�ʼ��; 2,�Ѿ��ͷ�;
    Devicestruct *device;
    HashCtx hashCtx;
}Sessionstruct;

#endif  // __INTERNAL_STRUCTS_SDF06_H__

