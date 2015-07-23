#include <stdio.h>
int main(){
 char a[] = "how are you"; 
 char *p = a;
 printf("*p=%p\n",*p);
 printf("p=%s\n",p);
 printf("p=%s\n",p);
 p++;
 *p++;
 printf("p = %s\n",p);
 printf("*p++ =%p\n ",*p++);
 printf("p++ = %s\n",p++);
 printf("p=%s\n",p);

 return 0;
}
