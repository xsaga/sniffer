#include <stdio.h>
#include <string.h>

void hexdump(const unsigned char *buffer, int len, int offset);

void hexdump(const unsigned char *buffer, int len, int offset){
    unsigned char tmp[16];
    int l, i;

    while(len > 0){
        printf("0x%04x: ", offset); 

        l = (len >= 16)? 16 : len;

        for(i = 0; i<l; i++){
            tmp[i] = *(buffer++);
        }
        
        len -= l;
         
        for(i = 0; i<l; i++){
            printf("%02x ", tmp[i]);
        }

        for(i = l; i<16; i++){
            printf("   ");
        }

        printf("| ");
        for(i = 0; i<l; i++){
            if(tmp[i] < ' ' || tmp[i] > '~'){
                printf(".");
            }else{
                printf("%c", tmp[i]);
            }
        }
        printf(" |\n");
        offset += l;
    }
    printf("0x%04x: \n", offset); 
}
