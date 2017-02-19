#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/stat.h>
#include<errno.h>

void genKey(int, char*);
int encryptDataWithKey(char*, char*, char*);
int decryptDataWithKey(char*, char*, char*);
char* readDataToEncrypt(char*, char*, int, int);
char* readDataToDecrypt(char*, char*, int);
int stringIsNull(char*);
int getFileSize(char*);

const int LEN = 32;
const int BLOCK = 8;
const int KEY_BIT_LEN = 256;
const int KEY_BYTE_LEN = 32; // the key is 32 bytes long

int main(int argc, char **argv) {
  int c;
  int generateKey=0;
  int encrypt=0;
  int decrypt=0;
  char *messageFileName="";
  char *keyFileName="";
  char *outFile="";

  while ((c=getopt(argc,argv,"gedf:k:o:")) != -1)
    switch (c) {
      case 'g':
        generateKey=1;
        break;
      case 'k':
        keyFileName=optarg;
        break;
      case 'f':
        messageFileName=optarg;
        break;
      case 'e':
        encrypt=1;
        break;
      case 'd':
        decrypt=1;
        break;
      case 'o':
        outFile=optarg;
        break;
      case '?':
        if (optopt == 'k') {
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        } else if (isprint(optopt)) {
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        } else {
          fprintf(stderr, "Unknown option 0x%X.\n", optopt);
        }
        return 1;
      default:
        abort();
    }

  if (generateKey==1) genKey(KEY_BIT_LEN, outFile); 
  if (encrypt == 1) encryptDataWithKey(messageFileName, keyFileName, outFile);
  if (decrypt == 1) decryptDataWithKey(messageFileName, keyFileName, outFile);

  return 0;
}

int getFileSize(char *messageFileName) {
  int size;
  struct stat st;
  if(stat(messageFileName, &st) != -1) {
    size=st.st_size;
  } else {
    size=-1;
  }
  return size;
}

int stringIsNull(char *str) {
  int ret=0;
  if ((str != NULL) && (str[0]=='\0')) {
    ret=1;
  }
  return ret;
}

void genKey(int keyBitLen, char *outFile) {
  FILE *fp;
  int c;
  int i=0;
  int keyByteLen=keyBitLen/8;
  time_t t;

  if (stringIsNull(outFile) == 1) {
    fp = fopen("key", "w");
  } else {
    fp = fopen(outFile, "w");
  } 
  if (fp) {
    srand((unsigned)time(&t));
    for (i=0; i<keyByteLen; i++) {
      c=rand();
      fputc((char)c, fp);
    }
    fclose(fp);
  }
}

char* readDataToEncrypt(char *messageFileName, char *messageData, int messageLen, int paddedMessageLen) {
  FILE *fp;
  int c;
  int i=0;

  fp = fopen(messageFileName, "r");
  if (fp) {
    for (i=0; i<messageLen; i++) {
      messageData[i]=fgetc(fp);
    }
    for (i=messageLen; i<paddedMessageLen; i++) {
      messageData[i]='\0';
    }
    fclose(fp);
  }
  return messageData;
}


int encryptDataWithKey(char *messageFileName, char *keyFileName, char *outFile) {
  FILE *fp;
  int c;
  int i;
  int j;
  int k;
  int dElem;
  int kElem;
  char keyData[KEY_BIT_LEN];

  int messageLen=0;
  int padsNeeded=0;
  int paddedMessageLen=0;
  if (stringIsNull(messageFileName) == 1) return 1;
  messageLen = getFileSize(messageFileName);
  if ((messageLen % 32) == 0) {
    padsNeeded = 0;
  } else {
    padsNeeded = 32 - (messageLen % 32);
  }
  paddedMessageLen = messageLen + padsNeeded;
  char *messageData = malloc(paddedMessageLen);

  messageData = readDataToEncrypt(messageFileName, messageData, messageLen, paddedMessageLen);

  fp = fopen(keyFileName, "r");
  if (fp) {
    for (i=0; i<KEY_BYTE_LEN; i++) {
      keyData[i]=fgetc(fp);
    }
    fclose(fp);
  }

  /* Actually do the encryption here */
  printf("[Encrypt]\n");
  char *outData = malloc(paddedMessageLen);
  for (i=0; i<KEY_BYTE_LEN; i=i+BLOCK) {
    for (j=0; j<paddedMessageLen; j=j+BLOCK) {
      for (k=0; k<BLOCK; k++) {
        dElem=k+j;
        kElem=i+k;
        if (i==0) {
          outData[dElem] = keyData[kElem] ^ messageData[dElem];
        } else {
          outData[dElem] = keyData[kElem] ^ outData[dElem];
        }
        printf("[i(%d)_j(%d)_k(%d)_dElem(%d)_kElem(%d)_0x%02X_0x%02X_0x%02X]\n",i,j,k,dElem,kElem,messageData[dElem],keyData[kElem],outData[dElem]);
      }
    }
  }

  /* Write the encrypted data to file */
  fp = fopen(outFile, "w");
  if (fp) {
    for (i=0; i<paddedMessageLen; i++) {
      fputc(outData[i],fp);
    }
    fclose(fp);
  }

  return 0;
}

char* readDataToDecrypt(char *messageFileName, char *messageData, int messageLen) {
  FILE *fp;
  int i;
  fp = fopen(messageFileName, "w");
  if (fp) {
    for (i=0; i<messageLen; i++) {
      messageData[i]=fgetc(fp);
    }
  fclose(fp);
  }

  return messageData;
}

int decryptDataWithKey(char *messageFileName, char *keyFileName, char *outFile) {
  FILE *fp;
  int i;
  int j;
  int k;
  int dElem;
  int kElem;
  char keyData[KEY_BIT_LEN];

  if (stringIsNull(messageFileName) == 1) return 1;
  int messageLen = getFileSize(messageFileName);

  char *messageData = malloc(messageLen);
  messageData = readDataToDecrypt(messageFileName, messageData, messageLen);

  fp = fopen(keyFileName, "r");
  if (fp) {
    for (i=0; i<KEY_BYTE_LEN; i++) {
      keyData[i]=fgetc(fp);
    }
    fclose(fp);
  }

  /* Actually do the decryption here */
  printf("[Decrypt]\n");
  char *outData = malloc(messageLen);
  for (i=(KEY_BYTE_LEN - BLOCK); i>-1; i=i-BLOCK) {
    for (j=(messageLen - BLOCK); j>-1; j=j-BLOCK) {
      for (k=(BLOCK-1); k>-1; k--) {
        dElem=k+j;
        kElem=i+k;
        if (i == (KEY_BYTE_LEN - BLOCK)) {
          outData[dElem] = keyData[kElem] ^ messageData[dElem];
        } else {
          outData[dElem] = keyData[kElem] ^ outData[dElem];
        }
        printf("[i(%d)_j(%d)_k(%d)_dElem(%d)_kElem(%d)_0x%02X_0x%02X_0x%02X]\n",i,j,k,dElem,kElem,messageData[dElem],keyData[kElem],outData[dElem]);
      }
    }
  }

  /* Write decrypted data to file */
  fp = fopen(outFile, "w");
  if (fp) {
    for (i=0; i<messageLen; i++) {
      fputc(outData[i],fp);
    }
    fclose(fp);
  }

  return 0;
}
