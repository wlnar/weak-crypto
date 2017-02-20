#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/stat.h>
#include<errno.h>

void genKey(int, char*, int);
int encryptDataWithKey(char*, char*, char*, int);
int decryptDataWithKey(char*, char*, char*, int);
char* readDataToEncrypt(char*, char*, int, int);
char* readDataToDecrypt(char*, char*, int);
int stringIsNull(char*);
int getFileSize(char*);
int readKey(char*, char*);

const int LEN = 32;
const int BLOCK = 8;
const int KEY_BIT_LEN = 256;
const int KEY_BYTE_LEN = 32;

/*
 *
 *
 *
 */

int main(int argc, char **argv) {
  int c;
  int generateKey=0;
  int encrypt=0;
  int decrypt=0;
  int verbose=0;
  char *messageFileName="";
  char *keyFileName="";
  char *outFile="";

  while ((c=getopt(argc,argv,"gedf:k:o:v")) != -1)
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
      case 'v':
        verbose=1;
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

  if (generateKey == 1) genKey(KEY_BIT_LEN, outFile, verbose); 
  if ((encrypt == 1) && (decrypt == 0)) encryptDataWithKey(messageFileName, keyFileName, outFile, verbose);
  if ((decrypt == 1) && (encrypt == 0)) decryptDataWithKey(messageFileName, keyFileName, outFile, verbose);

  return 0;
}

int getFileSize(char *fileName) {
  int size;
  struct stat st;
  if(stat(fileName, &st) != -1) {
    size=st.st_size;
  } else {
    size=-1;
  }
  return size;
}

int stringIsNull(char *str) {
  int ret = 0;
  if (str[0]=='\0') ret = 1;
  return ret;
}

void genKey(int keyBitLen, char *outFile, int verbose) {
  FILE *fp;
  int c;
  int i=0;
  int keyByteLen = keyBitLen / 8;
  time_t t;

  if (stringIsNull(outFile) == 1) {
    fp = fopen("key", "w");
  } else {
    fp = fopen(outFile, "w");
  } 
  if (fp) {
    srand((unsigned)time(&t));
    if (verbose == 1) printf("[Key]:\n");
    for (i=0; i<keyByteLen; i++) {
      c=rand()%256; // generate random number between 0 and 255
      if (verbose == 1) {
        printf("key[%02d] = %03d 0x%02X\n",i,c,c);
      }
      fputc(c, fp);
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

int readKey(char *keyFileName, char *keyData) {
  FILE *fp;
  int i;

  fp = fopen(keyFileName, "r");
  if (fp) {
    for (i=0; i<KEY_BYTE_LEN; i++) {
      keyData[i]=(char)fgetc(fp);
    }
    fclose(fp);
  }

  return 0;
}

int encryptDataWithKey(char *messageFileName, char *keyFileName, char *outFile, int verbose) {
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
  readKey(keyFileName, keyData);

  /* Actually do the encryption here */
  char *outData = malloc(paddedMessageLen);
  if (verbose == 1) printf("[Encrypt]\n");
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
        if (verbose == 1) {
          printf("[i(%d)_j(%d)_k(%d)_dElem(%d)_kElem(%d)_",i,j,k,dElem,kElem);
          printf("0x%02X_0x%02X_0x%02X]\n",(unsigned char)messageData[dElem],(unsigned char)keyData[kElem],(unsigned char)outData[dElem]);
        }
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
  fp = fopen(messageFileName, "r");
  if (fp) {
    for (i=0; i<messageLen; i++) {
      messageData[i]=(char)fgetc(fp);
    }
  fclose(fp);
  }

  return messageData;
}

int decryptDataWithKey(char *messageFileName, char *keyFileName, char *outFile, int verbose) {
  FILE *fp;
  int i;
  int j;
  int k;
  int dElem;
  int kElem;
  char keyData[KEY_BIT_LEN];

  int messageLen = getFileSize(messageFileName);
  char *messageData = malloc(messageLen);

  messageData = readDataToDecrypt(messageFileName, messageData, messageLen);
  readKey(keyFileName, keyData);

  /* Actually do the decryption here */
  char *outData = malloc(messageLen);
  if (verbose == 1) printf("[Decrypt]\n");
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
        if (verbose == 1) {
          printf("[i(%d)_j(%d)_k(%d)_dElem(%d)_kElem(%d)_",i,j,k,dElem,kElem);
          printf("0x%02X_0x%02X_0x%02X]\n",(unsigned char)messageData[dElem],(unsigned char)keyData[kElem],(unsigned char)outData[dElem]);
        }
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
