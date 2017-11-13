/*  This code is prepared to mimic subspace attack on AES CBC mode in SSL/TLS.
Project specific : Plaintext has only 1 block which makes AES CBC mode with only 1 block instead of taking
multiple blocks.
Input for both plaintext and key are 16 bytes, which can be represented by decimal numbers.
Also, if you initialize arr[16]={a} then it is treated as arr[0]={1, 0, 1, 0} the rest of 15
are taken zero values. */

#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include "aes.h"

#define KEYLEN 16
#define TRUE 1
#define FALSE 0

long int Cnt;   // to count no.of attempts made
int session_num;   // counts #of sessions
int Rec_Bytes;    // to count #of bytes to be recovered
int temp1,temp2;   // to store the value temporarily
int i;  // taken for changing the index of array
int aa;   // variable used for exhaustive search
int bb;   // variable used for exhaustive search
int zz;   // variable used for exhaustive search

unsigned char conti_match;  // A flag used after comparing generated cipher and recorded cipher
uint8_t IV[16];  // Array for storing IV temporarily according to sessions
uint8_t recorded_cipher[16];   //  Array for storing recorded ciphers temporarily according to sessions
void set_option();   // function used for setting session values
FILE *fp;   // file pointer

uint8_t plain[16]={3,77,170,4,49,9,211,48,153,160,221,192,52};  //Array is defined with 13 bytes of Plaintext
uint8_t XOR_plain[16];   //Array for storing XORed values temporarily
uint8_t key[16]={175,17,34,67,148,53,102,215,168,89,186,123,252,237,206,143};//Key array is initialized with values given
uint8_t cipher[16]= {0};    //Array for storing generated cipher values

/* IV and Cipher recorded values for 3 sessions are given in project, values are in decimal*/
uint8_t IV1[16]= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0}; //IV array for session1 is initialized with values given
uint8_t recorded_cipher1[16] = {95,123,253,239,222,157,46,171,125,24,141,181,89,200,96,172};// Cipher array for session1 is initialized with values given

uint8_t IV2[16]= {161,2,51,4,245,93,7,8,9,170,11,136,221,14,153,144}; //IV array for session2 is initialized with values given
uint8_t recorded_cipher2[16] = {45,143,230,198,142,232,130,121,135,143,35,10,7,244,3,155};// Cipher array for session2 is initialized with values given

uint8_t IV3[16]= {17,162,187,164,95,85,7,8,9,170,11,136,13,0,169,253}; //IV array for session3 is initialized with values given
uint8_t recorded_cipher3[16] = {51,221,10,20,49,9,211,48,153,160,208,192,170,249,10,255}; // Cipher array for session3 is initialized with values given

void Display_output();  // outputs messages and values once session is complete
void Recover_process();  // function for recovering bytes
void recover_1Byte();  // recovers 1 byte
void recover_2Bytes();  // recovers 2 bytes
void recover_3Bytes();  //  recovers 3 bytes
void Check_match();  // finds matching pair of generated cipher and recorded cipher
void Initialize();   // Initializes the variables and displays start-up messages

int main()
{
    Initialize();   // Calls the function for initializing variables
    Recover_process();    // Calls the function for recovery process

    fclose(fp);
    return 0;
}


void recover_1Byte()
{
    session_num = 1;
step1:
    while(session_num < 4)
    {
        conti_match = FALSE;

        Cnt = 0;

        set_option();


            for(bb = 0; bb < 256 ; bb++)
            {
                plain[13] = temp1;
                plain[14] = temp2;
                plain[15] = bb;

                 // XOR plaintext with IV
                  for(i = 0; i < 16; i++)
                  {
                     XOR_plain[i] = plain[i] ^ IV[i];
                  }
                if(Cnt < 41)
                {
                       fprintf(fp,"\n\nPlaintext P:");
                        for (i = 0; i < 16; i++)
                        {
                            fprintf(fp,"%02x ", plain[i]);
                        }

                        fprintf(fp,"\nXORED Plaintext P':");

                        for (i = 0; i < 16; i++)
                        {
                            fprintf(fp,"%02x ", XOR_plain[i]);
                        }
                }
                   aes(XOR_plain, key, cipher); // to perform full AES encryption
                // aes_rounds(plain, key, 10, cipher);  // use this function can specify #rounds

                if(Cnt<41)
                  {

                       fprintf(fp,"\nCiphertext C:");

                        for (i = 0; i < 16; i++)
                        {
                            fprintf(fp,"%02x ", cipher[i]);

                        }
                  }
                    Check_match();
                   if(conti_match== TRUE)
                        goto step1;
                    //return(0);
//                }

                Cnt++;

             }
            Display_output();
            session_num++;

    }

}

void recover_2Bytes()
{
    session_num = 1;
step1:
    while(session_num < 4)
    {
        conti_match = FALSE;

        Cnt = 0;

        set_option();

        for(aa = 0; aa < 256; aa++)
        {
            for(bb = 0; bb < 256 ; bb++)
            {
                plain[13] = temp1;
                plain[14] = aa;
                plain[15] = bb;

                 // XOR plaintext with IV
                  for(i = 0; i < 16; i++)
                  {
                     XOR_plain[i] = plain[i] ^ IV[i];
                  }

                  if(Cnt<41)
                  {

                       fprintf(fp,"\n\nPlaintext P:");
                        for (i = 0; i < 16; i++)
                        {
                             fprintf(fp,"%02x ", plain[i]);
                        }


                        fprintf(fp,"\nXORED Plaintext P':");
                        for (i = 0; i < 16; i++)
                        {
                            fprintf(fp,"%02x ", XOR_plain[i]);
                        }

                    }

                   aes(XOR_plain, key, cipher); // to perform full AES encryption
                // aes_rounds(plain, key, 10, cipher);  // use this function can specify #rounds

                  if(Cnt<41)
                  {

                       fprintf(fp,"\nCiphertext C:");

                        for (i = 0; i < 16; i++)
                        {
                            fprintf(fp,"%02x ", cipher[i]);

                        }
                  }
                    Check_match();
                   if(conti_match== TRUE)
                        goto step1;
                    //return(0);
//                }
                Cnt++;

             }

        }
        Display_output();
        session_num++;
    }
}

void recover_3Bytes()
{
    session_num = 1;
step1:
    while(session_num < 4)
    {
        conti_match = FALSE;

        Cnt = 0;

        set_option();
        for(zz = 0; zz < 256; zz++)
        {
            for(aa = 0; aa < 256; aa++)
            {
                for(bb = 0; bb < 256 ; bb++)
                {
                    plain[13] = zz;
                    plain[14] = aa;
                    plain[15] = bb;

                     // XOR plaintext with IV for CBC mode
                      for(i = 0; i < 16; i++)
                      {
                         XOR_plain[i] = plain[i] ^ IV[i];
                      }

                  if(Cnt<41)
                  {

                       fprintf(fp,"\n\nPlaintext P:");
                        for (i = 0; i < 16; i++)
                        {
                             fprintf(fp,"%02x ", plain[i]);
                        }


                        fprintf(fp,"\nXORED Plaintext P':");
                        for (i = 0; i < 16; i++)
                        {
                            fprintf(fp,"%02x ", XOR_plain[i]);
                        }

                    }
                       aes(XOR_plain, key, cipher); // to perform full AES encryption
                    // aes calls function aes_rounds(plain, key, 10, cipher) in aes.h which sets up round=10
                  if(Cnt<41)
                  {

                       fprintf(fp,"\nCiphertext C:");

                        for (i = 0; i < 16; i++)
                        {
                            fprintf(fp,"%02x ", cipher[i]);

                        }
                  }
                    Check_match();
                    if(conti_match== TRUE)
                        goto step1;
                    Cnt++;
                 }

            }
        }
        Display_output();
        session_num++;
    }
}

void Check_match()
{
        for (i = 0; i < 16; i++)
        {
            if(cipher[i]!= recorded_cipher[i])
            {
                conti_match = FALSE;
                i = 16;
             //   fputs("F",fp);
            }
            else
            {
                conti_match = TRUE;
             //   fputs("*****T******",fp);
            }
        }

        if(conti_match == TRUE)
        {
//                    fputs("--------M--------",fp);
            printf("\n\nMatched Plaintext found for IV and Ciphertext pair:");
            fprintf(fp,"\n\nMatched Plaintext found for IV and Ciphertext pair:");

            printf("\n\nKnown Bytes:");
            fprintf(fp,"\n\nKnown Bytes:");
            for (i = 0; i < (KEYLEN- Rec_Bytes) ; i++)
            {
                printf("%02x ", plain[i]);
                fprintf(fp,"%02x ", plain[i]);

            }

            printf("\nRecovered Bytes:");
            fprintf(fp,"\nRecovered Bytes:");
            for (i =(KEYLEN- Rec_Bytes); i < 16; i++)
            {
                printf("%02x ", plain[i]);
                fprintf(fp,"%02x ", plain[i]);

            }

            printf("\n\nRecorded IV:");
            fprintf(fp,"\n\nRecorded IV:");

            for (i = 0; i < 16; i++)
            {
                printf("%02x ", IV[i]);
                fprintf(fp,"%02x ", IV[i]);

            }

            printf("\nRecorded Ciphertext:");
            fprintf(fp,"\nRecorded Ciphertext:");

            for (i = 0; i < 16; i++)
            {
                printf("%02x ", cipher[i]);
                fprintf(fp,"%02x ", cipher[i]);

            }

            printf("\n Attempts made = %li ", Cnt);
            fprintf(fp,"\n Attempts made = %li ", Cnt);
             printf("\n\n");
             fprintf(fp,"\n\n");

             session_num++;
//                        goto step1;
            //return(0);
        }

}

void Recover_process()
{
    switch(Rec_Bytes)
    {
        case 1:
            recover_1Byte();
        break;
        case 2:
            recover_2Bytes();
        break;
        case 3:
            recover_3Bytes();
        break;
        default:
        break;
    }
}

void Display_output()
{
    printf("\nRecorded IV:");
    fprintf(fp,"\nRecorded  IV:");

    for (i = 0; i < 16; i++)
    {
        printf("%02x ", IV[i]);
        fprintf(fp,"%02x ", IV[i]);

    }

    printf("\nRecorded Ciphertext:");
    fprintf(fp,"\nRecorded Ciphertext:");

    for (i = 0; i < 16; i++)
    {
        printf("%02x ", recorded_cipher[i]);
        fprintf(fp,"%02x ", recorded_cipher[i]);

    }
     if(conti_match != TRUE)
     {
         printf("\n No Match found:");
         printf("\n Attempts made = %li ", Cnt);
         fprintf(fp,"\n No Match found:");
         fprintf(fp,"\n Attempts made = %li ", Cnt);
         printf("\n\n");
         fprintf(fp,"\n\n");
     }

     if (session_num == 3)
     {
         printf("\n OS: Windows7");
         printf("\n System Type: 64-bit OS");
         printf("\n Processor: Intel(R) Core(TM) i5 CPU, 2.40 GHz Speed");
         fprintf(fp,"\n OS: Windows7");
         fprintf(fp,"\n System Type: 64-bit OS");
         fprintf(fp,"\n Processor: Intel(R) Core(TM) i5 CPU, 2.40 GHz Speed");

         printf("\n\n");
         fprintf(fp,"\n\n");
    }

}

void Initialize()
{

    printf("\n-------------------------------AES CBC Attack--------------------------------");
//    fprintf(fp,"\n BYTE[15] BYTE[16]");
    printf("\n\n\nEnter No.of Plaintext Bytes you want to recover(1-3):");
    scanf("%d",&Rec_Bytes);
    printf("\n# of sessions:3");
    printf("\n# of Plaintext bytes:16 bytes");

    switch(Rec_Bytes)
    {
        case 1:
            fp=fopen("AES_Recover1Byte.txt","w");
        break;
        case 2:
            fp=fopen("AES_Recover2Bytes.txt","w");
        break;
        case 3:
            fp=fopen("AES_Recover3Bytes.txt","w");
        break;
        default:
        break;
    }

    fputs("\n-------------------------------AES CBC Attack--------------------------------",fp);
    fprintf(fp,"\n# of bytes to be recovered:%d",Rec_Bytes);
    fprintf(fp,"\n# of sessions:3");
    fprintf(fp,"\n# of Plaintext bytes:16 bytes");


    if(Rec_Bytes==1)
    {
          temp1 = 144;
          temp2 = 10;
    }

    if(Rec_Bytes==2)
    {
          temp1 = 144;
    }
}
void set_option()
{
    fprintf(fp,"\n\n\n************************Solution bit(b)****************************");
    fprintf(fp,"\n\n\nList of 40 Guessed Instances:");

    switch(session_num)
    {
        case 1:
            printf("\n\n\n------------------------Session 1-----------------------------");
            fprintf(fp,"\n\n\n------------------------Session 1-----------------------------");

            fprintf(fp,"\n\nRecorded  IV:");

            for (i = 0; i < 16; i++)
            {
                IV[i] = IV1[i];
                recorded_cipher[i] = recorded_cipher1[i];
                fprintf(fp,"%02x ", IV[i]);
            }

        break;
        case 2:
            printf("\n\n\n--------------------------Session 2---------------------------");
            fprintf(fp,"\n\n\n--------------------------Session 2---------------------------");

            fprintf(fp,"\n\nRecorded  IV:");

            for (i = 0; i < 16; i++)
            {
                IV[i] = IV2[i];
                recorded_cipher[i] = recorded_cipher2[i];
                fprintf(fp,"%02x ", IV[i]);
            }
        break;
        case 3:
            printf("\n\n\n--------------------------Session 3---------------------------");
            fprintf(fp,"\n\n\n--------------------------Session 3---------------------------");
            fprintf(fp,"\n\nRecorded  IV:");

            for (i = 0; i < 16; i++)
            {
                IV[i] = IV3[i];
                recorded_cipher[i] = recorded_cipher3[i];
                fprintf(fp,"%02x ", IV[i]);
            }
        break;
        default:
        break;
    }

}



