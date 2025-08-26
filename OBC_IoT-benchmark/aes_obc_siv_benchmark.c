#include "./common/stm32wrapper.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "aes-obc/aes_obc_siv.h"

#define EEVEE_BEGIN_EXP_HDR1 0x00
#define EEVEE_BEGIN_EXP_HDR2 0xff
#define EEVEE_BEGIN_EXP_HDR3 0x00

#define KEY_LEN 16
#define IV_LEN 16
#define MAX_MESSAGE_LEN 1500

int main(void)
{
    clock_setup();
    gpio_setup();
    usart_setup(115200);

    // Cycle counter setup
    SCS_DEMCR |= SCS_DEMCR_TRCENA;
    DWT_CYCCNT = 0;
    DWT_CTRL |= DWT_CTRL_CYCCNTENA;
    char cyclebuffer[40];

    uint8_t buffer[3];

    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];  // IV replaces nonce in OBC-SIV

    unsigned char *message = malloc(MAX_MESSAGE_LEN * sizeof(unsigned char));
    if(message == NULL) {
        // stop with error
        while(1) {
            sprintf(cyclebuffer, "Cannot allocate for message");
            send_USART_str(cyclebuffer);
        }
    }
    unsigned char *ciphertext = malloc(MAX_MESSAGE_LEN * sizeof(unsigned char));
    if(ciphertext == NULL) {
        free(message);
        // stop with error
        while(1) {
            sprintf(cyclebuffer, "Cannot allocate for ciphertext");
            send_USART_str(cyclebuffer);
        }
    }

    sprintf(cyclebuffer, "Ready!");
    send_USART_str(cyclebuffer);

    while(1) {
        // Blocking read of 3-byte header
        recv_USART_bytes(buffer, 3);
        if(buffer[0] != EEVEE_BEGIN_EXP_HDR1 || buffer[1] != EEVEE_BEGIN_EXP_HDR2 || buffer[2] != EEVEE_BEGIN_EXP_HDR3)
            continue;

        // Receive message length
        recv_USART_bytes(buffer, 2);
        unsigned int message_len = buffer[0] | (buffer[1] << 8);
        if(message_len > MAX_MESSAGE_LEN) {
            sprintf(cyclebuffer, "Message too large!");
            send_USART_str(cyclebuffer);
            continue;
        }

        // Receive message test vector
        recv_USART_bytes(message, message_len);
        // Receive key
        recv_USART_bytes(key, KEY_LEN);
        // Note: OBC-SIV doesn't use an external nonce, IV is generated from the MAC

        /////// MEASURE CYCLES
        DWT_CYCCNT = 0;
        unsigned int oldcount = DWT_CYCCNT;

        // Measure OBC-SIV encryption
        int success = aes_obc_siv_encrypt(ciphertext, iv, message, message_len, NULL, 0, key);

        unsigned int cyclecount = DWT_CYCCNT - oldcount;
        /////// STOP MEASURE CYCLES

        if(success != 0) {
            sprintf(cyclebuffer, "encrypt returned non-zero");
            send_USART_str(cyclebuffer);
            continue;
        }
        
        // Send cyclecount
        sprintf(cyclebuffer, "%d", cyclecount);
        send_USART_str(cyclebuffer);
        // Send ciphertext
        send_USART_bytes(ciphertext, message_len);
        // Send IV (which serves as the authentication tag in OBC-SIV)
        send_USART_bytes(iv, IV_LEN);
    }

    free(message);
    free(ciphertext);
    return 0;
}