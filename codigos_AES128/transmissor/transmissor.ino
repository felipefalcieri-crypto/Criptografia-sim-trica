#include "aes128.h"

// ---- Dados da matricula
const char MATRICULA_A[] = "20231001";
const char MATRICULA_B[] = "20231002";

#define RX2_PIN 16
#define TX2_PIN 17
#define MARCADOR 0xAA

void imprimeHex(const char *rotulo, const uint8_t *b, int n) {
  Serial.print(rotulo);
  for (int i = 0; i < n; i++) {
    if (b[i] < 0x10) Serial.print('0');
    Serial.print(b[i], HEX);
  }
  Serial.println();
}

// Monta a chave: 8 ultimos digitos de A (completando com '0' a esquerda) + 8 de B.
void montaChave(uint8_t key[16]) {
  const char *mats[2] = {MATRICULA_A, MATRICULA_B};
  for (int m = 0; m < 2; m++) {
    int len = strlen(mats[m]);
    for (int i = 0; i < 8; i++) {
      int idx = len - 8 + i;
      key[8 * m + i] = (idx >= 0) ? (uint8_t)mats[m][idx] : (uint8_t)'0';
    }
  }
}

void enviaQuadro() {
  // 1) Chave e expansao (11 chaves de rodada)
  uint8_t key[16], rk[176];
  montaChave(key);
  aes128_expand_key(key, rk);

  // 2) Mensagem + PKCS#7
  uint8_t msg[96];
  int len = snprintf((char *)msg, 64, "A:%s;B:%s", MATRICULA_A, MATRICULA_B);
  int total = pkcs7_pad(msg, len);
  int n = total / AES_BLOCK;

  // 3) Cifra bloco a bloco (ECB)
  uint8_t ct[96];
  for (int i = 0; i < n; i++) aes128_encrypt_block(rk, msg + 16 * i, ct + 16 * i);

  imprimeHex("Chave (hex):        ", key, 16);
  imprimeHex("Mensagem + PKCS#7:  ", msg, total);
  imprimeHex("Cifrado:            ", ct, total);

  // 4) Quadro: AA | n | blocos  -- bytes brutos
  Serial2.write((uint8_t)MARCADOR);
  Serial2.write((uint8_t)n);
  Serial2.write(ct, total);
  Serial2.flush();
  Serial.printf("Quadro enviado: %d bytes\n", 2 + total);
}

void setup() {
  Serial.begin(9600);                                // monitor serial (USB)
  Serial2.begin(9600, SERIAL_8N1, RX2_PIN, TX2_PIN); // UART2 para a outra placa
  delay(1000);
}

void loop() {
  // Reenvia a cada 5 s para facilitar a demonstracao (ligar a placa B depois).
  enviaQuadro();
  delay(5000);
}
