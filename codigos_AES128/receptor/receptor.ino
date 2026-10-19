#include "aes128.h"

// ---- Dados da matricula
const char MATRICULA_A[] = "20231001";
const char MATRICULA_B[] = "20231002";

#define RX2_PIN 16
#define TX2_PIN 17
#define MARCADOR 0xAA
#define MAX_BLOCOS 8            // limite de seguranca: 128 bytes
#define TIMEOUT_MS 1000         // tempo maximo para chegar o quadro inteiro

uint8_t rk[176];

void imprimeHex(const char *rotulo, const uint8_t *b, int n) {
  Serial.print(rotulo);
  for (int i = 0; i < n; i++) {
    if (b[i] < 0x10) Serial.print('0');
    Serial.print(b[i], HEX);
  }
  Serial.println();
}

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

// Le exatamente 'n' bytes ate o prazo; retorna true se conseguiu todos.
bool leExato(uint8_t *dst, int n, uint32_t prazo) {
  int got = 0;
  while (got < n) {
    if ((int32_t)(millis() - prazo) >= 0) return false;
    if (Serial2.available()) dst[got++] = (uint8_t)Serial2.read();
  }
  return true;
}

void setup() {
  Serial.begin(9600);
  Serial2.begin(9600, SERIAL_8N1, RX2_PIN, TX2_PIN);
  uint8_t key[16];
  montaChave(key);
  aes128_expand_key(key, rk);
  imprimeHex("Receptor pronto. Chave: ", key, 16);
}

void loop() {
  // 1) Sincroniza: descarta tudo ate achar 0xAA
  if (!Serial2.available()) return;
  if (Serial2.read() != MARCADOR) return;

  uint32_t prazo = millis() + TIMEOUT_MS;

  // 2) Numero de blocos
  uint8_t n;
  if (!leExato(&n, 1, prazo)) { Serial.println("ERRO: timeout lendo n"); return; }
  if (n < 1 || n > MAX_BLOCOS) { Serial.printf("ERRO: n invalido (%u)\n", n); return; }

  // 3) Exatamente 16*n bytes de texto cifrado
  uint8_t ct[16 * MAX_BLOCOS], pt[16 * MAX_BLOCOS];
  int total = 16 * n;
  if (!leExato(ct, total, prazo)) { Serial.println("ERRO: timeout lendo blocos"); return; }
  imprimeHex("Recebido (cifrado): ", ct, total);

  // 4) Decifra cada bloco
  for (int i = 0; i < n; i++) aes128_decrypt_block(rk, ct + 16 * i, pt + 16 * i);
  imprimeHex("Decifrado (hex):    ", pt, total);

  // 5) Remove PKCS#7 e exibe
  int len = pkcs7_unpad(pt, total);
  if (len < 0) { Serial.println("ERRO: PKCS#7 invalido (chave errada ou quadro corrompido)"); return; }
  pt[len] = 0;
  Serial.print("Texto original: ");
  Serial.println((char *)pt);
}
