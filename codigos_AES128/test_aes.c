/*
 * test_aes.c - roda no PC. Valida o aes128.h e gera os registros da Etapa 3.
 * Compilar: gcc -O2 -o test_aes test_aes.c && ./test_aes
 * (Para usar outras matriculas: ./test_aes <matriculaA> <matriculaB>)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes128.h"

static int falhas = 0;

static void hex(const char *rotulo, const uint8_t *b, int n) {
  printf("%-34s", rotulo);
  for (int i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

static void from_hex(const char *h, uint8_t *out) {
  for (int i = 0; h[2 * i] && h[2 * i + 1]; i++) {
    unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (uint8_t)v;
  }
}

static void confere(const char *nome, const uint8_t *obtido, const char *esperado_hex) {
  uint8_t esp[16]; from_hex(esperado_hex, esp);
  int ok = memcmp(obtido, esp, 16) == 0;
  printf("[%s] %s\n", ok ? "OK " : "ERRO", nome);
  if (!ok) { falhas++; hex("   obtido:", obtido, 16); hex("   esperado:", esp, 16); }
}

static void teste_vetor(const char *nome, const char *k, const char *p, const char *c) {
  uint8_t key[16], pt[16], ct[16], dec[16], rk[176];
  from_hex(k, key); from_hex(p, pt);
  aes128_expand_key(key, rk);
  aes128_encrypt_block(rk, pt, ct);
  aes128_decrypt_block(rk, ct, dec);
  char n1[96], n2[96];
  snprintf(n1, sizeof n1, "%s: cifrar", nome);
  snprintf(n2, sizeof n2, "%s: decifrar", nome);
  confere(n1, ct, c);
  confere(n2, dec, p);
}

static int bits_diferentes(const uint8_t *a, const uint8_t *b, int n) {
  int d = 0;
  for (int i = 0; i < n; i++) d += __builtin_popcount(a[i] ^ b[i]);
  return d;
}

int main(int argc, char **argv) {
  const char *matA = argc > 2 ? argv[1] : "20231001";
  const char *matB = argc > 2 ? argv[2] : "20231002";

  printf("=== 1. Vetores do FIPS-197 ===\n");
  teste_vetor("Apendice B  ", "2b7e151628aed2a6abf7158809cf4f3c",
              "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32");
  teste_vetor("Apendice C.1", "000102030405060708090a0b0c0d0e0f",
              "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a");

  /* --- Chave e mensagem da dupla --- */
  uint8_t key[16];
  char a8[9], b8[9];
  {
    int la = strlen(matA), lb = strlen(matB);
    for (int i = 0; i < 8; i++) {
      int ia = la - 8 + i, ib = lb - 8 + i;
      a8[i] = ia >= 0 ? matA[ia] : '0';
      b8[i] = ib >= 0 ? matB[ib] : '0';
    }
    a8[8] = b8[8] = 0;
    memcpy(key, a8, 8); memcpy(key + 8, b8, 8);
  }
  uint8_t msg[128];
  int len = snprintf((char *)msg, sizeof msg, "A:%s;B:%s", matA, matB);
  int total = pkcs7_pad(msg, len);
  int n = total / 16;

  uint8_t rk[176], ct[128], dec[128];
  aes128_expand_key(key, rk);
  for (int i = 0; i < n; i++) aes128_encrypt_block(rk, msg + 16 * i, ct + 16 * i);
  for (int i = 0; i < n; i++) aes128_decrypt_block(rk, ct + 16 * i, dec + 16 * i);

  printf("\n=== 2. Exemplo do enunciado (matriculas %s e %s) ===\n", matA, matB);
  printf("Chave (ASCII)                     %s%s\n", a8, b8);
  hex("Chave (hex)", key, 16);
  printf("Mensagem (%d bytes)               %s\n", len, msg);
  for (int i = 0; i < n; i++) { char r[40]; snprintf(r, 40, "Com PKCS#7, bloco %d", i + 1); hex(r, msg + 16 * i, 16); }
  for (int i = 0; i < n; i++) { char r[40]; snprintf(r, 40, "Cifrado, bloco %d", i + 1); hex(r, ct + 16 * i, 16); }
  int unp = pkcs7_unpad(dec, total);
  printf("Decifrado e sem PKCS#7:           %.*s  (%s)\n", unp, dec, (unp == len && memcmp(dec, msg, len) == 0) ? "OK" : "ERRO");
  if (!(unp == len && memcmp(dec, msg, len) == 0)) falhas++;

  if (argc <= 2) {
    printf("\nConferencia com os valores do enunciado:\n");
    confere("bloco 1 cifrado", ct, "3a3784991ab0acaa88d5fd94cb7b74ad");
    confere("bloco 2 cifrado", ct + 16, "cbea1d9e3e1f39da47111cf69064b166");
    uint8_t chave_ex[16]; from_hex("32303233313030313230323331303032", chave_ex);
    if (memcmp(chave_ex, key, 16) != 0) { printf("[ERRO] chave hex difere do enunciado\n"); falhas++; }
    else printf("[OK ] chave hex igual a do enunciado\n");
  }

  printf("\n=== 3. ECB: tres blocos (chave do exemplo) ===\n");
  {
    uint8_t kx[16], rkx[176], o[16];
    from_hex("32303233313030313230323331303032", kx);
    aes128_expand_key(kx, rkx);
    const char *pt[3] = {"LIGAR LED VERDE.", "DESLIGAR LED    ", "LIGAR LED VERDE."};
    const char *esp[3] = {"e0c22a6f02664f487dc9528642203dec", "2b4d065ea65478b60696616244cd5070", "e0c22a6f02664f487dc9528642203dec"};
    for (int i = 0; i < 3; i++) {
      aes128_encrypt_block(rkx, (const uint8_t *)pt[i], o);
      char r[48]; snprintf(r, 48, "bloco %d \"%s\"", i + 1, pt[i]);
      confere(r, o, esp[i]);
    }
  }

  printf("\n=== 4. Etapa 3 - registros da dupla ===\n");
  hex("Chave", key, 16);
  hex("Mensagem com PKCS#7", msg, total);
  hex("Texto cifrado final", ct, total);
  hex("Chave de rodada 0", rk, 16);
  hex("Chave de rodada 1", rk + 16, 16);

  printf("\nCinco estados do bloco 1 (rodada 1):\n");
  {
    uint8_t s[16];
    memcpy(s, msg, 16);
    hex("  entrada (bloco 1 claro)", s, 16);
    add_round_key(s, rk);        hex("  (1) AddRoundKey inicial", s, 16);
    sub_bytes(s);                hex("  (2) SubBytes", s, 16);
    shift_rows(s);               hex("  (3) ShiftRows", s, 16);
    mix_columns(s);              hex("  (4) MixColumns", s, 16);
    add_round_key(s, rk + 16);   hex("  (5) AddRoundKey (chave 1)", s, 16);
  }

  printf("\nEfeito avalanche (bloco 1):\n");
  {
    uint8_t base[16], alt[16], rk2[176], k2[16], m2[16];
    aes128_encrypt_block(rk, msg, base);

    memcpy(m2, msg, 16); m2[0] ^= 0x01;
    aes128_encrypt_block(rk, m2, alt);
    printf("  1 bit da mensagem (byte 0, bit 0): %3d de 128 bits (%.1f%%)\n",
           bits_diferentes(base, alt, 16), 100.0 * bits_diferentes(base, alt, 16) / 128);
    hex("    cifrado original", base, 16); hex("    cifrado alterado", alt, 16);

    memcpy(k2, key, 16); k2[0] ^= 0x01;
    aes128_expand_key(k2, rk2);
    aes128_encrypt_block(rk2, msg, alt);
    printf("  1 bit da chave    (byte 0, bit 0): %3d de 128 bits (%.1f%%)\n",
           bits_diferentes(base, alt, 16), 100.0 * bits_diferentes(base, alt, 16) / 128);
    hex("    cifrado original", base, 16); hex("    cifrado alterado", alt, 16);

    long soma_m = 0, soma_k = 0;
    for (int b = 0; b < 128; b++) {
      memcpy(m2, msg, 16); m2[b / 8] ^= (uint8_t)(1 << (b % 8));
      aes128_encrypt_block(rk, m2, alt); soma_m += bits_diferentes(base, alt, 16);
      memcpy(k2, key, 16); k2[b / 8] ^= (uint8_t)(1 << (b % 8));
      aes128_expand_key(k2, rk2);
      aes128_encrypt_block(rk2, msg, alt); soma_k += bits_diferentes(base, alt, 16);
    }
    printf("  Media sobre os 128 bits da mensagem: %.1f bits (%.1f%%)\n", soma_m / 128.0, soma_m / 128.0 / 128 * 100);
    printf("  Media sobre os 128 bits da chave:    %.1f bits (%.1f%%)\n", soma_k / 128.0, soma_k / 128.0 / 128 * 100);
  }

  printf("\n%s (%d falha(s))\n", falhas ? "FALHOU" : "TODOS OS TESTES PASSARAM", falhas);
  return falhas ? 1 : 0;
}
