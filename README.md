# AES-128 em dois ESP32

Implementação do AES-128 **do zero** (sem bibliotecas criptográficas) em C/Arduino.
A placa A cifra uma mensagem com as matrículas e a envia pela UART2;
a placa B recebe, decifra e mostra o texto original.

**Alunos:** Nome A (matrícula) · Nome B (matrícula)

## Como funciona
- **Chave (16 bytes):** 8 últimos dígitos da matrícula A + 8 da matrícula B, em ASCII.
- **Mensagem:** `A:<matrícula A>;B:<matrícula B>` com padding PKCS#7.
- **Modo:** ECB (usado só para fins didáticos; não recomendado na prática).
- **Quadro na UART2 (115200 bps, 8N1):** `0xAA | n | n blocos de 16 bytes`.

## Estrutura
| Arquivo | Descrição |
|---|---|
| `aes128.h` | AES-128 completo: SubBytes, ShiftRows, MixColumns, AddRoundKey, expansão de chave e inversas |
| `test_aes.c` | Teste no PC: vetores do FIPS-197 e registros da Etapa 3 |
| `transmissor/` | Sketch da placa A (cifra e envia) |
| `receptor/` | Sketch da placa B (recebe, decifra e mostra) |

## Ligação
| Placa A | Placa B |
|---|---|
| GPIO17 (TX2) | GPIO16 (RX2) |
| GPIO16 (RX2) | GPIO17 (TX2) |
| GND | GND |

## Como usar
1. Na Arduino IDE, instale a placa **esp32 (Espressif Systems)**.
2. Em `transmissor.ino` e `receptor.ino`, ajuste `MATRICULA_A` e `MATRICULA_B`
   (iguais nos dois).
3. Grave `transmissor/transmissor.ino` na placa A e `receptor/receptor.ino` na B.
4. Abra o Monitor Serial das duas placas em 9600 baud.

## Validação no PC
```bash
gcc -O2 -o test_aes test_aes.c
./test_aes                        # matrículas do exemplo
./test_aes <matriculaA> <matriculaB>
```
Confere os vetores do FIPS-197 (Apêndices B e C.1), o exemplo do enunciado,
os três blocos ECB e gera chaves de rodada, estados e efeito avalanche.

## Exemplo de saída
```
Receptor:  Texto original: A:20231001;B:20231002
```

## Por que não usar ECB?
Blocos iguais geram cifrados iguais, e blocos podem ser trocados, repetidos ou
removidos sem detecção. Na prática, usar CBC/CTR com IV novo ou GCM (que autentica).
