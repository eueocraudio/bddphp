# bddphp — Especificação do protocolo

Esta é a especificação normativa do **Blind Dead Drop**: o formato de fio, a
derivação de chaves/endereços e a API HTTP. Qualquer cliente que siga este
documento interopera com o servidor bddphp e com os clientes de referência em
`../bdd` (Python/C++) — o contrato é byte a byte.

> Palavras como **DEVE**, **NÃO DEVE** e **PODE** seguem o sentido usual de
> requisito normativo.

## 1. Modelo

Duas partes compartilham, fora de banda, um **segredo-raiz** de 32 bytes. Toda a
confidencialidade e a impossibilidade de correlação derivam desse segredo no
cliente. O servidor é um armazenamento opaco chave→valor: guarda blobs em
endereços, e nada mais.

- Um **channel** é um inteiro (≥ 0) escolhido pelas partes.
- Cada channel tem duas **parts**: `request` e `response`.
- Para cada (part, channel) deriva-se um **endereço** e uma **chave de mensagem**
  independentes.

Como `request` e `response` usam rótulos diferentes, seus endereços e chaves não
têm relação observável — o servidor não consegue ligar um pedido à sua resposta,
nem as duas partes entre si.

## 2. Derivação (HKDF-SHA256, RFC 5869)

Todas as derivações usam **HKDF-SHA256** com **salt = 32 bytes zero** (o caso
"sem salt" da RFC 5869 §2.2; equivale a `hash_hkdf('sha256', ikm, len, info, '')`
no PHP).

```
info_addr = "bdd-addr|" + part + "|" + channel      (ASCII, channel em decimal)
info_key  = "bdd-key|"  + part + "|" + channel

endereço(part, channel) = hex( HKDF(secret, info_addr, 32) )   → 64 chars hex minúsculos
chave(part, channel)    =      HKDF(secret, info_key,  32)     → 32 bytes
```

`part` DEVE ser exatamente `request` ou `response`. `channel` é a representação
decimal do inteiro, sem zeros à esquerda (ex.: `0`, `7`, `42`).

**Vetor de referência** (autoverificável):

```
secret  = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
part    = request
channel = 0
endereço = 59050b4ec15597c9f30cb39a5ddab76b17de9fb50120cba7e67b904579d98ffe
```

## 3. Cifragem (ChaCha20-Poly1305, RFC 8439)

Cada mensagem é selada com **ChaCha20-Poly1305 AEAD**, **AAD vazio**, sob a chave
de mensagem do (part, channel). O **nonce** é de 12 bytes, gerado por um CSPRNG.

O **blob de fio** é a concatenação:

```
blob = nonce(12 bytes) ‖ tag(16 bytes) ‖ ciphertext(N bytes)
```

- `nonce`: os 12 bytes de nonce usados.
- `tag`: a tag Poly1305 de 16 bytes.
- `ciphertext`: mesmo tamanho do plaintext.

Tamanho mínimo de um blob válido: 28 bytes (nonce + tag, plaintext vazio). Abrir
DEVE verificar a tag em tempo constante e falhar se ela não bater (mensagem
adulterada).

> Observação: como o AAD é vazio, a tag difere dos vetores da RFC 8439 §2.8.2
> (que autenticam 12 bytes de AAD); o *ciphertext* é idêntico. Os testes fixam a
> tag para AAD vazio.

## 4. API HTTP

Base: `/v1`. Endereços na URL DEVEM casar `^[0-9a-f]{64}$`; qualquer outra forma
responde `404`. Corpos são binários (`application/octet-stream`).

### `GET /v1/health`
Liveness. Responde `200` com JSON:
```json
{"status":"ok","ttl_buckets":[300,3600,86400,604800]}
```

### `PUT /v1/slot/<address>[?ttl=N]`
Guarda um blob no endereço (**escrita única**).
- Corpo: o blob (`nonce‖tag‖ciphertext`). Tamanho de **1 byte a 1 MiB**
  (`1048576`); fora disso → `413`.
- `ttl` (segundos, opcional) é **arredondado para cima** até o balde permitido
  mais próximo; ausente usa o padrão do servidor.
- Respostas: `201` criado · `409` endereço já ocupado (e não expirado) · `413`
  corpo vazio ou grande demais.

### `GET /v1/slot/<address>[?wait=N]`
Busca o blob.
- `wait` (segundos, opcional) faz **long-poll**: o servidor segura a requisição
  até o slot ser preenchido ou passarem `N` segundos. O servidor limita o tempo a
  **60 s** (`MAX_WAIT`).
- Respostas: `200` com o blob · `404` ausente ou expirado.

### `DELETE /v1/slot/<address>`
Remove o slot. Respostas: `204` removido · `404` ausente.

## 5. Semântica de armazenamento

- **Escrita única:** um `PUT` num endereço ocupado e não expirado é recusado
  (`409`). Um endereço cujo conteúdo já expirou PODE ser reescrito.
- **Expiração padronizada:** o `ttl` é sempre arredondado para um dos
  **baldes** `300, 3600, 86400, 604800` (5 min / 1 h / 1 dia / 1 semana), de modo
  que o único metadado temporal em repouso seja um de poucos valores grosseiros.
- **Aplicação da expiração:** a cada leitura, um slot expirado responde `404` e
  DEVE ser removido; uma varredura em segundo plano PODE limpar o restante.
- **Cegueira:** o servidor NÃO DEVE registrar corpos, peers, nem qualquer dado que
  ligue as duas parts/partes. Cabeçalhos que revelam software/versão (ex.:
  `X-Powered-By`) DEVEM ser suprimidos; `Server`/`Date` ficam a cargo da camada
  web/proxy à frente.

## 6. Fluxo típico (RPC cega)

```
Parte A (pede)                Servidor (cego)          Parte B (processa)
sela request, deriva addrR
PUT /v1/slot/<addrR>   ───────▶ guarda o blob
                                                ◀────── GET /v1/slot/<addrR>?wait
                              devolve o blob ──────────▶ abre + processa
                                                ◀────── PUT /v1/slot/<addrS>
GET /v1/slot/<addrS>?wait ────▶ devolve o blob
abre a response ◀──────────────────────────────────── (o servidor não ligou nada)
```

## 7. Segurança (resumo)

- A cegueira é sobre **conteúdo** e sobre a **ligação request↔response**, não
  sobre resistência completa a análise de tráfego: o servidor ainda vê tamanho do
  blob, o balde de TTL e o instante aproximado de escrita; um observador de rede
  vê os IPs.
- Quem tem o segredo-raiz lê e escreve em todos os channels — distribua-o por um
  canal genuinamente separado.
- O TLS é só transporte; a confidencialidade ponta a ponta vem do AEAD no cliente.
