# bddphp — Arquitetura

Como o código está organizado e por quê. Para o contrato de protocolo (formato de
fio, derivação, API), veja [`spec.md`](spec.md). Para comandos e convenções de
trabalho, veja [`CLAUDE.md`](CLAUDE.md).

## Princípios

1. **Cegueira do servidor.** O servidor guarda blobs opacos em endereços opacos e
   nunca aprende conteúdo, peers, nem a ligação request↔response. Toda a cripto e
   a derivação acontecem no cliente.
2. **Apoiar-se em primitivos auditados.** A cripto usa o que já vem no PHP —
   OpenSSL (`chacha20-poly1305`) e `hash_hkdf`. **Sem dependências de runtime**: o
   app roda de um checkout novo via `src/autoload.php`. Composer/PHPUnit são só de
   desenvolvimento.
3. **Testável sem rede.** A lógica do servidor é uma função pura de
   `(método, caminho, query, corpo)` → status, exercitável sem um contexto HTTP.

## Fronteira de confiança

```
   CLIENTE (confiável)                    SERVIDOR (não confiável, cego)
   ──────────────────                     ──────────────────────────────
   segredo-raiz (32B)                     tabela MySQL: slots(address, payload, expires_at)
   deriva endereço+chave (HKDF)           só vê: hex de 64, bytes cifrados, balde de expiração
   sela/abre (ChaCha20-Poly1305)   ──▶    PUT/GET/DELETE /v1/slot/<address>
   (único a ver plaintext)                (nunca tem o segredo nem plaintext)
```

## Componentes (`src/`, namespace `Bdd\`)

| Arquivo | Papel |
|---|---|
| `Crypto.php` | Wrappers finos: `hkdf()` (via `hash_hkdf`), `seal()/open()` (via `openssl_*`). Fixa o formato `nonce‖tag‖ciphertext`, AAD vazio. |
| `Protocol.php` | Regras compartilhadas do cliente: `slotAddress()`, `messageKey()`, `seal()`, `open()`. Define `PARTS = [request, response]` e os rótulos HKDF. |
| `Store.php` | Armazém de blobs em MySQL (PDO). `put` (escrita única via `SELECT … FOR UPDATE`), `get` (expiração preguiçosa), `getBlocking` (long-poll por polling), `delete`, `sweep`, `migrate`, `isValidAddress`. |
| `Server.php` | Roteamento/semântica HTTP, independente do contexto. `handle()` retorna o status; conhece `TTL_BUCKETS`, `MAX_WAIT`, `MAX_BLOB`, `snapTtl()`, e a página inicial de `GET /`. |
| `Responder.php` | Emite a resposta suprimindo metadados (`X-Powered-By`). Em modo "capture" grava a resposta em vez de enviar — usado nos testes. |
| `Client.php` | Cliente HTTP (extensão curl): `send`/`receive`/`waitReceive`/`purge`. Único componente que segura o segredo. `http`/`https` + `--insecure`/`--cafile`. |
| `Cli.php` + `bin/bdd` | CLI: `serve`, `migrate`, `keygen`, `send`, `recv`. Segredo via `--secret`/`BDD_SECRET`. |
| `Config.php` + `Env.php` | Config de servidor/DB a partir do ambiente ou de um `.env` **local** (nunca `~/.env`). Aceita `BDDPHP_*` ou o esquema `MYSQL_*_BDD`. |
| `autoload.php` | Carregador: prefere o Composer; senão, um PSR-4 mínimo para `Bdd\`. |

Fora de `src/`:

- **`public/index.php`** — front controller. Funciona como roteador do servidor
  embutido (`php -S … public/index.php`) e como entrada na raiz web sob
  Apache/LiteSpeed; localiza o `autoload.php` em ambos os layouts.
- **`examples/`** — clientes interoperáveis: PHP (nativo, importa o pacote),
  Python e C++ (cripto do zero). `demo.sh` roda RPCs cegas entre linguagens.
- **`docs/index.html`** — site de doc em arquivo único + derivador WebCrypto.
- **`tests/`** — PHPUnit (`CryptoTest`, `StoreTest`, `ServerTest`,
  `IntegrationTest`) + `selftest.php` autônomo.

## Decisões de porte (vs. o `bdd` original em Python)

- **Armazenamento: sistema de arquivos → MySQL.** Uma tabela
  `slots(address CHAR(64), payload LONGBLOB, expires_at BIGINT)`. A expiração é a
  coluna `expires_at` (epoch), não o mtime de um arquivo.
- **Long-poll: condvar → polling.** O original acordava leitores via
  `threading.Condition`. Sem primitivo equivalente entre conexões no MySQL,
  `getBlocking()` consulta `get()` num intervalo fixo até o deadline.
- **TLS: embutido → na frente.** O servidor embutido do PHP não faz TLS, então o
  modo canônico é HTTP atrás de um proxy reverso / serviço onion (era o modo
  `--no-tls` do original). O conteúdo já é cifrado ponta a ponta.
- **Cripto: lib auditada → primitivos do PHP.** `cryptography` (Python) →
  OpenSSL + `hash_hkdf` (PHP). O formato de fio e os rótulos são idênticos, então
  há interoperabilidade byte a byte (vetor de referência em `spec.md`).

## Escrita única e concorrência

`put()` abre uma transação, faz `SELECT expires_at … FOR UPDATE` no endereço:
- linha existente e **não expirada** → recusa (`409`);
- ausente ou **expirada** → `INSERT … ON DUPLICATE KEY UPDATE` (republica) → `201`.

O lock de linha serializa `PUT`s concorrentes no mesmo endereço, preservando a
semântica de escrita única sob carga.

## Topologia de implantação

Hospedagem compartilhada (sem processo de longa duração):

```
navegador / cliente
        │  HTTPS
        ▼
  servidor web do host (LiteSpeed)  ── TLS termina aqui
        │  .htaccess: DirectoryIndex index.html index.php
        ├── "/"        → index.html (docs estáticas)
        ├── "/v1/..."  → index.php  → Bdd\Server → Bdd\Store
        └── src/, .env → 403 (negado)
        │  PDO
        ▼
   MySQL remoto (mesma hospedagem)
```

`deploy.sh` monta esse layout (front controller + `.htaccess` + `index.html` +
`src/` + `.env` gerado + `bddphp-examples.zip`) e o espelha por FTP, lendo
credenciais da seção "BDD PHP" do `~/.env`. Detalhe do host: o domínio de preview
serve a partir do diretório de pouso do FTP (não `public_html`), então o deploy
usa `BDD_REMOTE_DIR=.`. Segredos nunca entram no repositório.

## Invariantes (não quebrar)

- O servidor permanece cego: nada de logar corpos/peers/ligações; nunca dar a ele
  o segredo ou plaintext.
- Espaço de endereço = 64 hex minúsculos; toda leitura de caminho passa por
  `Store::isValidAddress` / a regex de rota.
- O formato de fio e os rótulos HKDF são um contrato entre linguagens — mudá-los
  quebra a interoperabilidade; os testes de vetores das RFCs protegem isso.
