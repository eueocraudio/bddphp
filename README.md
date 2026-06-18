# bddphp — Blind Dead Drop (PHP + MySQL)

Um **dead drop cego**: um pequeno serviço HTTP onde duas partes trocam mensagens
através de um servidor que não aprende *nada*. O servidor só guarda blobs opacos
em endereços opacos — não consegue ler o conteúdo da mensagem, nem ligar request a
response ou uma parte à outra. Toda a confidencialidade e a impossibilidade de
correlação vivem no cliente.

Esta é uma porta em **PHP 8.4 + MySQL** do `bdd` original (em Python). O formato
de fio e os rótulos de derivação são os mesmos, então ele interopera com os
clientes de referência das outras linguagens. A criptografia do lado do cliente —
AEAD ChaCha20-Poly1305 (RFC 8439) e HKDF-SHA256 (RFC 5869) — usa os primitivos
auditados embutidos no PHP (OpenSSL e `hash_hkdf`), e o armazenamento é uma única
tabela MySQL no lugar do sistema de arquivos.

> Os clientes de exemplo em `examples/` incluem reimplementações do zero (em
> Python e C++) dos mesmos primitivos, validadas contra os vetores das RFCs, para
> mostrar que o formato de fio é um contrato entre linguagens.

📖 **Documentação completa:** abra [`docs/index.html`](docs/index.html) num
navegador — um guia com a referência de API, exemplos e uma ferramenta no
navegador que deriva um endereço de slot (e se autoverifica contra a referência).
É um único arquivo estático e funciona por `file://` ou qualquer host estático.
Também está no ar em <https://darkgoldenrod-gnat-566022.hostingersite.com/>.

🚀 **Implantar em hospedagem compartilhada:** `deploy.sh` envia o front
controller + `.htaccess` + `src/` + um `.env` gerado por FTP, lendo as
credenciais da seção "BDD PHP" do `~/.env`. Nenhum segredo fica no repositório.

## Como funciona

Duas partes compartilham um **segredo-raiz** de 32 bytes out-of-band. Um slot
lógico é um **channel** (um inteiro) que contém dois payloads: um **request** e
uma **response**. A partir do segredo, o cliente deriva — por channel e por part:

- um **endereço de slot** = `HKDF(secret, "bdd-addr|<part>|<channel>")` → 64 chars hex
- uma **chave de mensagem** = `HKDF(secret, "bdd-key|<part>|<channel>")`

O cliente cifra com ChaCha20-Poly1305 e guarda `nonce || tag || ciphertext` no
endereço derivado. Request e response usam rótulos diferentes, então caem em
endereços de aparência não-relacionada sob chaves não-relacionadas. O servidor só
vê endereços e ciphertext aleatórios.

## Instalação

```bash
./install.sh          # checa PHP/extensões, instala deps de dev, escreve .env, roda os testes
```

Requer PHP **8.4+** com as extensões `openssl`, `pdo_mysql`, `hash` e `curl`, mais
MySQL/MariaDB. O Composer é opcional (só para os testes; o app em si roda de um
checkout novo, sem `composer install`). Depois, crie o schema (importe
`schema.sql` na sua ferramenta de banco, ou):

```bash
bin/bdd migrate       # CREATE TABLE IF NOT EXISTS usando o banco configurado
```

A configuração vem de um `.env` local do projeto (veja `.env.example`) — defina
`BDDPHP_DSN`/`BDDPHP_DB_USER`/`BDDPHP_DB_PASS` ou as peças `MYSQL_*_BDD`.

## Endpoints

```
GET    /v1/health                  -> {"status":"ok","ttl_buckets":[...]}
PUT    /v1/slot/<address>[?ttl=N]   corpo: blob  -> 201 created / 409 occupied (write-once)
GET    /v1/slot/<address>[?wait=N]              -> 200 blob / 404
DELETE /v1/slot/<address>                       -> 204 / 404
```

O `<address>` é sempre 64 chars hex minúsculos (tamanho de SHA256); qualquer
outra forma é `404`. O corpo de um `PUT` vai de 1 byte até um teto de **1 MiB**
(vazio/inválido ou acima do teto → `413`). O servidor não loga peers nem
conteúdo; o que ele inevitavelmente observa é o tamanho do blob e o instante de
escrita (mitigado pelos baldes de TTL).

### Expiração (padronizada)

Toda entrada expira. O `?ttl=N` (segundos) pedido num `PUT` é **arredondado para
cima até o balde permitido mais próximo** — `300, 3600, 86400, 604800` (5 min /
1 h / 1 dia / 1 semana) — então o único metadado temporal armazenado é um de uns
poucos valores grosseiros. A expiração é aplicada com precisão em toda leitura
(um slot expirado é lido como `404` e apagado na hora). Os baldes são anunciados
em `/v1/health`.

## Início rápido (local)

```bash
# 1. Rode o servidor de dev (servidor embutido do PHP; HTTP apenas)
bin/bdd serve --port 8080

# 2. Um segredo compartilhado para as duas partes
export BDD_SECRET=$(bin/bdd keygen)

# 3. Depositar um request e uma response no channel 0
bin/bdd send --part request  --channel 0 --message 'ping?' --port 8080
bin/bdd send --part response --channel 0 --message 'pong!' --port 8080

# 4. Lê-los de volta
bin/bdd recv --part request  --channel 0 --port 8080
bin/bdd recv --part response --channel 0 --port 8080

# Ou bloquear até aparecer uma mensagem (long poll do servidor)
bin/bdd recv --part response --channel 0 --wait --timeout 60 --port 8080
```

`--wait` usa um **long poll do lado do servidor**: o `GET` é mantido aberto até
uma mensagem ser guardada naquele slot (um `PUT` o acorda imediatamente) ou a
espera expirar (teto de 60s no servidor). O código de saída é `2` no timeout.

## Segurança de transporte

O servidor embutido (`serve`) é **HTTP apenas** — o PHP não envolve TLS ali. É de
propósito: este serviço roda atrás de um proxy reverso ou de um serviço onion Tor
que fornece o transporte seguro. O conteúdo já é cifrado de ponta a ponta pelo
cliente, então HTTP entre o proxy e o app está ok. O cliente aceita
`--scheme https` com `--cafile` (ou `--insecure` para dev) ao falar com tal
frente — por exemplo, o site de produção.

## Implantação (hospedagem compartilhada)

`deploy.sh` espelha um layout `public_html` (front controller + `.htaccess` +
`src/` + `docs/index.html` + um `.env` gerado) para o host por FTP, lendo as
credenciais da seção "BDD PHP" do `~/.env`. Nunca guarda segredos no repositório.

```bash
./deploy.sh --dry-run    # monta e inspeciona a árvore de staging, não envia nada
./deploy.sh              # monta e envia
```

Em hospedagem compartilhada não há processo de longa duração: o servidor web do
host roda o front controller a cada requisição, e o `.htaccess` roteia `/v1/...`
até ele (e serve `docs/index.html` na raiz). Importe `schema.sql` uma vez pela
ferramenta de banco do host (ex.: phpMyAdmin).

## Exemplos

Clientes em **PHP** (nativo, usa o pacote), **Python** e **C++** (do zero) em
`examples/`, todos interoperáveis. `bash examples/demo.sh` roda três RPCs cegas
entre linguagens. Veja [`examples/README.md`](examples/README.md).

## Testes

```bash
composer test          # PHPUnit (precisa de um banco de teste acessível; veja phpunit.xml)
php tests/selftest.php  # vetores RFC de cripto/protocolo, sem banco
```
