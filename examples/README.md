# Exemplos

Clientes de exemplo em **PHP**, **Python** e **C++** que falam com o servidor
bddphp (Blind Dead Drop). Cada um implementa o mesmo protocolo, então todos
interoperam — uma mensagem selada por um pode ser aberta por qualquer outro:

- **derivação de endereço/chave**: HKDF-SHA256 sobre `bdd-{addr,key}|<part>|<channel>`
- **cifragem**: AEAD ChaCha20-Poly1305, blob de fio `nonce(12) || tag(16) || ciphertext`
- **transporte**: HTTP para `PUT/GET /v1/slot/<address>`, com long-poll `?wait=N`

O exemplo **PHP é o cliente nativo**: importa `Bdd\Client` do pacote, então
compartilha a cripto auditada (OpenSSL `chacha20-poly1305` + `hash_hkdf`) com o
servidor. Os exemplos **Python e C++ reimplementam à mão** o ChaCha20-Poly1305 e
o HKDF do zero, para mostrar que o formato de fio e os labels de derivação são um
contrato entre linguagens. Os três produzem os mesmos bytes; os feitos à mão são
validados contra os vetores das RFC 8439 / RFC 5869.

> ⚠️ A cripto feita à mão nos exemplos Python/C++ é educacional — não é
> constant-time, não é auditada. Para uso real, apoie-se numa biblioteca
> auditada (o pacote PHP faz isso via OpenSSL/`hash_hkdf`).

## Rodar a demo entre linguagens

`demo.sh` sobe um servidor bddphp e roda três **RPCs cegos** onde o solicitante e
o trabalhador são linguagens diferentes: cada trabalhador espera um request, o
*processa* (coloca em maiúsculas, fazendo as vezes de trabalho real) e posta a
response — tudo enquanto o servidor só vê blobs opacos.

```bash
bash examples/demo.sh
```

```
== Exchange 1 — Python asks, C++ processes (channel 1) ==
  Python -> request : 'hello from python'
  Python <- response: 'HELLO FROM PYTHON'  (computado pelo C++)

== Exchange 2 — C++ asks, Python processes (channel 2) ==
  C++ -> request : 'hello from c++'
  C++ <- response: 'HELLO FROM C++'  (computado pelo Python)
```

Ele compila o cliente C++ automaticamente e pula a etapa PHP graciosamente se não
houver runtime `php`. A demo só precisa de um `php` local — **sem banco de
dados**; o servidor grava os blobs em `./data` (sobrescreva o local com
`BDDPHP_DATA_DIR`).

## Preparação compartilhada (manual)

```bash
# a partir da raiz do repo
bin/bdd serve --port 8080 &                  # servidor HTTP local (cria ./data sozinho)
export BDD_SECRET=$(bin/bdd keygen)
```

Todo exemplo aceita os mesmos comandos, cada um seguido de `CHANNEL` (e `MSG`
para envios): `send-request`, `get-request`, `send-response`, `get-response`,
`wait-response` (long-poll) e `reply-upper` (trabalhador: long-poll de um
request, coloca em maiúsculas, responde). Mais `--host`, `--port`,
`--scheme http|https`, `--secret` (ou `BDD_SECRET`), e `--insecure` (pula a
verificação TLS quando `--scheme https` aponta para um proxy de dev).

> O servidor bddphp embutido é **HTTP** (o `php -S` não faz TLS). Use
> `--scheme https` apenas ao falar com um proxy reverso / serviço onion que
> termina TLS na frente — por exemplo o site de produção.

## PHP (nativo) — `php/example.php`

Usa o pacote bddphp diretamente. Sem etapa de build.

```bash
php examples/php/example.php --port 8080 send-request 0 "ola do PHP"
php examples/php/example.php --port 8080 get-request 0
```

## Python (do zero) — `python/example.py`

Cripto totalmente do zero, só com a biblioteca padrão. Sem etapa de build.

```bash
python3 examples/python/selftest.py          # vetores RFC 8439 / 5869
python3 examples/python/example.py --port 8080 send-request 0 "ola do Python"
python3 examples/python/example.py --port 8080 wait-response 0
```

## C++ (do zero) — `cpp/`

Cripto totalmente do zero (`bdd_crypto.hpp`). O transporte delega para a CLI
`curl` (`bdd_client.hpp`); um cliente de produção vincularia a libcurl.

```bash
cd examples/cpp && make          # compila example + selftest
./selftest                       # vetores RFC 8439 / 5869
./example --port 8080 send-request 0 "ola do C++"
./example --port 8080 wait-response 0
```

## Falando com produção

Os exemplos também alcançam o site implantado (que termina TLS):

```bash
php examples/php/example.php \
    --host darkgoldenrod-gnat-566022.hostingersite.com --port 443 --scheme https \
    send-request 0 "ola da produção"
```
