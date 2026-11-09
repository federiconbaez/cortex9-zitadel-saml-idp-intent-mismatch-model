# cortex9-zitadel-saml-idp-intent-mismatch-model

Modelo offline de **CVE-2026-109372** (GHSA-65fv-6pff-4q47, advisory del
repo GHSA-x4c7-fpcx-w9q6): confusión de proveedor de identidad SAML en los
callbacks de **intent** de ZITADEL. El handler ACS verificaba la respuesta
SAML con el proveedor nombrado en la URL (`/idps/<id>/saml/acs`) pero
resolvía el usuario bajo el IdP del intent obtenido por el RelayState, sin
comparar ambos. Corregido en 4.19.2 por el commit
[450c0560bc83](https://github.com/zitadel/zitadel/commit/450c0560bc832760e58ac9b1dee21bec1ae1d4e7)
(`pre` = antes, `post` = después), que agrega `checkSAMLIntentIDP` en ACS y
SLO.

Educativo, determinista, solo biblioteca estándar de Go (más un control
cruzado en Python 3 stdlib). No se importa ni se ejecuta código de ZITADEL,
no se parsea XML, no se firma nada y no se abre ningún socket. Claves e IdPs
son cadenas simbólicas.

Inglés: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## Qué se modela

`diff:N` es la línea N del diff guardado (ver [SOURCES.md](SOURCES.md)). Un
`*` en la columna `diff_lines` indica un paso reconstruido (desde
comentarios del diff, el test de integración o el advisory), no código que
aparezca en el diff.

1. Estado por RelayState (intent en ACS, estado de logout en SLO): antes de
   diff:9 / diff:23 (reconstruido).
2. Proveedor según la URL (`data.IDPID`): en ACS antes de diff:9 (se usa en
   diff:17); en SLO es `getProvider` en diff:32.
3. **Compuerta (solo post)** `checkSAMLIntentIDP`, comparación exacta de
   bytes (diff:42-47): en ACS en diff:12-15, *después* del proveedor; en SLO
   en diff:27-30, *antes* de `getProvider`.
4. Firma con la clave del IdP de la URL y Destination/Audience del SP de ese
   IdP: `saml2.NewSession`, diff:17 (reconstruido; comentarios del test en
   diff:146-148).
5. `InResponseTo == intent.RequestID`: diff:17, 183-185, 214-216 (solo ACS).
6. Usuario resuelto bajo el IdP **del intent**: diff:9-11 (`checkExternalUser`
   en diff:49, reconstruido).

Instancia fija: `idp-a` (atacante), `idp-b` (víctima, vinculada a
`victim-external-id` como en diff:143-151), `idp-c` (`carol-ext`).

## Evidencia diferencial

| Caso | pre | post |
|---|---|---|
| `p01` URL `idp-a`, intent `idp-b`, firmado por A para el SP de A | `CONFUSED_SESSION` como `user-victim` | `REJECT_IDP_MISMATCH` |
| `p05` SLO, URL A, estado B | `CONFUSED_LOGOUT` | `REJECT_IDP_MISMATCH` |
| `a03` sin copiar InResponseTo | `REJECT_REQUEST_ID` | `REJECT_IDP_MISMATCH` |
| `a06` clave compartida, respuesta para el SP de B | `SESSION` | `SESSION` (fuera del fix) |
| `n01`-`n07` legítimos o inválidos | sin cambio | sin cambio |

Barrido de 5.400 casos: `post` nunca da un resultado confundido; `pre` se
confunde en 324 casos, todos con IdP de URL ≠ IdP del estado; con IdPs
iguales el fix no cambia nada; `post` rechaza 2.700 casos por
`REJECT_IDP_MISMATCH`.

**Bordes del modelo, no hallazgos:** dos IDs vacíos pasan la compuerta (lo
exige el test del diff, diff:93-102); con clave compartida entre IdPs
(`a06`) el fix no aplica.

## Uso

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/derive_expected.py sweep | diff - results/sweep.csv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
```

Ver [LIMITATIONS.md](LIMITATIONS.md) y [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.
