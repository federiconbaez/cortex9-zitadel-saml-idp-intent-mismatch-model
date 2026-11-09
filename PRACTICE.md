# Guía práctica (7 niveles)

Ejercicios **offline y locales** sobre el modelo. No hace falta ZITADEL ni
red. Cada respuesta está comprobada en `tests/model_test.go`
(`TestPracticeLevels`).

**Alcance:** practica solo en tu propia máquina, en un laboratorio propio
(VM o contenedor local con tu propia instancia de ZITADEL y tus propios IdPs
de prueba) o en máquinas de HTB/plataformas de práctica donde tengas
autorización expresa. Nunca contra instancias, organizaciones, IdPs o
usuarios de terceros.

Comando:
`go run ./src/cmd/samlmodel case pre|post acs|slo <url_idp> <estado_idp> <firmante> <sp> intent|other <name_id> [shared]`

**Básico**

1. **Login legítimo.** URL `idp-b`, intent `idp-b`, firmado por B para el
   SP de B. ¿Qué usuario sale? (`SESSION`, `user-victim`)
2. **La confusión.** URL `idp-a`, intent `idp-b`, firmado por A para el SP
   de A, InResponseTo copiado, `victim-external-id`, en `pre`. ¿Con qué IdP
   se verificó y bajo cuál se resolvió el usuario? (`CONFUSED_SESSION`;
   verifica A, resuelve B; diff:9-11)

**Intermedio**

3. **¿Por qué copiar InResponseTo?** El mismo caso con `other`. (`pre` =
   `REJECT_REQUEST_ID`; diff:17, 183-185, 214-216)
4. **El fix.** El caso del nivel 2 en `post`. ¿Qué línea lo corta?
   (`REJECT_IDP_MISMATCH`, diff:12-15 y 42-47)
5. **SLO.** URL A, estado de logout B en `pre`. (`CONFUSED_LOGOUT`; el fix
   lo corta en diff:27-30, antes de `getProvider` en diff:32)

**Avanzado**

6. **IDs vacíos.** ¿`checkSAMLIntentIDP("", "")` pasa? ¿Por qué el test
   del diff lo exige y qué lo frena después en el modelo? (pasa,
   diff:93-102; luego `REJECT_PROVIDER`)
7. **Clave compartida.** URL B, intent B, firmado con la clave compartida
   para el SP de B, en `post`. ¿Por qué el fix no cambia nada y qué
   tendrías que revisar en tu propio laboratorio? (`SESSION`; es
   reutilización de clave, no confusión de IdP)

**Defensa propia:** en tu propio laboratorio, escribí un test que, para
cada callback SAML, compare el IdP de la URL con el IdP del estado del
servidor *antes* de verificar firma o crear sesión, y que pase el barrido
de `results/sweep.csv` sin ningún `CONFUSED_*`. Agregá un caso a
`fixtures/cases.tsv` con su etiqueta a mano, regenerá
`fixtures/expected.tsv` con `scripts/derive_expected.py` y comprobá que todo
coincide.
