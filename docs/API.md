# API de CulinaryServer

Contrato entre el Worker y sus dos únicos clientes:

- **Culinary Restaurant** (servidor de sucursal en CulinaryOS): rutas `/branch/v1/*`.
- **CulinaryAdmin** (panel del proveedor): rutas `/admin/v1/*`.

Cualquier otra ruta responde `404`. Todas las respuestas llevan `Cache-Control: no-store`.

## 1. Convenciones

| Concepto | Formato |
|---|---|
| Cuerpos | JSON UTF-8, `Content-Type: application/json`, máximo 64 KiB (salvo las partes de paquetes). Los objetos son estrictos: un campo desconocido da `400`. |
| Fechas | ISO 8601 en UTC con milisegundos, por ejemplo `2026-10-24T15:04:05.123Z`. |
| base64url | RFC 4648 §5, **sin relleno** `=`. |
| Llave pública | SubjectPublicKeyInfo DER en base64url (`spki`). Ed25519 mide 44 bytes; P-256, 91. |
| Algoritmos de llave | `Ed25519` o `ES256` (ECDSA P-256 con SHA-256). |
| Firma Ed25519 | 64 bytes (RFC 8032). |
| Firma ES256 | 64 bytes **r ‖ s** (IEEE P1363), no DER. En .NET: `ECDsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)`. Un TPM entrega r y s por separado: rellena cada uno a 32 bytes y concaténalos. |
| SHA-256 / SHA-512 | Hexadecimal en minúsculas. |
| Identificadores | `licenseId`, `ticketId`, `releaseId`, etc. son UUID en minúsculas. |

### Errores

```json
{ "error": { "code": "license_expired", "message": "Licencia vencida", "notice": "<JWS opcional>" } }
```

| HTTP | `code` | Cuándo |
|---|---|---|
| 400 | `bad_request` | JSON inválido, campo faltante, desconocido o fuera de rango. `message` indica el campo. |
| 401 | `unauthorized` | Falta la firma, el reto ya se usó o venció, la firma no corresponde, o la sesión del panel no es válida. |
| 403 | `forbidden` | Código de alta o invitación inválidos. |
| 403 | `activation_rejected` | Código de activación inválido, ya usado o licencia revocada. |
| 403 | `license_expired` | Licencia vencida. Incluye `notice`. |
| 403 | `license_revoked` | Licencia revocada. Incluye `notice`. |
| 403 | `binding_mismatch` | La huella de hardware no coincide con la del equipo activado. |
| 403 | `license_transferred` | La firma es de un equipo ya liberado. Trae un aviso firmado con `status: "transferred"`, y la sucursal se bloquea. |
| 404 | `not_found` | Ruta o registro inexistente. |
| 409 | `conflict` | Estado incompatible (siteId repetido, versión repetida, licencia revocada, etc.). |
| 413 | `too_large` | Cuerpo mayor al límite. |
| 416 | `range_not_satisfiable` | Cabecera `Range` inválida o con varios rangos en una descarga. |
| 429 | `rate_limited` | Demasiados tickets abiertos o cuenta del panel bloqueada. |
| 500 | `internal` | Error no previsto. |
| 503 | `server_misconfigured` | Falta o es inválido `ROOT_PUBLIC_SPKI`, `LICENSE_SIGNING_KEY`, `LICENSE_SIGNING_CHAIN`, `CHALLENGE_KEY` o `KEY_FLOOR`, o la intermedia de licencias venció o quedó bajo el piso de llaves. |

## 2. Solicitudes firmadas con reto

Las usan la sucursal (después de activar) y el panel para confirmar el alta e iniciar sesión.

### 2.1 Pedir el reto

`POST /branch/v1/challenges` con `{ "licenseId": "<uuid>" }`, o `POST /admin/v1/challenges` con `{ "username": "<usuario>" }`.

```json
{ "nonce": "AAABmhQ3...base64url de 56 bytes", "expiresAt": "2026-10-24T15:06:05.123Z" }
```

- Vale **2 minutos**, **una sola vez**, y solo para el `scope` y el `subject` con que se pidió. Se consume en cuanto el Worker lo recibe, aunque la firma falle. Pide uno nuevo por cada solicitud firmada.
- Trátalo como texto opaco. Pedir retos no guarda nada en el servidor, así que pedir muchos no bloquea a nadie, y la respuesta es igual exista o no la licencia o el usuario.

### 2.2 Firmar

Cadena a firmar: siete líneas unidas con `\n` (LF, sin salto final), codificadas en UTF-8:

```
culinary-request-v1
<scope>              branch | admin
<MÉTODO>             en mayúsculas: GET, POST, PUT
<ruta>               ruta absoluta con la query tal como se envía, sin host: /branch/v1/license/renew
<subject>            licenseId (sucursal) o username (panel)
<nonce>              el nonce del reto
<sha256(cuerpo)>     SHA-256 en hex de los bytes exactos del cuerpo; sin cuerpo, el de la cadena vacía
```

SHA-256 de la cadena vacía: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Cabeceras:

| Cabecera | Valor |
|---|---|
| `X-Culinary-Subject` | `licenseId` o `username` |
| `X-Culinary-Challenge` | `nonce` |
| `X-Culinary-Signature` | firma en base64url |

Ejemplo en C# para la sucursal:

```csharp
var body = JsonSerializer.SerializeToUtf8Bytes(payload);           // estos mismos bytes van en la solicitud
var bodyHash = Convert.ToHexStringLower(SHA256.HashData(body));
var input = Encoding.UTF8.GetBytes(string.Join("\n",
    "culinary-request-v1", "branch", "POST", "/branch/v1/license/renew", licenseId, nonce, bodyHash));
var signature = key.Sign(input);                                   // Ed25519 o ES256 P1363
request.Headers.Add("X-Culinary-Subject", licenseId);
request.Headers.Add("X-Culinary-Challenge", nonce);
request.Headers.Add("X-Culinary-Signature", Base64Url.EncodeToString(signature));
```

## 3. Documentos firmados por la raíz

Los documentos se firman con Ed25519 en formato **JWS compacto** (RFC 7515, `alg` `EdDSA` de RFC 8037):

```
base64url(header) "." base64url(payload) "." base64url(firma)
header = { "alg": "EdDSA", "typ": "<tipo>", "kid": "<16 caracteres>" }
```

La firma cubre los bytes ASCII de `base64url(header) + "." + base64url(payload)`. No hay que canonicalizar JSON: se verifica sobre lo recibido.

| `typ` | Contenido |
|---|---|
| `culinary-license+jws` | Licencia de uso (sección 4.3). |
| `culinary-license-status+jws` | Aviso de vencimiento o revocación (sección 4.4). |
| `culinary-release+jws` | Manifiesto de un paquete, independiente de la licencia (sección 4.5). |
| `culinary-update+jws` | Actualización dirigida a una licencia (sección 4.5). |
| `culinary-intermediate+jws` | Certificado de una llave intermedia, firmado por la raíz: `kid`, `key` (32 bytes base64url), `uses` (tipos que puede firmar), `generation`, `nbf`, `exp`. |
| `culinary-key-floor+jws` | Piso de llaves, firmado por la raíz: `license` y `release`, la generación mínima vigente de cada intermedia. |

La raíz sólo firma intermedias y el piso de llaves. Los demás documentos los firma una intermedia y llevan su certificado en el encabezado: `{ "alg": "EdDSA", "typ", "kid": <kid de la intermedia>, "chain": <JWS culinary-intermediate+jws> }`. Los documentos que la raíz firmó antes de las intermedias no traen `chain` y siguen valiendo.

Al verificar, la sucursal debe:

1. Verificar la firma con la llave pública raíz **aprovisionada en el equipo**, nunca con una recibida por red. El panel la muestra en `GET /admin/v1/root-key`; `kid` sirve solo para detectar una raíz distinta. Con `chain`: verificar el certificado con la raíz, que su `kid` sea el SHA-256 de `key` y el del encabezado, que `uses` incluya el `typ`, que `generation` no esté bajo el piso de llaves guardado y que el `iat` del documento caiga entre `nbf` y `exp`; después verificar el documento con `key`.
2. Comprobar que `alg` es `EdDSA` y que `typ` es el esperado para ese uso. Un documento de un tipo no vale como otro.
3. Rechazar un payload con `v` distinto de `1`.

## 4. Culinary Restaurant (`/branch/v1`)

### 4.1 Huella de hardware

Solo cuando el equipo no tiene TPM 2.0. Cada parte se envía como `sha256hex` de la cadena indicada, en UTF-8:

| Campo | Cadena de entrada |
|---|---|
| `board` | `culinary-hw-v1|board|` + UUID de la placa (`/sys/class/dmi/id/product_uuid`) en minúsculas |
| `disk` | `culinary-hw-v1|disk|` + número de serie del disco del sistema, sin espacios al inicio ni al final |
| `mac` | `culinary-hw-v1|mac|` + MAC de la interfaz física principal en minúsculas, con `:` |

En la renovación deben coincidir **al menos dos de las tres**, así que cambiar un disco o una tarjeta de red no bloquea la sucursal. Si cambian dos, el proveedor libera el equipo desde el panel (sección 5.3).

### 4.2 Activación

La primera vez, con el código que entrega el panel. La sucursal genera su llave de licencia:

- **Con TPM 2.0:** llave ECC P-256 no exportable dentro del TPM (`alg: "ES256"`, `binding.kind: "tpm"`). `tpm` con `Ed25519` da `400`.
- **Sin TPM:** llave Ed25519 (o P-256) guardada cifrada en el almacén (`binding.kind: "fingerprint"`).

1. `POST /branch/v1/challenges` → `nonce`.
2. `POST /branch/v1/activate`, firmada (sección 2) con la llave nueva. `X-Culinary-Subject` es el `licenseId`.

```json
{
  "activationCode": "K7Q2M-9XWZT-4HPLA-R3VNE",
  "siteId": "plaza-centro",
  "key": { "alg": "ES256", "spki": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..." },
  "binding": { "kind": "tpm" }
}
```

Sin TPM: `"binding": { "kind": "fingerprint", "fingerprint": { "board": "<hex64>", "disk": "<hex64>", "mac": "<hex64>" } }`.

El código no distingue mayúsculas, guiones ni espacios. Respuesta `200`:

```json
{ "license": "<JWS culinary-license+jws>", "keyFloor": "<JWS culinary-key-floor+jws>" | null }
```

El código sirve una sola vez. El plazo de la prueba, mensual o anual empieza en este momento, salvo que el panel haya fijado `expiresAt` antes. Si la activación se rechaza (licencia vencida, `503`), el código no se gasta y la llave no queda ligada. Lo mismo si `siteId` no es el de la licencia: `409 site_mismatch`, con el siteId esperado en el mensaje.

### 4.3 Licencia de uso

Payload de `culinary-license+jws`:

```json
{
  "v": 1,
  "licenseId": "0b6c5c1e-3f0a-4d39-9f5e-1d2a8f3c7b10",
  "revision": 4,
  "tenantId": "grupo-plaza",
  "siteId": "plaza-centro",
  "customer": "Restaurante La Plaza",
  "branchName": "Centro",
  "plan": "monthly",
  "tier": "pro",
  "addons": ["deliveryHub", "webOrdering"],
  "status": "active",
  "features": ["printing", "reservations"],
  "limits": { "maxUsers": 15, "maxTables": 30, "maxTerminals": 10 },
  "activatedAt": "2026-10-24T15:04:05.123Z",
  "expiresAt": "2026-11-24T15:04:05.123Z",
  "validatedAt": "2026-10-25T09:00:00.000Z",
  "offlineUntil": "2026-11-01T09:00:00.000Z",
  "key": { "alg": "ES256", "spki": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..." },
  "binding": "tpm",
  "iat": "2026-10-25T09:00:00.000Z"
}
```

| Campo | Significado |
|---|---|
| `plan` | Periodo de cobro: `trial`, `monthly`, `annual` o `permanent`. |
| `tier` | Nivel comercial, independiente del periodo: `lite` o `pro`. Pro incluye reservaciones y zonas avanzadas. |
| `addons` | Subconjunto de `mobileOrdering` (comanderos móviles ilimitados), `deliveryHub` (UberEats, Rappi, DiDi Food) y `webOrdering` (web propia con menú QR). Los timbres fiscales se cobran por uso y no van en la licencia. |
| `expiresAt` | Fin del plazo pagado; `null` en `permanent`. |
| `validatedAt` | Última vez que el Worker validó la licencia. |
| `offlineUntil` | `validatedAt` + 7 días: gracia cuando el servicio no responde. |
| `features` | Subconjunto de `reservations`, `reviews`, `customerRequests`, `printing`, `courses`, `promotions`, `multiBranch` (igual a `Restaurant.Modules`). |
| `limits` | `maxUsers` y `maxTables`, de 1 a 10000, y `maxTerminals`: terminales fijas simultáneas (los comanderos móviles no cuentan). Si el panel no lo fija, sigue al nivel: 2 en Lite y 10 en Pro. |
| `key` | Llave de la licencia: la sucursal debe tener su privada. Certificada por la intermedia de licencias junto con el resto. |
| `revision` | Sube con cada cambio del panel. La sucursal rechaza una licencia con revisión menor a la guardada. |

Reglas que la sucursal hace cumplir del lado de su servidor:

- `siteId` debe ser el de la sucursal y `key.spki` el de su propia llave.
- Licencia usable mientras `ahora < offlineUntil` **y** (`expiresAt` es `null` **o** `ahora < expiresAt`).
- Si no es usable: pantalla de bloqueo con `plan` y `expiresAt`, sin exportar datos.
- Renovar al menos una vez al día mientras haya conexión.

### 4.4 Renovación

`POST /branch/v1/license/renew`, firmada con la llave de la licencia.

```json
{ "fingerprint": { "board": "<hex64>", "disk": "<hex64>", "mac": "<hex64>" } }
```

Con TPM, cuerpo `{}`. Respuesta `200`: `{ "license": "<JWS culinary-license+jws>", "keyFloor" }` con `validatedAt` nuevo. La sucursal guarda el piso de llaves más alto que reciba.

Una licencia vencida o revocada no se renueva: `403` con `code` `license_expired` o `license_revoked` y `notice`, un JWS `culinary-license-status+jws`:

```json
{
  "v": 1,
  "licenseId": "0b6c5c1e-3f0a-4d39-9f5e-1d2a8f3c7b10",
  "revision": 5,
  "siteId": "plaza-centro",
  "status": "expired",
  "plan": "monthly",
  "expiresAt": "2026-11-24T15:04:05.123Z",
  "revokedAt": null,
  "challenge": "<el nonce de la solicitud que recibió este aviso>",
  "iat": "2026-11-25T08:00:00.000Z"
}
```

La sucursal se bloquea de inmediato, sin esperar a que acabe la gracia, solo si el aviso pasa la verificación de la sección 3, trae su `licenseId` y su `siteId`, su `challenge` es el nonce que ella misma envió en esa solicitud y su `revision` no es menor que la guardada. Así un aviso viejo no se puede reenviar después de una renovación. Un `403` sin `notice` válido no bloquea por sí solo: puede venir de un intermediario.

Todas las rutas firmadas de la sucursal que rechazan una licencia vencida o revocada (renovación, actualizaciones, soporte, registro) responden con el mismo `notice`.

Otros errores: `401` (firma o reto), `403 binding_mismatch`, `409 conflict` si la licencia cambió durante la renovación (reintenta con un reto nuevo).

### 4.5 Actualizaciones

**Consultar**: `POST /branch/v1/updates/check`, firmada. Solo con licencia activa.

```json
{ "platform": "linux-x64", "currentVersion": "1.3.2" }
```

`platform`: `linux-x64`, `win-x64` o `android-arm64`. Si no hay nada más nuevo para esta licencia: `{ "update": null }`. Si hay:

```json
{
  "update": "<JWS culinary-update+jws>",
  "release": "<JWS culinary-release+jws>",
  "keyFloor": "<JWS culinary-key-floor+jws>" | null,
  "download": {
    "path": "/branch/v1/downloads/5f1d0c9a-6a7e-4b1e-8d0b-2b7c1e9f4a33",
    "token": "<base64url>",
    "expiresAt": "2026-10-25T10:00:00.000Z"
  }
}
```

La autorización (`update`, intermedia de licencias) y el manifiesto (`release`, intermedia de paquetes) se verifican por separado y deben coincidir en `releaseId`, `version`, `platform`, `filename`, `bytes` y `sha512`; así el Worker por sí solo no puede autorizar otros bytes.

Payload de `culinary-update+jws`:

```json
{
  "v": 1,
  "licenseId": "0b6c5c1e-3f0a-4d39-9f5e-1d2a8f3c7b10",
  "siteId": "plaza-centro",
  "releaseId": "5f1d0c9a-6a7e-4b1e-8d0b-2b7c1e9f4a33",
  "version": "1.4.0",
  "platform": "linux-x64",
  "filename": "culinary-1.4.0.deb",
  "bytes": 48213004,
  "sha512": "<hex128>",
  "notes": "Corrige impresión",
  "iat": "2026-10-25T09:00:00.000Z",
  "exp": "2026-10-25T10:00:00.000Z"
}
```

El payload de `culinary-release+jws` lleva `v`, `releaseId`, `version`, `platform`, `filename`, `bytes`, `sha512` e `iat`.

**Descargar**: `GET <download.path>` con `Authorization: Bearer <download.token>`. No lleva firma de reto, así que se puede reanudar con `Range: bytes=<inicio>-<fin>` (`206` con `Content-Range`; un rango inválido da `416`) durante la hora que vale el permiso.

Antes de instalar, la sucursal comprueba:

1. `update` y `release` pasan la verificación de la sección 3. `update` tiene `typ` `culinary-update+jws`, con su `licenseId` y su `siteId`, y `exp` sin vencer.
2. La versión es mayor que la instalada.
3. El tamaño y el SHA-512 del archivo descargado coinciden con `bytes` y `sha512`.

Sin pedir permiso de descarga, `POST /branch/v1/updates/latest` (solicitud firmada, cuerpo `{}`) responde `{ "releases": { "linux-x64": { "version", "notes" }, ... } }`: la versión más nueva publicada a esa licencia por plataforma, sin importar la instalada. Culinary Restaurant la consulta cada 15 minutos para avisar a sus gerentes.

### 4.6 Soporte

Firmadas con la llave de la licencia. Se permiten con licencia vencida (para pedir la renovación), no con revocada.

| Método y ruta | Cuerpo | Respuesta |
|---|---|---|
| `POST /branch/v1/tickets` | `{ "subject": "≤150", "message": "≤4000" }` | `201 { "ticket": Ticket }` |
| `GET /branch/v1/tickets` | sin cuerpo | `200 { "tickets": [Ticket] }`, los 50 más recientes |
| `POST /branch/v1/tickets/{id}/messages` | `{ "message": "≤4000" }` | `201 { "ticket": Ticket }` |

```json
{
  "id": "c2f5...", "licenseId": "0b6c...", "subject": "No imprime",
  "status": "answered",
  "createdAt": "...", "updatedAt": "...",
  "messages": [
    { "id": "...", "author": "branch", "adminId": null, "body": "La impresora de cocina no responde", "createdAt": "..." },
    { "id": "...", "author": "admin", "adminId": "9a1e...", "body": "Reinicia el servicio de impresión", "createdAt": "..." }
  ]
}
```

`status`: `open` (espera al proveedor), `answered` (respondió el proveedor), `closed`. Un mensaje de la sucursal lo vuelve a `open`. Límites: 20 tickets no cerrados por licencia, 100 mensajes por ticket.

### 4.7 Registro para la central multiempresa

`PUT /branch/v1/registry`, firmada. Registra la huella SHA-256 del certificado cliente mTLS que la sucursal usa contra `MesaNexo.Central` (puertos `/v1/events`, `/v1/cloud/*`).

```json
{ "centralCertificateSha256": "<hex64>" }
```

Respuesta `200`: `{ "siteId": "...", "tenantId": "...", "centralCertificateSha256": "..." }`. `409` si otra sucursal ya registró ese certificado. Liberar el equipo desde el panel borra el registro.

### 4.8 Fallos

`POST /branch/v1/faults` (solicitud firmada; funciona con la licencia vencida) con `{ "faults": [Fault] }`, de 1 a 20. Responde `{ "received": n }`. La sucursal quita de cada texto lo que no debe salir de ella (contraseñas, tokens, correos, números largos, cadenas de consulta) antes de enviarlo.

| Campo | Contenido |
|---|---|
| `fingerprint` | SHA-256 en hexadecimal: identifica el fallo dentro de la licencia |
| `source` | `api`, `worker`, `client`, `web` o `kiosk` |
| `severity` | `error` o `critical` |
| `what` | Qué falló, ≤300 |
| `affected` | Qué afectó, ≤300 |
| `detail` | Traza o salida de la aplicación, ≤8000 |
| `context` | Hasta 16 pares de texto: ruta, operación, pantalla, rol, sistema |
| `version`, `platform` | ≤32 |
| `occurrences` | Veces que ocurrió desde el último envío |
| `firstAt`, `lastAt` | ISO 8601 |

Repetir `fingerprint` suma `occurrences`, actualiza `detail`, `context` y `version`, y reabre el fallo si estaba resuelto. Con 500 fallos abiertos en una licencia, los conocidos se siguen contando y los nuevos se descartan.

### 4.9 Resúmenes del panel del propietario

`POST /branch/v1/stats`, firmada como las demás. El contrato y las fórmulas están en `docs/METRICAS-PANEL.md` del repositorio de la sucursal. Cuerpo de hasta 2 MiB y 10 días, y sólo con licencia utilizable: una vencida o revocada recibe `403` con su `notice`.

```json
{ "accepted": ["2026-10-30"], "ignored": ["2026-10-29"], "rejected": ["2026-10-28"] }
```

| Lista | Significado |
|---|---|
| `accepted` | El día se guardó y reemplazó al anterior. |
| `ignored` | Ya había una revisión igual o mayor. Reenviar es seguro. |
| `rejected` | Sus cifras no cuadran. No se publica, abre un fallo y la sucursal lo conserva pendiente. |

Cada subida renueva `live`, y una sucursal sin contacto por más de 15 minutos aparece como atrasada.

## 5. CulinaryAdmin (`/admin/v1`)

### 5.1 Alta de administradores e inicio de sesión

Cada cuenta corresponde a **un dispositivo**: una llave Ed25519 o P-256 que el panel genera y guarda sin poder exportarla (WebCrypto `extractable: false` o el almacén del sistema). Para otro equipo se invita una cuenta nueva y se borra la anterior.

**Alta**: `POST /admin/v1/enroll` (sin firma):

```json
{
  "code": "<ADMIN_SETUP_CODE o invitación>",
  "username": "proveedor",
  "password": "mínimo 12 caracteres",
  "deviceName": "Laptop oficina",
  "key": { "alg": "Ed25519", "spki": "MCowBQYDK2VwAyEA..." }
}
```

- `username`: `^[a-z0-9._-]{3,32}$`. `password`: de 12 a 256 caracteres.
- El primer administrador usa `ADMIN_SETUP_CODE`, que solo vale mientras no exista ningún administrador activo. Los demás usan una invitación (`POST /admin/v1/invites`), de un solo uso y válida 24 horas.

Respuesta `201`:

```json
{ "adminId": "...", "totp": { "secret": "BASE32...", "uri": "otpauth://totp/CulinaryAdmin:proveedor?secret=...&issuer=CulinaryAdmin&algorithm=SHA1&digits=6&period=30" } }
```

El panel muestra `uri` como código QR una sola vez. TOTP: RFC 6238, SHA-1, 6 dígitos, 30 s, se acepta un paso de desfase y cada código vale una vez.

**Confirmar**: `POST /admin/v1/enroll/confirm`, firmada (scope `admin`, subject = `username`) con la llave del alta: `{ "totp": "123456" }` → `200 { "adminId", "username" }`. Hasta confirmar no se puede iniciar sesión, y una cuenta sin confirmar se borra a las 24 horas.

**Iniciar sesión**: `POST /admin/v1/login`, firmada igual:

```json
{ "password": "...", "totp": "654321" }
```

```json
{ "token": "<base64url>", "expiresAt": "2026-10-24T23:04:05.123Z", "admin": { "id": "...", "username": "proveedor" } }
```

- Tres factores: llave del dispositivo, contraseña y TOTP. Cualquier fallo responde `401` con el mismo mensaje.
- Cinco fallos con firma válida bloquean la cuenta 15 minutos (`429`).
- La sesión dura 8 horas. Las demás rutas piden `Authorization: Bearer <token>`.

**Contraseña olvidada**: `POST /admin/v1/password`, firmada igual y sin sesión: `{ "totp": "123456", "newPassword": "mínimo 12 caracteres" }` → `200 { "ok": true }`. La llave del dispositivo y el TOTP sustituyen a la contraseña; comparte el bloqueo de cinco fallos con el inicio de sesión y cierra todas las sesiones de la cuenta. Si además se perdió el TOTP o el equipo, otro administrador borra la cuenta y envía una invitación (o, sin otro administrador, el procedimiento de recuperación del README).
- `POST /admin/v1/invites` y `DELETE /admin/v1/admins/{id}` piden además la firma del dispositivo (sección 2, scope `admin`, subject = el `username` de la sesión). Así un token robado no basta para crear ni borrar cuentas.

| Método y ruta | Respuesta |
|---|---|
| `GET /admin/v1/me` | `{ "admin": { "id", "username" } }` |
| `POST /admin/v1/logout` | `{ "ok": true }` |
| `POST /admin/v1/invites` | `201 { "code": "XXXXX-XXXXX-XXXXX-XXXXX", "expiresAt" }` |
| `GET /admin/v1/admins` | `{ "admins": [{ "id", "username", "deviceName", "keyAlg", "active", "createdAt" }] }` |
| `DELETE /admin/v1/admins/{id}` | `{ "ok": true }`; no permite borrarse a sí mismo |
| `GET /admin/v1/root-key` | `{ "kid", "alg": "EdDSA", "publicKey": "<32 bytes base64url>", "spki", "pem", "licenseIntermediate": { "kid", "generation", "notBefore", "expiresAt" } \| null, "keyFloor": { "license", "release" } \| null }` |
| `GET /admin/v1/audit?before=<id>` | `{ "entries": [{ "id", "at", "adminId", "action", "target", "detail" }] }`, 100 por página |

### 5.2 Licencias

**Crear**: `POST /admin/v1/licenses`:

```json
{
  "customer": "Restaurante La Plaza",
  "branchName": "Centro",
  "siteId": "plaza-centro",
  "tenantId": "grupo-plaza",
  "plan": "trial",
  "tier": "lite",
  "addons": ["mobileOrdering"],
  "trialDays": 14,
  "features": ["printing", "reservations"],
  "limits": { "maxUsers": 15, "maxTables": 30 }
}
```

- `tier` es obligatorio; `addons` es opcional (vacío si falta). `limits.maxTerminals` es opcional y, si falta, sigue al nivel.

- `siteId`: `^[a-z0-9-]{1,32}$`, único. Es el `siteId` de la sucursal.
- `tenantId`: `^[a-z0-9-]{1,64}$`, opcional. Agrupa las sucursales de una misma empresa; si falta se genera uno.
- `trialDays` (1 a 365) va solo con `plan: "trial"`.

Respuesta `201`: `{ "license": Licencia, "activationCode": "XXXXX-XXXXX-XXXXX-XXXXX" }`. El código se muestra una sola vez.

Licencia en el panel:

```json
{
  "id": "...", "tenantId": "grupo-plaza", "siteId": "plaza-centro",
  "customer": "Restaurante La Plaza", "branchName": "Centro",
  "plan": "trial", "tier": "lite", "addons": ["mobileOrdering"], "trialDays": 14,
  "features": ["printing", "reservations"], "limits": { "maxUsers": 15, "maxTables": 30, "maxTerminals": 2 },
  "revision": 1,
  "status": "pending",
  "createdAt": "...", "activatedAt": null, "expiresAt": null, "validatedAt": null,
  "revokedAt": null, "revokeReason": null,
  "binding": null,
  "centralCertificateSha256": null
}
```

`status`: `pending` (sin activar), `active`, `expired` o `revoked`. `binding`: `null` o `{ "kind": "tpm" | "fingerprint", "keyAlg": "ES256" | "Ed25519" }`.

| Método y ruta | Cuerpo | Efecto |
|---|---|---|
| `GET /admin/v1/licenses?tenantId=&status=` | | `{ "licenses": [Licencia] }`; `status` fuera de `pending`, `active`, `expired`, `revoked` da `400` |
| `GET /admin/v1/licenses/{id}` | | `{ "license": Licencia }` |
| `PATCH /admin/v1/licenses/{id}` | cualquiera de `customer`, `branchName`, `siteId`, `plan`, `tier`, `addons`, `trialDays`, `features`, `limits`, `expiresAt` | Editar, habilitar o quitar funciones. Solo `plan` y `expiresAt` mueven el vencimiento: cambiar `plan` en una licencia activada reinicia el plazo desde ahora, y `expiresAt` (futuro) lo fija a mano y gana. `trialDays` solo vale con el plan de prueba (`400` si no) y cambiarlo no mueve un plazo ya corriendo. `siteId` cambia solo mientras ningún equipo tiene la licencia (sin activar o tras `reset-activation`; `409` si no) y `409` si otra licencia ya lo usa. |
| `DELETE /admin/v1/licenses/{id}` | | `{ "ok": true }`. La quita del panel: deja de salir en las listas y `GET`/`PATCH`/acciones dan `404`. Antes la revoca (la sucursal se bloquea en su siguiente contacto) y libera su `siteId` y su certificado mTLS para otra licencia. La fila se conserva para tickets, publicaciones y bitácora (`license.delete` guarda el `siteId` original). |
| `POST /admin/v1/licenses/{id}/renew` | `{}` o `{ "until": "<ISO futuro>" }` | Sin `until`, suma un periodo (mes, año o `trialDays`) al vencimiento vigente o a ahora, lo que sea posterior. `409` en `permanent`, revocada o sin activar. |
| `POST /admin/v1/licenses/{id}/revoke` | `{ "reason": "≤500" }` | Revocación definitiva. |
| `POST /admin/v1/licenses/{id}/reset-activation` | `reason` (1 a 500 caracteres) | Transferencia: libera el equipo (borra huella y registro mTLS, y guarda su llave para avisarle), audita motivo y llave, y devuelve `{ "license", "activationCode" }` nuevo. El equipo liberado se bloquea en su siguiente contacto. |

Cada cambio sube `revision`; la sucursal lo recibe en su siguiente renovación. Una licencia revocada no admite cambios (`409`).

### 5.3 Versiones y publicaciones

Subida a R2 por partes, para paquetes de cualquier tamaño:

1. `POST /admin/v1/releases` con `{ "version": "1.4.0", "platform": "linux-x64", "filename": "culinary-1.4.0.deb", "notes": "..." }` → `201 { "release": Versión }` en estado `uploading`. `filename`: `^[A-Za-z0-9][A-Za-z0-9._-]{0,150}\.(exe|deb|apk)$`, con la extensión de la plataforma (`linux-x64` → `.deb`, `win-x64` → `.exe`, `android-arm64` → `.apk`); `version`: `x.y.z` (hasta 5 dígitos por parte), única por plataforma.
2. `PUT /admin/v1/releases/{id}/parts/{n}` con los bytes crudos y `Content-Length`, `n` de 1 a 10000 → `{ "partNumber", "etag" }`. Todas las partes salvo la última deben medir al menos 5 MiB, y ninguna puede pasar del límite de cuerpo del plan de Workers (100 MB en Free y Pro). Un paquete pequeño cabe en una sola parte.
3. `POST /admin/v1/releases/{id}/complete` con `{ "parts": [{ "partNumber": 1, "etag": "..." }] }` → el Worker calcula el SHA-512 de lo que quedó en R2. `{ "release": Versión }` en estado `signing`, sin `manifest`.
4. `PUT /admin/v1/releases/{id}/manifest` con `{ "manifest": "<JWS culinary-release+jws>" }`, firmado en la estación con la intermedia de paquetes (`scripts/sign-release.mjs`). El Worker comprueba la cadena y que `releaseId`, `version`, `platform`, `filename`, `bytes` y `sha512` coincidan con lo subido → `{ "release": Versión }` en estado `ready`. Sólo una versión `ready` se puede publicar.

`DELETE /admin/v1/releases/{id}` cancela una subida sin terminar.

```json
{ "id": "...", "version": "1.4.0", "platform": "linux-x64", "filename": "culinary-1.4.0.deb", "notes": "...",
  "status": "ready", "bytes": 48213004, "sha512": "<hex128>", "manifest": "<JWS culinary-release+jws>", "createdAt": "..." }
```

**Publicar**: `POST /admin/v1/publications`:

```json
{ "releaseId": "...", "target": "all" }
{ "releaseId": "...", "target": { "licenseIds": ["0b6c...", "7d2e..."] } }
```

→ `201 { "publication": { "id", "releaseId", "target", "createdAt", "withdrawnAt" } }`. `GET /admin/v1/publications` las lista y `POST /admin/v1/publications/{id}/withdraw` retira una. La sucursal recibe la versión más nueva de su plataforma que alguna publicación vigente le dirija.

### 5.4 Soporte

| Método y ruta | Respuesta |
|---|---|
| `GET /admin/v1/tickets?status=open` | `{ "tickets": [{ "id", "licenseId", "customer", "branchName", "siteId", "subject", "status", "createdAt", "updatedAt" }] }`, 200 más recientes; `status` opcional: `open`, `answered` o `closed` |
| `GET /admin/v1/tickets/{id}` | `{ "ticket": Ticket }` con mensajes |
| `POST /admin/v1/tickets/{id}/messages` con `{ "message": "≤4000" }` | `201 { "ticket": Ticket }`, estado `answered` |
| `POST /admin/v1/tickets/{id}/close` | `{ "ticket": Ticket }` |

### 5.5 Registro de sucursales

`GET /admin/v1/registry?tenantId=grupo-plaza`, sin licencias revocadas:

```json
{
  "branches": [
    {
      "tenantId": "grupo-plaza", "tenantName": "Restaurante La Plaza",
      "branchId": "0b6c...", "siteId": "plaza-centro", "slug": "plaza-centro", "branchName": "Centro",
      "certificateSha256": "<hex64 o null>", "licenseStatus": "active", "features": ["multiBranch"]
    }
  ]
}
```

Cada fila trae los campos de sucursal del archivo `--provision-tenant` de `MesaNexo.Central` (`tenantId`, `branchId`, `siteId`, `slug`, `certificateSha256`, `tenantName`, `branchName`). Las credenciales del dueño no pasan por este Worker.

### 5.7 Cuentas del panel del propietario

| Ruta | Uso |
|---|---|
| `POST /owner-invites` | Con firma del dispositivo. Cuerpo `{ "tenantId", "email", "role", "licenseIds" }`. `role` es `owner` o `manager`; el gerente lleva sus sucursales y el dueño ninguna. Responde `{ "code", "expiresAt" }`, válido 7 días. |
| `GET /owner-accounts?tenantId=` | Cuentas de un negocio. |
| `DELETE /owner-accounts/:id` | Con firma del dispositivo. Elimina la cuenta y sus sesiones. |

Mientras no haya correo, quien pierde su contraseña o su autenticador recupera el acceso así: se elimina su cuenta y se le invita de nuevo.

### 5.6 Fallos

| Ruta | Respuesta |
|---|---|
| `GET /admin/v1/faults?status=open` | `{ "faults": [Fault] }`, los 200 vistos más recientemente. `status`: `open` o `resolved`; sin él, ambos |
| `POST /admin/v1/faults/{id}/resolve` | `{ "fault": Fault }`, queda en la bitácora |
| `POST /admin/v1/faults/{id}/reopen` | `{ "fault": Fault }`, queda en la bitácora |

`Fault` lleva los campos de §4.8 menos `fingerprint`, más `id`, `licenseId`, `customer`, `branchName`, `siteId`, `status`, `resolvedAt` y `resolvedBy`. Los resueltos se borran a los 90 días.

## 6. Panel del propietario (`/owner/v1`)

Sin firma de dispositivo: correo, contraseña de 12 caracteres o más y TOTP. Tras cinco intentos fallidos la cuenta se bloquea 15 minutos. Las sesiones duran 30 días y viajan como `Authorization: Bearer`.

| Ruta | Uso |
|---|---|
| `POST /enroll` | `{ "code", "password" }`. Gasta el código y responde el secreto TOTP. |
| `POST /enroll/confirm` | `{ "email", "password", "totp" }`. Activa la cuenta. |
| `POST /login` | `{ "email", "password", "totp" }`. Responde `{ "token", "expiresAt" }`. |
| `POST /logout` | Cierra la sesión. |
| `GET /me` | La cuenta y sus sucursales, con licencia, último contacto, `stale` y `live`. |
| `GET /stats/summary` | Totales, ranking por sucursal, días, horas, canales, pagos y devoluciones. `partial` lista las sucursales atrasadas o sin datos. |
| `GET /stats/products` | Por nombre y categoría, porque cada sucursal tiene sus propios identificadores. El margen estimado sólo cuenta productos con receta. |
| `GET /stats/staff` | Por sucursal y mesero. |
| `GET /stats/cash` | Movimientos, merma y arqueos. |
| `GET /stats/closings` | Cada corte junto a lo que cuenta el panel. `reopenedNet` y `reopenedTickets` son lo que explican las reaperturas. |

Las rutas `/stats/*` piden `from` y `to` (`AAAA-MM-DD`, días de negocio, máximo 366) y aceptan `branch` con un `licenseId`. El servidor filtra por el negocio de la cuenta, y un gerente sólo alcanza sus sucursales. Una sucursal fuera de alcance responde `404`, igual que una inexistente. Lo subido sigue consultable con la licencia vencida, y una licencia eliminada desaparece del panel.

**Planes.** El servidor recorta por el `tier` de cada licencia, así que una sucursal Lite nunca entrega cifras Pro:

- Lite entra en ventas, cuentas, comensales, ticket promedio, ranking, días y cantidad e ingreso de productos. Las horas sólo cuando el periodo es un día, para comparar hoy con ayer a la misma hora.
- Sus filas llevan en cero `gross`, `discounts`, `voidedCount`, `voidedAmount`, `comps` y `staffMeals`, y no aportan canales, pagos, devoluciones, costo ni margen. `/stats/staff`, `/stats/cash` y `/stats/closings` sólo cuentan sucursales Pro, y `live.lowStock` de una Lite va vacío.
- Lite lee desde el primer día de su mes en curso o desde seis días antes de su día de negocio, lo que llegue más atrás. Si el periodo empieza antes, la sucursal queda fuera de toda la respuesta.

Cada respuesta de `/stats/*` dice `lite`, las sucursales Lite que no entran en las cifras Pro, y `outOfRange`, las que quedaron fuera por el periodo.
