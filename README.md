# CulinaryServer

Cloudflare Worker que conecta solo a dos clientes:

- **CulinaryAdmin**, el panel del proveedor: licencias, funciones, versiones, soporte y registro de sucursales.
- **Culinary Restaurant**, el servidor de sucursal en CulinaryOS: activación, renovación, actualizaciones y tickets.

Cualquier otra ruta responde 404, y el panel solo admite CORS desde los orígenes configurados. El contrato completo está en [docs/API.md](docs/API.md).

## Cómo funciona

- **Llave raíz Ed25519 fuera de línea.** La privada nunca entra al Worker. Sólo firma, desde la estación del proveedor, dos llaves intermedias con vencimiento y uso limitado:
  - **Licencias** (secretos `LICENSE_SIGNING_KEY` y `LICENSE_SIGNING_CHAIN` del Worker): licencias, avisos de bloqueo y autorizaciones de actualización.
  - **Paquetes** (sólo en la estación): el manifiesto con el SHA-512 de cada paquete. El Worker no publica una versión hasta que se pega esa firma en el panel.

  Cada documento lleva en su encabezado (`chain`) el certificado de su intermedia, y la sucursal sólo acepta de cada intermedia los tipos que el certificado lista. Si alguien toma el Worker, puede firmar licencias, pero no autorizar bytes que la estación no firmó. Los retos usan su propia llave (`CHALLENGE_KEY`). El procedimiento completo está en [docs/LLAVES.md](docs/LLAVES.md).
- **Licencia de uso.** Al activar, la sucursal genera su propia llave (no exportable dentro del TPM 2.0 si lo hay; si no, una llave ligada a la huella de placa, disco y MAC). El Worker certifica esa llave con la intermedia de licencias junto con el plan, las funciones y los límites. Cada renovación firma un reto del servidor con esa llave, así que copiar la licencia a otro equipo no sirve.
- **Gracia sin conexión.** Cada licencia incluye `offlineUntil`: 7 días desde la última validación. Una licencia vencida o revocada ya no se renueva y recibe un aviso firmado para la pantalla de bloqueo.
- **Panel.** Cada cuenta es un dispositivo con su llave, más contraseña y TOTP. Las cuentas siguientes entran por invitación.
- **Almacenamiento.** D1 para los datos y R2 para los paquetes. El Worker aplica sus migraciones (`migrations/`) solo, en la primera solicitud, porque el despliegue desde Git no escribe el ID de la base en el repositorio.

## Despliegue desde GitHub

Lo que no se puede hacer desde el repositorio está marcado con **(tú)**.

**Requisito: plan Workers Paid.** Publicar una versión calcula el SHA-512 de todo el paquete dentro de la solicitud, y el inicio de sesión del panel usa PBKDF2. Los dos pasan de los 10 ms de CPU por solicitud del plan Free. Las pruebas locales no lo detectan porque Miniflare no limita la CPU.

1. **(tú) Genera los secretos, una sola vez**, en un equipo de confianza:

   ```bash
   npm install
   ```

   ```bash
   npm run keys
   ```

   Crea en `secrets/` (ignorada por Git) lo que falte: `root-private.txt`, `root-public.pem`, `challenge-key.txt` y `admin-setup-code.txt`. No sobrescribe nada: cambiar la raíz obliga a reaprovisionar todas las sucursales. Después firma las dos intermedias:

   ```bash
   node scripts/sign-intermediate.mjs --use license --generation 1
   ```

   ```bash
   node scripts/sign-intermediate.mjs --use release --generation 1
   ```

   Duran 400 días; el panel muestra cuándo vence la de licencias.

2. **(tú) Conecta el repositorio en Cloudflare:** Workers & Pages → Create → elige GitHub → repositorio `CulinaryServer`.
   - El nombre del Worker debe ser `culinary-server`, igual que `name` en `wrangler.jsonc`. Si no coincide, la compilación falla.
   - Deja vacío el comando de compilación y el de despliegue en `npx wrangler deploy`.
   - Save and Deploy. El primer despliegue crea la base D1 `culinary-server` y el bucket R2 `culinary-server-packages`. R2 debe estar activado en la cuenta (Dashboard → R2, una sola vez); si no, el despliegue falla al crear el bucket.

3. **(tú) Agrega los secretos:** el Worker → Settings → Variables and Secrets → Add, tipo **Secret**:
   - `LICENSE_SIGNING_KEY`: el contenido de `secrets/license-g1-private.txt`.
   - `LICENSE_SIGNING_CHAIN`: el contenido de `secrets/license-g1-chain.txt`.
   - `CHALLENGE_KEY`: el contenido de `secrets/challenge-key.txt`.
   - `ADMIN_SETUP_CODE`: el contenido de `secrets/admin-setup-code.txt`.

   La pública de la raíz va en `ROOT_PUBLIC_SPKI`, dentro de `vars` en `wrangler.jsonc` (no es secreta). Si migras desde la versión anterior, borra el secreto `ROOT_PRIVATE_KEY` del Worker. Pulsa Deploy. Sin estos valores, los retos y todo lo que firma responden `503 server_misconfigured`.

4. **(tú) Si el panel corre en un navegador o en Tauri**, define la variable `ADMIN_ORIGINS` con sus orígenes separados por comas (por ejemplo `https://admin.ejemplo.com,http://tauri.localhost`). Si el panel llama desde código nativo, déjala vacía. Ojo: el valor de `wrangler.jsonc` reemplaza al del panel en cada despliegue desde Git, así que cámbialo en el archivo.

5. **(tú) Desactiva las compilaciones de ramas que no sean `main`** en Settings → Build → Branch control, si aparece la opción. Una vista previa usaría la misma base y los mismos secretos que producción. `preview_urls` ya está apagado en `wrangler.jsonc`.

6. **Primer administrador:** en CulinaryAdmin, alta con el código de `admin-setup-code.txt`. Ese código deja de servir en cuanto existe un administrador activo; después puedes borrar el secreto `ADMIN_SETUP_CODE`.

7. **(tú) Guarda `secrets/root-private.txt` y `secrets/release-g1-private.txt` fuera de línea** (por ejemplo en un gestor de contraseñas o una USB cifrada) y bórralos del equipo, junto con `license-g1-private.txt` una vez subido. Copia `secrets/root-public.pem` a la configuración de Culinary Restaurant: es la llave con la que verifica las intermedias. El panel también la muestra en `GET /admin/v1/root-key`.

Cada push a `main` vuelve a desplegar. Las migraciones nuevas se agregan como `migrations/000N_nombre.sql` y en la lista de `src/db.ts`.

## Recuperar el acceso al panel

Si se pierden todos los dispositivos de administrador, con Wrangler autenticado en tu cuenta:

```bash
npx wrangler d1 execute culinary-server --remote --command "DELETE FROM admin"
```

Luego vuelve a definir `ADMIN_SETUP_CODE` y da de alta un administrador nuevo. Las licencias no se tocan.

## Desarrollo

```bash
npm test
```

```bash
npm run typecheck
```

Las pruebas corren dentro del runtime de Workers con `@cloudflare/vitest-plugin` y una cadena desechable (raíz, intermedia de licencias e intermedia de paquetes) que genera `vitest.config.ts`. Para `npm run dev`, crea `.dev.vars` con `LICENSE_SIGNING_KEY`, `LICENSE_SIGNING_CHAIN`, `CHALLENGE_KEY` y `ADMIN_SETUP_CODE` de una cadena de desarrollo, nunca la raíz.

## Decisiones que conviene revisar

- **El plazo empieza al activar**, también en mensual y anual. El panel puede fijar `expiresAt` antes de activar si el cobro empezó otro día.
- **Huella sin TPM:** basta con que coincidan dos de tres partes (placa, disco, MAC), para que cambiar una pieza no bloquee la sucursal. Cada cambio aceptado actualiza la huella guardada y queda en la auditoría (`license.hardware_change`). Con dos cambios a la vez, el proveedor libera el equipo desde el panel.
- **La huella es una señal, no un secreto.** Son identificadores que cualquiera con acceso al equipo puede leer o imitar. Lo que liga la licencia es la llave privada; la huella sólo detecta que esa llave se copió a otra máquina.
- **Una transferencia sólo recuerda el último equipo liberado.** Ese equipo recibe un aviso firmado y se bloquea en su siguiente contacto. Uno liberado antes, o uno sin internet, se bloquea solo al terminar la gracia.
- **TPM sin atestación:** el Worker registra la llave pública que la sucursal declara como del TPM (exige que sea P-256), pero no verifica el certificado de respaldo (EK) del fabricante.
- **La huella de hardware solo se revisa al renovar.** Las demás rutas de la sucursal confían en la firma de la llave. Una llave copiada a otro equipo deja de renovar, y a los 7 días la licencia se bloquea sola.
- **El registro mTLS no prueba la posesión del certificado.** Una sucursal con licencia podría registrar primero la huella del certificado de otra; la verdadera recibiría `409`. El proveedor lo ve en `GET /admin/v1/registry` y lo corrige liberando el equipo.
- **La misma raíz firma los paquetes.** Es lo pedido (una sola llave, en el Worker). Si alguien tomara el control del Worker podría firmar un paquete; una llave de publicación aparte, fuera de línea, cerraría ese hueco.
- **Revocar es definitivo.** Para volver a dar servicio se crea otra licencia.
- **PBKDF2 a 100 000 iteraciones**, para mantener corto el inicio de sesión; lo compensan la llave del dispositivo y el TOTP.
