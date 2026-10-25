# CulinaryServer

Cloudflare Worker que conecta solo a dos clientes:

- **CulinaryAdmin**, el panel del proveedor: licencias, funciones, versiones, soporte y registro de sucursales.
- **Culinary Restaurant**, el servidor de sucursal en CulinaryOS: activación, renovación, actualizaciones y tickets.

Cualquier otra ruta responde 404, y el panel solo admite CORS desde los orígenes configurados. El contrato completo está en [docs/API.md](docs/API.md).

## Cómo funciona

- **Llave raíz Ed25519.** La privada vive solo como secreto del Worker (`ROOT_PRIVATE_KEY`). Firma las licencias, los avisos de bloqueo, los manifiestos de paquetes y las actualizaciones dirigidas, todo como JWS compacto.
- **Licencia de uso.** Al activar, la sucursal genera su propia llave (no exportable dentro del TPM 2.0 si lo hay; si no, una llave ligada a la huella de placa, disco y MAC). El Worker certifica esa llave con la raíz junto con el plan, las funciones y los límites. Cada renovación firma un reto del servidor con esa llave, así que copiar la licencia a otro equipo no sirve.
- **Gracia sin conexión.** Cada licencia incluye `offlineUntil`: 3 días desde la última validación. Una licencia vencida o revocada ya no se renueva y recibe un aviso firmado para la pantalla de bloqueo.
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

   Crea `secrets/` (ignorada por Git) con `root-private.txt`, `admin-setup-code.txt` y `root-public.pem`. El script no sobrescribe una raíz existente: cambiarla obliga a reaprovisionar todas las sucursales.

2. **(tú) Conecta el repositorio en Cloudflare:** Workers & Pages → Create → elige GitHub → repositorio `CulinaryServer`.
   - El nombre del Worker debe ser `culinary-server`, igual que `name` en `wrangler.jsonc`. Si no coincide, la compilación falla.
   - Deja vacío el comando de compilación y el de despliegue en `npx wrangler deploy`.
   - Save and Deploy. El primer despliegue crea la base D1 `culinary-server` y el bucket R2 `culinary-server-packages`. R2 debe estar activado en la cuenta (Dashboard → R2, una sola vez); si no, el despliegue falla al crear el bucket.

3. **(tú) Agrega los secretos:** el Worker → Settings → Variables and Secrets → Add, tipo **Secret**:
   - `ROOT_PRIVATE_KEY`: el contenido de `secrets/root-private.txt`.
   - `ADMIN_SETUP_CODE`: el contenido de `secrets/admin-setup-code.txt`.

   Pulsa Deploy. Sin `ROOT_PRIVATE_KEY`, los retos y todo lo que firma responden `503 server_misconfigured`.

4. **(tú) Si el panel corre en un navegador o en Tauri**, define la variable `ADMIN_ORIGINS` con sus orígenes separados por comas (por ejemplo `https://admin.ejemplo.com,http://tauri.localhost`). Si el panel llama desde código nativo, déjala vacía. Ojo: el valor de `wrangler.jsonc` reemplaza al del panel en cada despliegue desde Git, así que cámbialo en el archivo.

5. **(tú) Desactiva las compilaciones de ramas que no sean `main`** en Settings → Build → Branch control, si aparece la opción. Una vista previa usaría la misma base y los mismos secretos que producción. `preview_urls` ya está apagado en `wrangler.jsonc`.

6. **Primer administrador:** en CulinaryAdmin, alta con el código de `admin-setup-code.txt`. Ese código deja de servir en cuanto existe un administrador activo; después puedes borrar el secreto `ADMIN_SETUP_CODE`.

7. **(tú) Guarda `secrets/root-private.txt` fuera de línea** (por ejemplo en un gestor de contraseñas) y bórralo del equipo. Copia `secrets/root-public.pem` a la configuración de Culinary Restaurant: es la llave con la que verifica todo lo que firma el Worker. El panel también la muestra en `GET /admin/v1/root-key`.

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

Las pruebas corren dentro del runtime de Workers con `@cloudflare/vitest-plugin` y una llave raíz desechable. Para `npm run dev`, crea `.dev.vars` con `ROOT_PRIVATE_KEY=...` y `ADMIN_SETUP_CODE=...`.

## Decisiones que conviene revisar

- **El plazo empieza al activar**, también en mensual y anual. El panel puede fijar `expiresAt` antes de activar si el cobro empezó otro día.
- **Huella sin TPM:** basta con que coincidan dos de tres partes (placa, disco, MAC), para que cambiar una pieza no bloquee la sucursal. Con dos cambios, el proveedor libera el equipo desde el panel.
- **TPM sin atestación:** el Worker registra la llave pública que la sucursal declara como del TPM (exige que sea P-256), pero no verifica el certificado de respaldo (EK) del fabricante.
- **La huella de hardware solo se revisa al renovar.** Las demás rutas de la sucursal confían en la firma de la llave. Una llave copiada a otro equipo deja de renovar, y a los 3 días la licencia se bloquea sola.
- **El registro mTLS no prueba la posesión del certificado.** Una sucursal con licencia podría registrar primero la huella del certificado de otra; la verdadera recibiría `409`. El proveedor lo ve en `GET /admin/v1/registry` y lo corrige liberando el equipo.
- **La misma raíz firma los paquetes.** Es lo pedido (una sola llave, en el Worker). Si alguien tomara el control del Worker podría firmar un paquete; una llave de publicación aparte, fuera de línea, cerraría ese hueco.
- **Revocar es definitivo.** Para volver a dar servicio se crea otra licencia.
- **PBKDF2 a 100 000 iteraciones**, para mantener corto el inicio de sesión; lo compensan la llave del dispositivo y el TOTP.
