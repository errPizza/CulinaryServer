# Llaves de firma

## Inventario

| Llave | Dónde vive | Firma | Si se pierde | Si se compromete |
|---|---|---|---|---|
| Raíz (`root-private.txt`) | Fuera de línea: gestor de contraseñas o USB cifrada, nunca en el Worker | Intermedias y piso de llaves | Nuevas intermedias imposibles; hay que reaprovisionar todas las sucursales con una raíz nueva | Igual que perderla: raíz nueva y reaprovisionar |
| Intermedia de licencias (`license-gN`) | Secretos `LICENSE_SIGNING_KEY` y `LICENSE_SIGNING_CHAIN` del Worker | Licencias, avisos de bloqueo y autorizaciones de actualización | Firmar otra generación con la raíz | Subir el piso de licencias y firmar otra generación |
| Intermedia de paquetes (`release-gN`) | Sólo en la estación de firma, fuera de línea | Manifiestos de paquetes (SHA-512) | Firmar otra generación con la raíz | Subir el piso de paquetes y firmar otra generación |
| Retos (`challenge-key.txt`) | Secreto `CHALLENGE_KEY` del Worker | MAC de los retos de 2 minutos | Generar otra; sólo invalida retos en curso | Generar otra |

La pública de la raíz va incrustada en Culinary Restaurant (`-p:CulinaryRootPublicKey=...`) y en `ROOT_PUBLIC_SPKI` del Worker. No cambia al rotar intermedias.

## Publicar una versión

1. En CulinaryAdmin → Versiones → Subir versión. El Worker guarda el paquete en R2 y calcula su SHA-512. La versión queda en «Falta firma».
2. En la estación de firma, con el mismo archivo que subiste:

   ```bash
   node scripts/sign-release.mjs --file Culinary-0.4.0.exe --release-id <id> --version 0.4.0 --platform win-x64
   ```

   El panel muestra el comando exacto y la huella esperada.
3. Pega la línea que imprime en «Firmar». El Worker comprueba que la firma sea de la intermedia de paquetes y que describa los mismos bytes, y la versión queda lista para publicar.

La sucursal y cada terminal verifican el manifiesto y la autorización por separado y exigen que coincidan en versión, archivo, tamaño y SHA-512.

## Rotar la intermedia de licencias (cada año)

El panel muestra su vencimiento. Un mes antes:

```bash
node scripts/sign-intermediate.mjs --use license --generation 2
```

Sube `LICENSE_SIGNING_KEY` y `LICENSE_SIGNING_CHAIN` nuevos al Worker. Las licencias firmadas con la generación anterior siguen valiendo: la vigencia se comprueba con la fecha de firma.

## Revocar una intermedia comprometida

1. Firma una generación nueva como en la rotación.
2. Sube el piso para que la generación comprometida deje de valer:

   ```bash
   node scripts/sign-key-floor.mjs --license 2 --release 1
   ```

3. Sube el resultado como secreto `KEY_FLOOR`. Cada sucursal lo recibe y lo guarda al renovar la licencia; desde ese momento rechaza todo lo firmado por generaciones menores, también después de reiniciar. El Worker se niega a firmar con una intermedia por debajo del piso.

Las licencias vigentes firmadas por la generación revocada se reemplazan en la siguiente renovación de cada sucursal.

## Documentos firmados por la raíz directamente

Las licencias y versiones emitidas antes de las intermedias siguen valiendo, porque la raíz ya no está en línea para firmar nada nuevo.
