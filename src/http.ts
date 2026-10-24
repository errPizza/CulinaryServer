import type { Context } from "hono";
import { z } from "zod";

export type Env = {
  DB: D1Database;
  PACKAGES: R2Bucket;
  ROOT_PRIVATE_KEY?: string;
  ADMIN_SETUP_CODE?: string;
  ADMIN_ORIGINS: string;
};

export type AdminIdentity = { id: string; username: string };

export type App = { Bindings: Env; Variables: { admin: AdminIdentity; sessionHash: string } };

export type Ctx = Context<App>;

export class ApiError extends Error {
  constructor(
    readonly status: 400 | 401 | 403 | 404 | 409 | 413 | 429 | 503,
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export const MAX_JSON_BYTES = 64 * 1024;

/** Reads the body once as bytes: signed requests hash exactly what was sent. */
export async function rawBody(c: Ctx, limit = MAX_JSON_BYTES): Promise<Uint8Array<ArrayBuffer>> {
  const declared = Number(c.req.header("content-length") ?? 0);
  if (declared > limit) throw new ApiError(413, "too_large", "Solicitud demasiado grande");
  const bytes = new Uint8Array(await c.req.arrayBuffer());
  if (bytes.length > limit) throw new ApiError(413, "too_large", "Solicitud demasiado grande");
  return bytes;
}

export function parseJson<T extends z.ZodType>(schema: T, bytes: Uint8Array): z.infer<T> {
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new ApiError(400, "bad_request", "El cuerpo debe ser JSON");
  }
  const result = schema.safeParse(data);
  if (!result.success) {
    const issue = result.error.issues[0]!;
    throw new ApiError(400, "bad_request", `${issue.path.join(".") || "cuerpo"}: ${issue.message}`);
  }
  return result.data;
}

export async function readJson<T extends z.ZodType>(c: Ctx, schema: T): Promise<z.infer<T>> {
  return parseJson(schema, await rawBody(c));
}
