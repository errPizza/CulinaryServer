import type { Context } from "hono";
import { z } from "zod";
import { sha256Hex } from "./crypto";

export type Env = {

  DB: D1Database;
  PACKAGES: R2Bucket;
  ROOT_PUBLIC_SPKI?: string;
  LICENSE_SIGNING_KEY?: string;
  LICENSE_SIGNING_CHAIN?: string;
  KEY_FLOOR?: string;
  CHALLENGE_KEY?: string;
  ADMIN_SETUP_CODE?: string;
  ADMIN_ORIGINS: string;

};

export type AdminIdentity = { id: string; username: string };
export type OwnerIdentity = { id: string; tenantId: string; email: string; role: "owner" | "manager" };
export type App = { Bindings: Env; Variables: { admin: AdminIdentity; owner: OwnerIdentity; sessionHash: string } };
export type Ctx = Context<App>;
export type ErrorCode = | "bad_request" | "unauthorized" | "forbidden" | "activation_rejected" | "site_mismatch" | "license_expired" | "license_revoked" | "license_transferred" | "binding_mismatch" | "not_found" | "conflict" | "too_large" | "range_not_satisfiable" | "rate_limited" | "server_misconfigured";

export class ApiError extends Error {

  constructor(readonly status: 400 | 401 | 403 | 404 | 409 | 413 | 416 | 429 | 503, readonly code: ErrorCode, message: string, readonly extra: Record<string, unknown> = {}) {
    
    super(message);

  }

}

export const MAX_JSON_BYTES = 64 * 1024;

export async function rawBody(c: Ctx, limit = MAX_JSON_BYTES): Promise<Uint8Array<ArrayBuffer>> {

  const tooLarge = () => new ApiError(413, "too_large", "Solicitud demasiado grande");

  if (Number(c.req.header("content-length") ?? 0) > limit) throw tooLarge();

  const body = c.req.raw.body;

  if (!body) return new Uint8Array();

  const chunks: Uint8Array[] = [];
  let size = 0;

  for await (const chunk of body) {

    size += chunk.length;

    if (size > limit) throw tooLarge();

    chunks.push(chunk);

  }

  const bytes = new Uint8Array(size);
  let offset = 0;

  for (const chunk of chunks) {

    bytes.set(chunk, offset);
    offset += chunk.length;

  }

  return bytes;
}

export function parseJson<T extends z.ZodType>(schema: T, bytes: Uint8Array): z.infer<T> {
  
  let data: unknown;

  try {

    data = JSON.parse(new TextDecoder().decode(bytes));

  } catch {

    throw new ApiError(400, "bad_request", "El cuerpo debe ser JSON");

  }

  return parse(schema, data);
}

export function parse<T extends z.ZodType>(schema: T, data: unknown): z.infer<T> {

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

export async function bearerHash(c: Ctx, message: string): Promise<string> {
  
  const auth = c.req.header("authorization") ?? "";
 
  if (!auth.startsWith("Bearer ") || auth.length > 200) throw new ApiError(401, "unauthorized", message);
  
  return sha256Hex(auth.slice(7));
}

export async function uniqueOr409<T>(write: Promise<T>, message: string): Promise<T> {
  
  try {
    
    return await write;
  } catch (error) {
    
    if (String(error).includes("UNIQUE constraint failed")) throw new ApiError(409, "conflict", message);
   
    throw error;

  }

}