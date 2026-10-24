import { Hono } from "hono";
import { cors } from "hono/cors";
import { admin } from "./admin";
import { adminAccounts, adminAuth, requireAdmin } from "./admin-auth";
import { branch } from "./branch";
import { migrate } from "./db";
import { ApiError, type App, type Env } from "./http";

const app = new Hono<App>();

app.use(async (c, next) => {
  await migrate(c.env.DB);
  await next();
  c.header("cache-control", "no-store");
  c.header("x-content-type-options", "nosniff");
});

// Browsers only reach the panel routes, and only from the origins listed in ADMIN_ORIGINS.
app.use(
  "/admin/*",
  cors({
    origin: (origin, c) => (c.env.ADMIN_ORIGINS.split(",").map((o: string) => o.trim()).includes(origin) ? origin : null),
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowHeaders: ["authorization", "content-type", "x-culinary-subject", "x-culinary-challenge", "x-culinary-signature"],
    maxAge: 600,
  }),
);

app.route("/branch/v1", branch);
app.route("/admin/v1", adminAuth);
app.use("/admin/v1/*", requireAdmin);
app.route("/admin/v1", adminAccounts);
app.route("/admin/v1", admin);

app.notFound((c) => c.json({ error: { code: "not_found", message: "Ruta no disponible" } }, 404));

app.onError((error, c) => {
  if (error instanceof ApiError) return c.json({ error: { code: error.code, message: error.message, ...error.extra } }, error.status);
  console.error(error);
  return c.json({ error: { code: "internal", message: "Error interno" } }, 500);
});

export default {
  fetch: app.fetch,
  async scheduled(_controller, env) {
    await migrate(env.DB);
    const at = Date.now();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM challenge WHERE expires_at < ?").bind(at),
      env.DB.prepare("DELETE FROM admin_session WHERE expires_at < ?").bind(at),
      env.DB.prepare("DELETE FROM admin_invite WHERE expires_at < ?").bind(at),
      env.DB.prepare("DELETE FROM download_grant WHERE expires_at < ?").bind(at),
      env.DB.prepare("DELETE FROM admin WHERE active = 0 AND created_at < ?").bind(new Date(at - 24 * 60 * 60 * 1000).toISOString()),
    ]);
  },
} satisfies ExportedHandler<Env>;
