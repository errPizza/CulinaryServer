import { Hono } from "hono";
import { cors } from "hono/cors";
import { admin } from "./admin";
import { adminAccounts, adminAuth } from "./admin-auth";
import { branch } from "./branch";
import { migrate, purgeExpired } from "./db";
import { ApiError, type App, type Env } from "./http";

const app = new Hono<App>();

app.use(async (c, next) => {

  await migrate(c.env.DB);
  await next();

  c.header("cache-control", "no-store");
  c.header("x-content-type-options", "nosniff");

});

app.use("/admin/*", cors({

  origin: (origin, c) => (c.env.ADMIN_ORIGINS.split(",").map((o: string) => o.trim()).includes(origin) ? origin : null),
  allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowHeaders: ["authorization", "content-type", "x-culinary-subject", "x-culinary-challenge", "x-culinary-signature"],
  maxAge: 600

}));

app.route("/branch/v1", branch);
app.route("/admin/v1", adminAuth);
app.route("/admin/v1", adminAccounts);
app.route("/admin/v1", admin);
app.notFound((c) => c.json({ error: { code: "not_found", message: "Ruta no disponible" } }, 404));

app.onError((error, c) => {
  
  if (error instanceof ApiError) return c.json({ error: { ...error.extra, code: error.code, message: error.message } }, error.status);
  
  console.error(error);

  return c.json({ error: { code: "internal", message: "Error interno" } }, 500);
});

export default {

  fetch: app.fetch,
  async scheduled(_controller, env) {

    await migrate(env.DB);
    await purgeExpired(env.DB, Date.now());

  }

} satisfies ExportedHandler<Env>;