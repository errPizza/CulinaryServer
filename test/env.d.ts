declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
    ROOT_PUBLIC_SPKI: string;
    ADMIN_SETUP_CODE: string;
  }
  interface GlobalProps {
    mainModule: typeof import("../src/index");
  }
}
