declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
    ROOT_PUBLIC_SPKI: string;
    LICENSE_SIGNING_KEY: string;
    LICENSE_SIGNING_CHAIN: string;
    CHALLENGE_KEY: string;
    ADMIN_SETUP_CODE: string;
    TEST_ROOT_KEY: string;
    TEST_RELEASE_KEY: string;
    TEST_RELEASE_CHAIN: string;
  }
  interface GlobalProps {
    mainModule: typeof import("../src/index");
  }
}
