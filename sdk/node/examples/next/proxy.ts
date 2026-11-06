import type { NextRequest } from "next/server";
import { polaris } from "./lib/polaris";

// Refreshes the session before Server Components, which cannot write cookies, read it.
export const proxy = (request: NextRequest) => polaris.middleware(request);

export const config = { matcher: ["/((?!auth/|_next/|favicon.ico).*)"] };
