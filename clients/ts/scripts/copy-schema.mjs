// tsc does not copy .d.ts sources: dist/index.d.ts imports its types from ./schema.js.
import { copyFileSync } from "node:fs";

copyFileSync(new URL("../src/schema.d.ts", import.meta.url), new URL("../dist/schema.d.ts", import.meta.url));
