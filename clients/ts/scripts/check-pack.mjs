// `npm pack --dry-run`: the tarball holds the compiled client and nothing else.
import { execFileSync } from "node:child_process";

const [pack] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { encoding: "utf8" }));
const files = pack.files.map((f) => f.path).sort();
const expected = ["LICENSE", "README.md", "dist/index.d.ts", "dist/index.js", "dist/schema.d.ts", "package.json"];
const missing = expected.filter((f) => !files.includes(f));
const extra = files.filter((f) => !expected.includes(f));
console.log(`${pack.name}@${pack.version}: ${files.length} files, ${pack.size} bytes packed`);
for (const f of files) console.log(`  ${f}`);
if (missing.length || extra.length) {
  console.error(`unexpected tarball contents: missing ${JSON.stringify(missing)}, extra ${JSON.stringify(extra)}`);
  process.exit(1);
}
