import test from "node:test";
import assert from "node:assert/strict";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import fs from "node:fs";

const schema = JSON.parse(fs.readFileSync(".actor/input_schema.json", "utf8"));
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

const cases = [
  ["rejects empty targets", { targets: [] }, false],
  ["rejects http-less url", { targets: [{ type: "openapi", url: "example.com" }] }, false],
  ["rejects auto when unimplemented", { targets: [{ type: "auto", url: "https://x.test/o.json" }] }, false],
  ["rejects json export format", { targets: [{ type: "openapi", url: "https://x.test/o.json" }], exportFormats: ["json"] }, false],
  ["rejects unknown root field", { targets: [{ type: "openapi", url: "https://x.test/o.json" }], bogus: 1 }, false],
  ["accepts valid openapi", { targets: [{ type: "openapi", url: "https://x.test/o.json" }] }, true],
  ["accepts valid apify-actor", { targets: [{ type: "apify-actor", actorId: "apify/hello-world" }] }, true],
  ["accepts summary export format", { targets: [{ type: "openapi", url: "https://x.test/o.json" }], exportFormats: ["summary"] }, true],
  ["rejects 51 targets", { targets: Array.from({ length: 51 }, (_, i) => ({ type: "openapi", url: `https://x.test/${i}.json` })) }, false],
];

for (const [name, input, expected] of cases) {
  test(name, () => {
    const ok = validate(input);
    assert.equal(ok, expected, JSON.stringify(validate.errors ?? []));
  });
}
