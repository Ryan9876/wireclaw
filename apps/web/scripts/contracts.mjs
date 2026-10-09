import { readFile, writeFile, mkdir } from 'node:fs/promises';
import openapiTS, { astToString } from 'openapi-typescript';
import { compile } from 'json-schema-to-typescript';
import Ajv from 'ajv/dist/2020.js';
import standalone from 'ajv/dist/standalone/index.js';

await mkdir(new URL('../src/generated/', import.meta.url), { recursive: true });
const root = new URL('../../../contracts/', import.meta.url);
const api = JSON.parse(await readFile(new URL('api.openapi.json', root), 'utf8'));
await writeFile(
  new URL('../src/generated/api.ts', import.meta.url),
  astToString(await openapiTS(api)),
);
for (const [file, name] of [
  ['investigation-result', 'Report'],
  ['evidence', 'Evidence'],
]) {
  const schema = JSON.parse(await readFile(new URL(`${file}.schema.json`, root), 'utf8'));
  schema.title = name;
  const output = await compile(schema, name, {
    style: { singleQuote: true },
    unreachableDefinitions: true,
  });
  await writeFile(new URL(`../src/generated/${file}.ts`, import.meta.url), output);
}

// Precompile at build time. Runtime Ajv compilation would require unsafe-eval,
// which is deliberately forbidden by the local UI Content-Security-Policy.
const ajv = new Ajv({ strict: false, code: { source: true, esm: true } });
const report = JSON.parse(
  await readFile(new URL('investigation-result.schema.json', root), 'utf8'),
);
const evidence = JSON.parse(await readFile(new URL('evidence.schema.json', root), 'utf8'));
ajv.addSchema(report);
ajv.addSchema(evidence);
ajv.addSchema({
  $id: 'wireclaw-case',
  components: api.components,
  $ref: '#/components/schemas/CaseResponse',
});
ajv.addSchema({
  $id: 'wireclaw-deletion',
  components: api.components,
  $ref: '#/components/schemas/DeletionResponse',
});
let validators = standalone(ajv, {
  validReport: report.$id,
  validEvidence: evidence.$id,
  validCase: 'wireclaw-case',
  validDeletion: 'wireclaw-deletion',
});
const helpers = new Set();
validators = validators.replace(
  /require\("ajv\/dist\/runtime\/([A-Za-z0-9]+)"\)\.default/g,
  (_match, name) => {
    helpers.add(name);
    return `runtime_${name}`;
  },
);
if (validators.includes('require(')) throw new Error('Unexpected standalone runtime dependency');
const imports = [...helpers]
  .map(
    (name) =>
      `import helper_${name} from 'ajv/dist/runtime/${name}.js';\nconst runtime_${name} = typeof helper_${name} === 'function' ? helper_${name} : helper_${name}.default;`,
  )
  .join('\n');
await writeFile(
  new URL('../src/generated/validators.js', import.meta.url),
  `${imports}\n${validators}`,
);
await writeFile(
  new URL('../src/generated/validators.d.ts', import.meta.url),
  `import type { Report } from './investigation-result';
import type { Evidence } from './evidence';
import type { components } from './api';
export function validReport(data: unknown): data is Report;
export function validEvidence(data: unknown): data is Evidence;
export function validCase(data: unknown): data is components['schemas']['CaseResponse'];
export function validDeletion(data: unknown): data is components['schemas']['DeletionResponse'];
`,
);
