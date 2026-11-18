import fs from 'node:fs';

const files = [
  'package.json', 'Dockerfile', 'src/main.js', 'README.md',
  '.actor/actor.json', '.actor/input_schema.json', '.actor/output_schema.json', '.actor/dataset_schema.json',
  '.devcontainer/devcontainer.json'
];

for (const file of files) {
  if (!fs.existsSync(file)) throw new Error(`Missing required file: ${file}`);
}

for (const file of ['.actor/actor.json', '.actor/input_schema.json', '.actor/output_schema.json', '.actor/dataset_schema.json', 'package.json']) {
  JSON.parse(fs.readFileSync(file, 'utf8'));
}

const actor = JSON.parse(fs.readFileSync('.actor/actor.json', 'utf8'));
if (actor.version !== '0.0') throw new Error('actor.json version must remain 0.0');

console.log('Build check passed');
