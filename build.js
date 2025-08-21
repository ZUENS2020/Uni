const esbuild = require('esbuild');
const path = require('path');

esbuild.build({
  entryPoints: [path.resolve(__dirname, 'packages/api/index.js')],
  bundle: true,
  platform: 'node',
  target: 'node16', // Targeting a specific Node.js version
  outfile: path.resolve(__dirname, 'packages/api/dist/bundle.js'),
  external: ['mysql2', 'express', 'cors', 'dotenv'], // We can keep some packages external if they have native bindings
}).catch(() => process.exit(1));
