#!/usr/bin/env node
/**
 * Post-build script to add .js extensions to relative imports
 * Required for Node.js ESM to work with TypeScript compiled output
 */
import { readFileSync, writeFileSync } from 'fs';
import { glob } from 'glob';

const files = await glob('dist/**/*.js', { cwd: process.cwd() });

for (const file of files) {
  let content = readFileSync(file, 'utf8');

  // Add .js extension to relative imports (only if not already present)
  // Matches: import ... from './path' or from '../path'
  content = content.replace(
    /from\s+['"](\.\.[/\\][^'"]+)['"]/g,
    (match, path) => {
      if (path.endsWith('.js')) return match; // Already has .js
      return `from '${path}.js'`;
    }
  );
  content = content.replace(
    /from\s+['"](\.[/\\][^'"]+)['"]/g,
    (match, path) => {
      if (path.endsWith('.js')) return match; // Already has .js
      return `from '${path}.js'`;
    }
  );

  writeFileSync(file, content, 'utf8');
}

console.log(`✅ Fixed imports in ${files.length} files`);
