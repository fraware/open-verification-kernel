// Dependency-free structural tests for the OVK public resource index.
// Run from repository root: node site/tests/catalog_contract.mjs
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const read = (p) => readFileSync(resolve(root,p),'utf8');
const context = {window: {}};
runInNewContext(read('site/assets/catalog.js'), context, {timeout: 1000});
const items = Array.from(context.window.OVK_CATALOG ?? []);
assert.equal(items.length,51, 'curated catalog count unexpectedly changed; review links and description');
const categories = new Set(['Overview','Architecture','Guides','Trust & release','Checkers','Evidence','Research','Examples','Templates']);
const drafts = new Set(['docs/PR_SOURCE_BINDING_V1.md','docs/SOURCE_SCOPED_JOB_SUMMARY.md']);
const seen = new Set();
for (const entry of items) {
  assert.equal(entry.length,5,'resource entry needs title, description, category, path and keywords');
  const [title,description,category,path,keywords] = entry;
  for(const part of [title,description,category,path,keywords]){
    assert.equal(typeof part,'string');
    assert.ok(part.trim(),'empty catalog field');
  }
  assert.ok(categories.has(category),`unknown category: ${category}`);
  assert.ok(!seen.has(path),`duplicate path: ${path}`);
  assert.ok(!path.startsWith('/')&&!path.includes('..'),`non-repository path: ${path}`);
  seen.add(path);
  if(!drafts.has(path)){
    assert.ok(existsSync(resolve(root,path)),`broken repository resource path: ${path}`);
  }
}
assert.ok([...drafts].every(p=>seen.has(p)), 'development-only resources must be labeled in UI');
const html=read('site/index.html'),script=read('site/assets/app.js'),css=read('site/assets/styles.css');
for(const marker of [
  'id="resourceSearch"','id="categoryList"','id="quickResults"',
  'id="resultList"','id="emptyState"','id="totalCount"',
  'id="menuToggle"','id="copyCode"','href="#main"'
])assert.ok(html.includes(marker),`missing HTML control ${marker}`);
for(const asset of ['assets/catalog.js','assets/app.js','assets/styles.css','assets/favicon.svg'])
  assert.ok(existsSync(resolve(root,'site',asset)),`missing asset ${asset}`);
assert.ok(script.includes('Development draft'), 'draft status must be disclosed');
assert.ok(script.includes('837c931d059f74dcda06432d83f5bde759f53d0a'), 'draft links must pin actual source SHA');
assert.ok(script.includes('textContent'), 'render search terms safely as text');
assert.ok(!script.includes('.innerHTML'), 'do not interpolate user search into HTML');
assert.ok(css.includes('prefers-reduced-motion'), 'motion reduction support missing');
console.log(`PASS site resource contract (${items.length} indexed source paths; ${drafts.size} pinned drafts)`);
