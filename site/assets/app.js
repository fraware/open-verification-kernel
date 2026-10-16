(() => {
  'use strict';
  const source = Array.isArray(window.OVK_CATALOG) ? window.OVK_CATALOG : [];
  const categories = ['All resources', 'Guides', 'Checkers', 'Evidence', 'Architecture', 'Trust & release', 'Research', 'Examples', 'Templates', 'Overview'];
  const repo = 'https://github.com/fraware/open-verification-kernel/blob/main/';
  const development = new Set(['docs/PR_SOURCE_BINDING_V1.md','docs/SOURCE_SCOPED_JOB_SUMMARY.md']);
  const draftRef = 'https://github.com/fraware/open-verification-kernel/blob/837c931d059f74dcda06432d83f5bde759f53d0a/';
  const entries = source.map(([title, description, category, path, keywords], i) => ({id:i,title, description, category, path, keywords, draft:development.has(path), href:(development.has(path)?draftRef:repo)+path}));
  const els = {
    input: document.getElementById('resourceSearch'), list: document.getElementById('resultList'), quick: document.getElementById('quickResults'),
    cats: document.getElementById('categoryList'), count: document.getElementById('resultsCount'),
    queryContext: document.getElementById('queryContext'), clear: document.getElementById('clearSearch'),
    empty: document.getElementById('emptyState'), reset: document.getElementById('resetAll'),
    more: document.getElementById('showMore'), total: document.getElementById('totalCount'),
    menu: document.getElementById('menuToggle'), mobile: document.getElementById('mobileNav'),
    copy: document.getElementById('copyCode'), copyLabel: document.getElementById('copyLabel'),
    quickCode: document.getElementById('quickStartCode'),
  };
  const state = { query: '', category: 'All resources', limit: 12, suggestionsOpen: false };
  const norm = str => String(str ?? '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  const words = (value) => value.trim().split(/\s+/).filter(Boolean);
  function score(item, queryTerms) {
    if (!queryTerms.length) return 1;
    const title = norm(item.title), desc = norm(item.description), keys = norm(item.keywords), path = norm(item.path), category = norm(item.category);
    let sum = 0;
    for (const word of queryTerms) {
      const aliases = {authentication:'authorization',authn:'authorization',rbac:'authorization',workflows:'workflow',pipelines:'workflow',proofs:'proof',certificates:'certificate'};
      const raw = norm(word); const t = aliases[raw] || raw;
      if (title === t) sum += 30;
      else if (title.startsWith(t)) sum += 17;
      else if (title.includes(t)) sum += 12;
      else if (keys.includes(t)) sum += 8;
      else if (category.includes(t)) sum += 6;
      else if (desc.includes(t)) sum += 5;
      else if (path.includes(t)) sum += 3;
      else return 0;
    }
    return sum;
  }
  function linkify(text, queryTerms) {
    const fragment = document.createDocumentFragment();
    if (!queryTerms.length) { fragment.appendChild(document.createTextNode(text)); return fragment; }
    const sorted = [...new Set(queryTerms)].sort((a,b) => b.length-a.length);
    let at = 0;
    const lower = norm(text);
    while (at < text.length) {
      let bestPos = -1, bestToken = '';
      for (const token of sorted) {
        const pos = lower.indexOf(norm(token), at);
        if (pos >= 0 && (bestPos < 0 || pos < bestPos || pos === bestPos && token.length > bestToken.length)) { bestPos = pos; bestToken = token; }
      }
      if (bestPos < 0) { fragment.appendChild(document.createTextNode(text.slice(at))); break; }
      if (bestPos > at) fragment.appendChild(document.createTextNode(text.slice(at,bestPos)));
      const mark = document.createElement('mark');
      mark.textContent = text.slice(bestPos,bestPos+bestToken.length);
      fragment.appendChild(mark);
      at = bestPos+bestToken.length;
    }
    return fragment;
  }
  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (typeof text === 'string') node.textContent = text;
    return node;
  }
  function renderFilters() {
    const fragment = document.createDocumentFragment();
    for (const cat of categories) {
      const button = element('button','category-button');
      button.type = 'button'; button.setAttribute('aria-pressed',String(state.category === cat));
      const label = element('span','',cat); const count = element('span','cat-count',String(cat === 'All resources' ? entries.length : entries.filter(item=>item.category===cat).length));
      button.append(label,count);
      button.addEventListener('click',() => {state.category = cat; state.limit = 12; render(); syncUrl(); document.getElementById('explore').scrollIntoView({block:'start',behavior: matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});});
      fragment.append(button);
    }
    els.cats.replaceChildren(fragment);
  }
  function filtered() {
    const ts = words(state.query);
    return entries.map(item => ({item, rank:score(item,ts)}))
      .filter(x => x.rank > 0 && (state.category==='All resources'||x.item.category===state.category))
      .sort((a,b)=> b.rank-a.rank || a.item.title.localeCompare(b.item.title))
      .map(x=>x.item);
  }
  function renderCard(item, ts) {
    const a = element('a','resource-card'); a.href=item.href; a.target='_blank'; a.rel='noopener noreferrer';
    a.setAttribute('aria-label',`${item.title} — ${item.category} (opens GitHub in a new tab)`);
    const outer = element('div',''); const top = element('div','card-top');
    top.append(element('span','card-category',item.category + (item.draft?' · Development draft':'')),element('span','card-arrow','↗'));
    const h3 = element('h3'); h3.append(linkify(item.title,ts));
    const p = element('p'); p.append(linkify(item.description,ts));
    outer.append(top,h3,p);
    const path = element('div','card-path',item.path);
    a.append(outer,path);return a;
  }
  function renderQuick(found) {
    const showing = Boolean(state.query.trim()) && state.suggestionsOpen;
    els.quick.hidden = !showing;
    els.input.setAttribute('aria-expanded',String(showing));
    if(!showing){els.quick.replaceChildren();return;}
    const frag = document.createDocumentFragment();
    const label = element('div','quick-heading',`TOP MATCHES · ${found.length} FOUND`);
    frag.append(label);
    for(const item of found.slice(0,4)){
      const anchor = element('a','quick-link');anchor.href=item.href;anchor.target='_blank';anchor.rel='noopener noreferrer';
      anchor.setAttribute('aria-label',`${item.title} (opens GitHub in a new tab)`);
      const name = element('span','',item.title);const meta=element('small','',item.category+(item.draft?' · Draft':''));
      const wrap=element('span','quick-link-text');wrap.append(name,meta);
      anchor.append(wrap,element('span','quick-arrow','↗'));frag.append(anchor);
    }
    if(!found.length)frag.append(element('p','quick-empty','No matches. Try a shorter or different term.'));
    const view=element('button','quick-all',`View all ${found.length} ${found.length===1?'result':'results'} ↓`);
    view.type='button';view.addEventListener('click',()=>{state.suggestionsOpen=false;renderQuick(found);document.getElementById('explore').scrollIntoView({block:'start',behavior:'smooth'});});
    frag.append(view);els.quick.replaceChildren(frag);
  }
  function render() {
    const found = filtered(), tokens=words(state.query);
    renderQuick(found);
    const fragment=document.createDocumentFragment();
    for(const item of found.slice(0,state.limit)) fragment.append(renderCard(item,tokens));
    els.list.replaceChildren(fragment);
    els.count.textContent = `${found.length} ${found.length===1?'resource':'resources'} found`;
    els.queryContext.textContent = state.query ? `for “${state.query}”` : '';
    els.empty.hidden = found.length>0;
    els.more.hidden = found.length<=state.limit;
    if(!els.more.hidden) els.more.textContent=`Show more resources (${found.length-state.limit} remaining) ↓`;
    els.clear.hidden=!state.query && state.category==='All resources';
    renderFilters();
  }
  function syncUrl() {
    const url=new URL(location.href);
    if(state.query) url.searchParams.set('q',state.query); else url.searchParams.delete('q');
    if(state.category!=='All resources')url.searchParams.set('category',state.category);else url.searchParams.delete('category');
    try { history.replaceState(null,'',url.pathname+url.search+url.hash); }
    catch (error) { if (error.name !== 'SecurityError') throw error; } // Embedded/file previews may disallow URL edits.
  }
  function setQuery(value,{focus=true,scroll=true}={}) {
    state.query=value.trimStart().slice(0,160);state.limit=12;state.suggestionsOpen=Boolean(state.query);els.input.value=state.query;render();syncUrl();
    if(scroll)document.getElementById('explore').scrollIntoView({block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});
    if(focus) els.input.focus({preventScroll:true});
  }
  els.input.addEventListener('input',()=>setQuery(els.input.value,{focus:false,scroll:false}));
  els.input.addEventListener('keydown',(e)=>{
    if(e.key==='Escape'){ e.preventDefault();if(state.query)setQuery('',{focus:true,scroll:false});else els.input.blur();}
    if(e.key==='Enter'){const first=els.quick.querySelector('.quick-link')||els.list.querySelector('.resource-card');if(first && state.query){e.preventDefault();first.focus();}}
    if(e.key==='ArrowDown'){const first=els.quick.querySelector('.quick-link')||els.list.querySelector('.resource-card');if(first){e.preventDefault();first.focus();}}
  });
  document.addEventListener('keydown',(e)=>{
    if((e.key==='k'&&(e.metaKey||e.ctrlKey)) || (e.key==='/' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName) && !document.activeElement.isContentEditable)){
      e.preventDefault();els.input.focus({preventScroll:false});els.input.select();
    }
  });
  document.addEventListener('pointerdown',(e)=>{if(!e.target.closest('.hero-search-group')&&state.suggestionsOpen){state.suggestionsOpen=false;renderQuick(filtered());}});
  els.quick.addEventListener('keydown',(e)=>{if(!['ArrowDown','ArrowUp','Escape'].includes(e.key))return;e.preventDefault();if(e.key==='Escape'){state.suggestionsOpen=false;renderQuick(filtered());els.input.focus();return;}const links=[...els.quick.querySelectorAll('a,button')];const i=links.indexOf(document.activeElement);const next=e.key==='ArrowDown'?i+1:i-1;if(next<0)els.input.focus();else if(next<links.length)links[next].focus();});
  for (const b of document.querySelectorAll('[data-query]')) b.addEventListener('click',()=>setQuery(b.dataset.query));
  els.clear.addEventListener('click',()=>{state.category='All resources';setQuery('',{scroll:false});});
  els.reset.addEventListener('click',()=>{state.category='All resources';setQuery('',{scroll:false});});
  els.more.addEventListener('click',()=>{state.limit+=12;render();});
  els.menu.addEventListener('click',()=>{const opening=els.menu.getAttribute('aria-expanded')!=='true';els.menu.setAttribute('aria-expanded',String(opening));els.menu.setAttribute('aria-label',opening?'Close navigation':'Open navigation');els.mobile.hidden=!opening;});
  els.mobile.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{els.mobile.hidden=true;els.menu.setAttribute('aria-expanded','false');els.menu.setAttribute('aria-label','Open navigation');}));
  els.copy.addEventListener('click',async()=>{
    const code=els.quickCode.textContent;
    try {
      if(navigator.clipboard && window.isSecureContext)await navigator.clipboard.writeText(code);
      else {const selection=window.getSelection();const range=document.createRange();range.selectNodeContents(els.quickCode);selection.removeAllRanges();selection.addRange(range);const didCopy=document.execCommand('copy');selection.removeAllRanges();if(!didCopy)throw Error('clipboard unavailable');}
      els.copyLabel.textContent='Copied';els.copy.setAttribute('aria-label','Copied local commands');
    } catch(_){els.copyLabel.textContent='Select code';els.copy.setAttribute('aria-label','Select code to copy');}
  });
  const params=new URLSearchParams(location.search);
  state.query=(params.get('q')||'').slice(0,160);
  const cat=params.get('category');if(categories.includes(cat))state.category=cat;
  els.input.value=state.query;state.suggestionsOpen=Boolean(state.query);
  els.total.textContent=String(entries.length);
  render();
})();
