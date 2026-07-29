var currentData = null;
var currentTaskId = null;
var currentView = 'landing';
var _lookupPollTimer = null;
var _batchPollTimer = null;
var currentInvId = null;
var _currentLookupValue = '';
var sessionHistory = [];
var pivotStack = [];
var compareData = [];

function q(id){return document.getElementById(id)}
function el(tag,html){var e=document.createElement(tag);if(html!==undefined)e.innerHTML=html;return e}
function esc(s){if(s==null)return'';var d=el('div');d.textContent=s;return d.innerHTML}
function vc(v){return'verdict-'+(v||'unknown')}
function cc(v){return'consensus-'+(v||'unknown')}
function sc(v){return'sc-'+(v||'unknown')}

function switchView(view){
  currentView=view;
  document.querySelectorAll('.view').forEach(function(v){if(v)v.classList.remove('is-active')});
  document.querySelectorAll('.nav-btn').forEach(function(b){if(b)b.classList.remove('is-active')});
  var vw=q('view-'+view);if(vw)vw.classList.add('is-active');
  var navMap={landing:'nav-landing',results:'nav-results',investigations:'nav-investigations',batch:'nav-batch',timeline:'nav-timeline',compare:'nav-compare'};
  var nb=q(navMap[view]);if(nb)nb.classList.add('is-active');
  if(view==='landing'){var si=q('search-input');if(si)si.focus()}
  if(view==='results'&&currentData){var oi=q('omnibar-input');if(oi)oi.focus()}
  if(view==='investigations')loadInvestigations();
  if(view==='timeline')renderTimeline();
}

// ---- SESSION HISTORY & PIVOT ----

function addToHistory(iocValue,verdict,score){
  var existing=sessionHistory.length;
  for(var i=0;i<existing;i++){if(sessionHistory[i].ioc===iocValue){sessionHistory.splice(i,1);break}}
  sessionHistory.unshift({ioc:iocValue,verdict:verdict||'unknown',score:score||0,time:Date.now()});
  if(sessionHistory.length>50)sessionHistory.pop();
  updateHistoryUI();
}

function updateHistoryUI(){
  var hc=q('history-count');
  if(hc)hc.textContent=sessionHistory.length||'';
}

function pushPivot(value){
  pivotStack.push({ioc:value,data:currentData});
  if(pivotStack.length>20)pivotStack.shift();
  renderBreadcrumbs();
}

function renderBreadcrumbs(){
  var bc=q('breadcrumbs');
  if(!bc)return;
  if(!pivotStack.length&&sessionHistory.length<2){bc.style.display='none';return}
  bc.style.display='flex';
  var html='';
  pivotStack.forEach(function(p,i){
    html+='<span class="bc-link" onclick="restorePivot('+i+')">'+esc(p.ioc)+'</span>';
    if(i<pivotStack.length-1)html+='<span class="bc-sep">→</span>';
  });
  if(currentData&&pivotStack.length){
    html+='<span class="bc-sep">→</span>';
    html+='<span class="bc-current">'+esc(currentData.normalized||currentData.input)+'</span>';
  }
  bc.innerHTML=html;
}

function restorePivot(idx){
  var entry=pivotStack[idx];
  if(!entry)return;
  currentData=entry.data;
  pivotStack=pivotStack.slice(0,idx);
  renderResults(currentData);
  renderBreadcrumbs();
}

// ---- COMPARE MODE ----

function openCompare(){
  switchView('compare');
  var html='<div class="panel-section"><h3 class="panel-title">IOC Compare</h3>'+
    '<p style="color:var(--muted);margin-bottom:0.75rem">Enter two IOCs to compare side by side</p>'+
    '<div class="compare-inputs">'+
    '<input class="cmp-input" id="cmp-a" placeholder="First IOC (IP, hash, domain...)" style="flex:1;min-width:0"/>'+
    '<span style="color:var(--muted);padding:0 0.5rem">vs</span>'+
    '<input class="cmp-input" id="cmp-b" placeholder="Second IOC" style="flex:1;min-width:0"/>'+
    '<button class="btn btn-primary" onclick="runCompare()">Compare</button></div>'+
    '<div id="compare-spinner" class="spinner" style="display:none;margin:2rem auto"></div>'+
    '<div id="compare-results" style="margin-top:1.5rem"></div></div>';
  q('compare-content').innerHTML=html;
}

function runCompare(){
  var a=q('cmp-a');var b=q('cmp-b');
  if(!a||!b||!a.value.trim()||!b.value.trim()){toast('Enter two IOCs','error');return}
  q('compare-spinner').style.display='block';
  q('compare-results').innerHTML='';
  compareData=[];
  apiPost('/api/lookup',{ioc:a.value.trim()}).then(function(da){
    pollCompareTask(da.task_id,0);
  }).catch(function(err){toast('First IOC failed: '+err.message,'error');q('compare-spinner').style.display='none'});
  apiPost('/api/lookup',{ioc:b.value.trim()}).then(function(db){
    pollCompareTask(db.task_id,1);
  }).catch(function(err){toast('Second IOC failed: '+err.message,'error')});
}

function pollCompareTask(taskId,idx){
  var poll=setInterval(function(){
    apiGet('/api/tasks/'+taskId).then(function(task){
      if(task.status==='done'){
        clearInterval(poll);
        apiGet('/api/tasks/'+taskId+'/result').then(function(data){
          compareData[idx]=data;
          if(compareData[0]&&compareData[1])renderCompare();
        });
      } else if(task.status==='error'){
        clearInterval(poll);
        toast('Compare task '+idx+' failed','error');
      }
    }).catch(function(){clearInterval(poll)});
  },400);
}

function renderCompare(){
  q('compare-spinner').style.display='none';
  var a=compareData[0];var b=compareData[1];
  if(!a||!b){q('compare-results').innerHTML='<div class="empty-state">Compare data unavailable</div>';return}
  var aa=a.composite||{};var ba=b.composite||{};
  var av=aa.verdict||'unknown';var bv=ba.verdict||'unknown';
  var as=Math.round(aa.score||0);var bs=Math.round(ba.score||0);
  var diffScore=as!==bs;
  var diffVerdict=av!==bv;
  var diffClass=diffVerdict?'diff-highlight':'';

  var html='<div class="compare-grid">'+
    '<div class="cmp-col"><div class="cmp-header">'+
      '<div class="cmp-ioc">'+esc(a.normalized||a.input)+'<span class="th-type-badge" style="margin-left:0.4rem">'+esc(a.ioc_type)+'</span></div>'+
      '<div class="cmp-score '+(diffScore?'diff':'')+'"><span class="th-score-num" style="font-size:2rem;color:'+(as>=70?'var(--red)':as>=40?'var(--amber)':'var(--green)')+'">'+as+'</span>/100</div>'+
      '<div class="verdict-badge '+vc(av)+'">'+esc(av)+'</div></div>'+
      '<div class="cmp-sources">'+(a.results||[]).length+' sources</div>'+
    '</div>'+
    '<div class="cmp-vs"><div class="cmp-vs-badge">VS</div>'+(diffVerdict?'<div class="cmp-diff-tag">Different verdict</div>':'')+(diffScore?'<div class="cmp-diff-tag">Score diff: '+Math.abs(as-bs)+'</div>':'')+'</div>'+
    '<div class="cmp-col"><div class="cmp-header">'+
      '<div class="cmp-ioc">'+esc(b.normalized||b.input)+'<span class="th-type-badge" style="margin-left:0.4rem">'+esc(b.ioc_type)+'</span></div>'+
      '<div class="cmp-score '+(diffScore?'diff':'')+'"><span class="th-score-num" style="font-size:2rem;color:'+(bs>=70?'var(--red)':bs>=40?'var(--amber)':'var(--green)')+'">'+bs+'</span>/100</div>'+
      '<div class="verdict-badge '+vc(bv)+'">'+esc(bv)+'</div></div>'+
      '<div class="cmp-sources">'+(b.results||[]).length+' sources</div>'+
    '</div></div>';

  var resultsA=a.results||[];var resultsB=b.results||[];
  var allSources={};
  resultsA.forEach(function(r){allSources[r.source]=1});
  resultsB.forEach(function(r){allSources[r.source]=1});
  html+='<div class="panel-section" style="margin-top:1.5rem"><h3 class="panel-title">Source Comparison</h3></div>'+
    '<table class="data-table cmp-table"><thead><tr><th>Source</th><th>IOC A ('+esc(a.normalized||a.input)+')</th><th>IOC B ('+esc(b.normalized||b.input)+')</th></tr></thead><tbody>';
  Object.keys(allSources).sort().forEach(function(src){
    var ra=resultsA.filter(function(r){return r.source===src})[0]||{};
    var rb=resultsB.filter(function(r){return r.source===src})[0]||{};
    var va=ra.verdict||'—';var vb=rb.verdict||'—';
    var sa=ra.raw_score!=null?Math.round(ra.raw_score*100)+'/100':'—';
    var sb=rb.raw_score!=null?Math.round(rb.raw_score*100)+'/100':'—';
    var rowDiff=va!=='—'&&vb!=='—'&&va!==vb;
    html+='<tr><td><strong>'+esc(src)+'</strong></td>'+
      '<td class="'+(rowDiff?'diff-highlight':'')+'"><span class="verdict-badge '+vc(va)+'" style="font-size:0.7rem">'+esc(va)+'</span> <span style="font-size:0.7rem;opacity:0.7">'+esc(sa)+'</span></td>'+
      '<td class="'+(rowDiff?'diff-highlight':'')+'"><span class="verdict-badge '+vc(vb)+'" style="font-size:0.7rem">'+esc(vb)+'</span> <span style="font-size:0.7rem;opacity:0.7">'+esc(sb)+'</span></td></tr>';
  });
  html+='</tbody></table>';

  var enA=a.enrichment||{};var enB=b.enrichment||{};
  html+='<div class="panel-section" style="margin-top:1rem"><h3 class="panel-title">Enrichment Comparison</h3></div>'+
    '<div class="compare-enrich-grid"><div class="cmp-enrich-col">'+
    '<h4 style="margin-bottom:0.5rem">'+esc(a.normalized||a.input)+'</h4>'+overviewEnrichment(enA)+'</div>'+
    '<div class="cmp-enrich-col"><h4 style="margin-bottom:0.5rem">'+esc(b.normalized||b.input)+'</h4>'+overviewEnrichment(enB)+'</div></div>';

  q('compare-results').innerHTML=html;
}

function toast(msg,type){
  var e=el('div');e.className='toast toast-'+(type||'success');e.textContent=msg;
  document.body.appendChild(e);setTimeout(function(){if(e.parentNode)e.remove()},3000)
}

function apiGet(url){return fetch(url).then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(r.status+' '+t)});return r.json()})}
function apiPost(url,body){return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(r.status+' '+t)});return r.json()})}

function openModal(title,bodyHtml){
  q('modal-title').textContent=title;
  q('modal-body').innerHTML=bodyHtml;
  q('modal').classList.add('is-active');
  q('modal-overlay').classList.add('is-active');
}
function closeModal(){
  q('modal').classList.remove('is-active');
  q('modal-overlay').classList.remove('is-active');
}

// ---- LOOKUP ----

function doLookup(value){
  if(!value||!value.trim())return;
  _currentLookupValue=value.trim();
  var normalizedValue=value.trim();
  ['landing-error','results-error'].forEach(function(id){var e=q(id);if(e)e.hidden=true});

  if(currentView==='landing'){
    var ls=q('landing-spinner');if(ls)ls.hidden=false;
  } else {
    var rc=q('result-content');if(rc)rc.classList.remove('is-active');
    var pip=q('pipeline-progress');if(pip)pip.classList.remove('is-active');
    var rs=q('results-spinner');if(rs)rs.hidden=false;
  }

  apiPost('/api/lookup',{ioc:normalizedValue}).then(function(data){
    ['landing-spinner','results-spinner'].forEach(function(id){var e=q(id);if(e)e.hidden=true});
    currentTaskId=data.task_id;
    switchView('results');
    q('results-spinner').hidden=true;
    showPipeline(data.task_id,data.ioc_value);
  }).catch(function(err){
    ['landing-spinner','results-spinner'].forEach(function(id){var e=q(id);if(e)e.hidden=true});
    var eid=currentView==='results'?'results-error':'landing-error';
    var ee=q(eid);if(ee){ee.textContent=err.message;ee.hidden=false}
  });
}

function showPipeline(taskId,iocValue){
  q('pipeline-progress').classList.add('is-active');
  q('result-content').classList.remove('is-active');
  q('save-to-inv-btn').classList.remove('is-active');

  var searchVal=_currentLookupValue||iocValue;
  var oi=q('omnibar-input');if(oi)oi.value=searchVal;

  var stagesContainer=q('pipeline-stages');
  stagesContainer.innerHTML='<div class="pl-stage is-active"><span class="pl-icon"></span>Starting...</div>';

  if(_lookupPollTimer)clearInterval(_lookupPollTimer);
  _lookupPollTimer=setInterval(function(){pollTask(taskId)},600);
  pollTask(taskId);
}

function pollTask(taskId){
  apiGet('/api/tasks/'+taskId).then(function(task){
    renderPipeline(task);

    if(task.status==='done'){
      clearInterval(_lookupPollTimer);_lookupPollTimer=null;
      fetchResult(taskId);
    } else if(task.status==='error'){
      clearInterval(_lookupPollTimer);_lookupPollTimer=null;
      q('pipeline-progress').classList.remove('is-active');
      var ee=q('results-error');if(ee){ee.textContent=task.error||'Analysis failed';ee.hidden=false}
    }
  }).catch(function(err){
    clearInterval(_lookupPollTimer);_lookupPollTimer=null;
    q('pipeline-progress').classList.remove('is-active');
    var ee=q('results-error');if(ee){var msg=err.message||'';ee.textContent=msg.indexOf('404')>-1?'Task expired — submit again':msg;ee.hidden=false}
  });
}

function renderPipeline(task){
  var fill=q('pipeline-fill');if(fill)fill.style.width=task.progress+'%';

  if(task.stages&&task.stages.length){
    var c=q('pipeline-stages');
    c.innerHTML=task.stages.map(function(s){
      var cls='pl-stage pl-'+s.status;
      if(s.status==='running')cls+=' is-active';
      return '<div class="'+cls+'"><span class="pl-icon"></span>'+esc(s.name)+(s.message?' <span style="font-size:0.65rem;opacity:0.7">'+esc(s.message)+'</span>':'')+'</div>';
    }).join('');
  }
}

function fetchResult(taskId){
  apiGet('/api/tasks/'+taskId+'/result').then(function(data){
    currentData=data;
    var iocVal=data.normalized||data.input||'';
    var comp=data.composite||{};
    addToHistory(iocVal,comp.verdict,comp.score||0);
    renderBreadcrumbs();
    renderResults(data);
    q('pipeline-progress').classList.remove('is-active');
    q('result-content').classList.add('is-active');
    q('save-to-inv-btn').classList.add('is-active');
    var nr=q('nav-results');if(nr)nr.style.display='inline-block';
  }).catch(function(err){
    var ee=q('results-error');if(ee){ee.textContent=err.message;ee.hidden=false}
    q('pipeline-progress').style.display='none';
  });
}

// ---- RENDER RESULTS ----

function renderResults(data){
  var c=data.composite||{};
  var score=c.score||0;
  var verdict=c.verdict||'unknown';
  var conf=c.confidence||'low';
  var results=data.results||[];
  var enrich=data.enrichment||{};
  var rels=data.relationships||[];

  var h='<div class="th-header-top">'+
    '<div class="th-score-wrap">'+
      '<svg class="th-score-ring" viewBox="0 0 80 80"><circle class="th-score-bg" cx="40" cy="40" r="34"/><circle class="th-score-fill" id="sfill" cx="40" cy="40" r="34" stroke-dasharray="213.6" stroke-dashoffset="213.6"/></svg>'+
      '<div class="th-score-text"><span class="th-score-num" id="snum">'+Math.round(score)+'</span><span class="th-score-label">score</span></div>'+
    '</div>'+
    '<div class="th-info">'+
      '<div class="th-ioc-row"><span class="th-ioc">'+esc(data.normalized||data.input)+'</span><span class="th-type-badge">'+esc(data.ioc_type||'unknown')+'</span></div>'+
      '<div class="th-verdict-row"><span class="verdict-badge '+vc(verdict)+'">'+esc(verdict)+'</span><span class="confidence-badge '+confClass(conf)+'">'+esc(conf)+' confidence</span>'+
        '<span style="color:var(--muted);font-size:0.78rem">'+c.sources_contributing+' sources</span></div>'+
      '<div class="th-meta">'+
        '<span><strong>Sources:</strong> '+results.length+'</span>'+
        '<span><strong>Relationships:</strong> '+rels.length+'</span>'+
      '</div>'+
    '</div>'+
  '</div>';

  var brk={malicious:0,suspicious:0,clean:0,unknown:0};
  results.forEach(function(r){if(brk[r.verdict]!==undefined)brk[r.verdict]++});
  var totalR=results.length||1;
  var barHtml='<div class="breakdown-bar">';
  ['malicious','suspicious','clean','unknown'].forEach(function(v){if(brk[v]>0)barHtml+='<div class="brk-'+v+'" style="flex:'+brk[v]+'"></div>'});
  barHtml+='</div>';

  var consHtml='';
  ['malicious','suspicious','clean','unknown','error'].forEach(function(v){if(brk[v])consHtml+='<span class="consensus-pill '+cc(v)+'">'+brk[v]+' '+v+'</span>'});

  q('threat-header').innerHTML=h;

  var es = data.executive_summary || '';
  if (es) {
    q('executive-summary-content').textContent = es;
    q('view-toggle').style.display = 'flex';

    var evb = q('exec-verdict-badge');
    if (evb) { evb.textContent = verdict; evb.className = 'exec-verdict-badge verdict-badge ' + vc(verdict); }
    var esn = q('exec-score-num');
    if (esn) { esn.textContent = Math.round(score) + '/100'; esn.style.color = score >= 70 ? 'var(--red)' : score >= 40 ? 'var(--amber)' : 'var(--green)'; }

    var action = '';
    var actionClass = '';
    if (score >= 70 && verdict === 'malicious') { action = 'BLOCK'; actionClass = 'action-block'; }
    else if (score >= 40 && (verdict === 'malicious' || verdict === 'suspicious')) { action = 'MONITOR'; actionClass = 'action-monitor'; }
    else { action = 'NO ACTION'; actionClass = 'action-clear'; }
    var eab = q('exec-action-badge');
    if (eab) { eab.textContent = action; eab.className = 'exec-action-badge ' + actionClass; }
    var esa = q('executive-summary-action');
    if (esa) {
      var reason = action === 'BLOCK' ? 'Immediate blocking recommended due to high-severity threat indicators.' :
                   action === 'MONITOR' ? 'Caution advised â€” monitor for further suspicious activity.' :
                   'No immediate action required; no threat indicators detected.';
      esa.innerHTML = '<div class="action-recommendation ' + actionClass + '"><strong>Recommended Action:</strong> ' + reason + '</div>';
    }

    switchResultView('analyst');
  } else {
    q('view-toggle').style.display = 'none';
  }

  var ring=q('sfill');
  if(ring){
    var circ=2*Math.PI*34;
    var off=circ-(Math.min(score,100)/100)*circ;
    ring.style.strokeDashoffset=off;
    ring.className='score-ring score-'+(score>=70?'high':score>=40?'medium':'low');
  }
  var sn=q('snum');
  if(sn){sn.textContent=Math.round(score);sn.className='th-score-num score-'+(score>=70?'high':score>=40?'medium':'low')}

  var comp=enrich.completeness||{};
  var compKeys=Object.keys(comp);
  var compBadges='';
  if(compKeys.length){
    compBadges='<div class="panel-section"><h3 class="panel-title">Enrichment Data Sources <span class="comp-badge-hint">(ok / error / skip)</span></h3><div class="comp-overview-grid">';
    compKeys.forEach(function(k){
      var v=comp[k];
      var cls=v==='ok'?'comp-ok':v==='error'?'comp-error':'comp-skip';
      compBadges+='<span class="comp-overview-chip '+cls+'" title="'+esc(k)+': '+esc(v)+'">'+esc(k)+'</span>';
    });
    compBadges+='</div></div>';
  }

  q('panel-overview').innerHTML='<div class="panel-section"><h3 class="panel-title">Consensus</h3><div class="consensus-grid">'+(consHtml||'<span class="consensus-pill consensus-unknown">No results</span>')+'</div>'+barHtml+'</div>'+
    '<div class="panel-section"><h3 class="panel-title">Enrichment Summary</h3>'+overviewEnrichment(enrich)+'</div>'+
    compBadges+
    '<div class="panel-section"><h3 class="panel-title">Source Results</h3><div class="source-cards" id="ov-cards">'+results.map(function(r){return sourceCard(r,false)}).join('')+'</div></div>';

  q('panel-sources').innerHTML='<div class="panel-section"><h3 class="panel-title">Detailed Source Data</h3><div class="source-cards">'+results.map(function(r){return sourceCard(r,true)}).join('')+'</div></div>';

  q('panel-enrichment').innerHTML=renderEnrichment(enrich,data.ioc_type);

  var relHtml='<div class="panel-section"><h3 class="panel-title">Relationships</h3>';
  if(rels.length===0){
    relHtml+='<div class="empty-state">No relationships found</div>';
  } else {
    relHtml+='<div class="table-wrap"><table class="data-table"><thead><tr><th>Target IOC</th><th>Relationship</th><th>Via Source</th></tr></thead><tbody>';
    rels.forEach(function(rr){
      relHtml+='<tr><td class="clickable" onclick="doLookup(\''+esc(rr.target_ioc)+'\')">'+esc(rr.target_ioc)+'</td><td>'+esc(rr.relationship)+'</td><td>'+esc(rr.via_source)+'</td></tr>';
    });
    relHtml+='</tbody></table></div>';
  }
  relHtml+='<div class="graph-placeholder">Pivot by clicking any related IOC above</div></div>';
  q('panel-relations').innerHTML=relHtml;

  var gr=q('panel-graph');
  if(gr)gr.innerHTML=renderGraph(data);

  q('panel-export').innerHTML='<div class="panel-section"><h3 class="panel-title">Download / Copy</h3><div class="export-actions">'+
    '<button class="btn btn-secondary" id="export-json"><svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1v10M4 7l4 4 4-4M2 13h12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg> Download JSON</button>'+
    '<button class="btn btn-secondary" id="export-csv"><svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1v10M4 7l4 4 4-4M2 13h12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg> Download CSV</button>'+
    '<button class="btn btn-secondary" id="export-stix"><svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1v10M4 7l4 4 4-4M2 13h12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg> Export STIX</button>'+
    '<button class="btn btn-secondary" id="export-clipboard"><svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="3" y="5" width="10" height="10" rx="2" stroke="currentColor" stroke-width="1.5"/><path d="M5 5V3a1 1 0 011-1h4a1 1 0 011 1v2" stroke="currentColor" stroke-width="1.5"/></svg> Copy to Clipboard</button>'+
    '<button class="btn btn-secondary" id="export-report"><svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 1h10v14H3V1z" stroke="currentColor" stroke-width="1.5"/><path d="M6 4h4M6 7h4M6 10h2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> Download Report</button></div>'+
    '<div class="export-section"><h4>SIEM Export</h4><div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.4rem">'+
    '<button class="btn btn-secondary" onclick="siemExport(\'splunk\')">Splunk KV</button>'+
    '<button class="btn btn-secondary" onclick="siemExport(\'ecs\')">Elastic ECS</button>'+
    '<button class="btn btn-secondary" onclick="siemExport(\'leef\')">IBM LEEF</button></div></div>'+
    '<div class="export-section"><h4>MISP Export</h4>'+
    '<button class="btn btn-secondary" onclick="mispExport()">Export MISP Event</button>'+
    '<p style="font-size:0.72rem;color:var(--faint);margin-top:0.3rem">MISP server push requires API key — file download used instead</p></div>'+
    '<pre class="export-preview">'+esc(JSON.stringify(data,null,2))+'</pre></div>';

  wireExports(data);
  q('result-content').style.display='block';
}

function overviewEnrichment(enrich){
  var html='<div class="enrichment-slim-grid">';
  var geo=enrich.geoip||{};
  if(geo.country||geo.city||geo.asn){
    html+='<div class="e-card"><div class="e-card-title">GeoIP</div>';
    if(geo.country)html+='<div class="e-row"><span class="e-label">Country</span><span class="e-value">'+esc(geo.country)+'</span></div>';
    if(geo.city)html+='<div class="e-row"><span class="e-label">City</span><span class="e-value">'+esc(geo.city)+'</span></div>';
    if(geo.asn)html+='<div class="e-row"><span class="e-label">ASN</span><span class="e-value">'+esc(geo.asn)+'</span></div>';
    if(geo.org)html+='<div class="e-row"><span class="e-label">Org</span><span class="e-value">'+esc(geo.org)+'</span></div>';
    html+='</div>';
  }
  var who=enrich.whois||{};
  if(who.org||who.registrar){
    html+='<div class="e-card"><div class="e-card-title">WHOIS</div>';
    if(who.registrar)html+='<div class="e-row"><span class="e-label">Registrar</span><span class="e-value">'+esc(who.registrar)+'</span></div>';
    if(who.org)html+='<div class="e-row"><span class="e-label">Org</span><span class="e-value">'+esc(who.org)+'</span></div>';
    if(who.abuse_email)html+='<div class="e-row"><span class="e-label">Abuse</span><span class="e-value">'+esc(who.abuse_email)+'</span></div>';
    html+='</div>';
  }
  var rdns=enrich.reverse_dns||{};
  if(rdns.hostnames&&rdns.hostnames.length){
    html+='<div class="e-card"><div class="e-card-title">Reverse DNS</div>'+
      rdns.hostnames.map(function(h){return'<div class="e-row"><span class="e-value">'+esc(h)+'</span></div>'}).join('')+'</div>';
  }
  var dns=enrich.dns||{};
  if(dns.a&&dns.a.length){
    html+='<div class="e-card"><div class="e-card-title">DNS A</div>'+
      dns.a.slice(0,4).map(function(a){return'<div class="e-row"><span class="e-value">'+esc(a)+'</span></div>'}).join('')+'</div>';
  }
  var cv=enrich.cve||{};
  if(cv.is_in_kev){
    html+='<div class="e-card"><div class="e-card-title">CISA KEV</div><div class="e-row"><span class="e-value" style="color:var(--red);font-weight:700">Known exploited vulnerability</span></div></div>';
  }
  if(cv.epss_score>0){
    html+='<div class="e-card"><div class="e-card-title">EPSS</div><div class="e-row"><span class="e-value">'+(cv.epss_score*100).toFixed(2)+'% probability of exploitation</span></div></div>';
  }
  var br=enrich.breach||{};
  if(br.breach_count>0){
    html+='<div class="e-card"><div class="e-card-title">Breaches</div><div class="e-row"><span class="e-value" style="color:var(--red);font-weight:700">'+br.breach_count+' known breaches</span></div></div>';
  }
  var es=enrich.email_security||{};
  if(es.spf||es.dkim||es.dmarc){
    html+='<div class="e-card"><div class="e-card-title">Email Security</div>'+
      (es.spf!=='pass'&&es.spf!=='missing'?'<div class="e-row"><span class="e-label">SPF</span><span class="e-value" style="color:var(--red)">'+esc(es.spf)+'</span></div>':'')+
      (es.dkim!=='pass'&&es.dkim!=='missing'?'<div class="e-row"><span class="e-label">DKIM</span><span class="e-value" style="color:var(--red)">'+esc(es.dkim)+'</span></div>':'')+
      (es.dmarc!=='pass'&&es.dmarc!=='missing'?'<div class="e-row"><span class="e-label">DMARC</span><span class="e-value" style="color:var(--red)">'+esc(es.dmarc)+'</span></div>':'')+
    '</div>';
  }
  var comp=enrich.completeness||{};
  var compKeys=Object.keys(comp);
  if(compKeys.length){
    html+='<div class="e-card"><div class="e-card-title">Completeness</div>';
    compKeys.forEach(function(k){html+='<div class="e-row"><span class="e-label">'+esc(k)+'</span><span class="e-value '+(comp[k]==='ok'?'comp-ok':comp[k]==='error'?'comp-error':'comp-skip')+'">'+esc(comp[k])+'</span></div>'});
    html+='</div>';
  }

  html+='</div>';
  return html;
}

function renderEnrichment(enrich,iocType){
  var html='<div class="panel-section"><h3 class="panel-title">Deep Enrichment</h3>';

  var comp=enrich.completeness||{};
  var compKeys=Object.keys(comp);
  if(compKeys.length){
    html+='<div class="panel-section"><h4 class="panel-title">Completeness</h4><div class="enrichment-slim-grid">';
    compKeys.forEach(function(k){
      var v=comp[k];
      var cls=v==='ok'?'comp-ok':v==='error'?'comp-error':'comp-skip';
      html+='<span class="comp-chip '+cls+'">'+esc(k)+': '+esc(v)+'</span>';
    });
    html+='</div></div>';
  }

  html+='<div class="enrichment-grid">';

  var geo=enrich.geoip||{};
  html+='<div class="e-card"><div class="e-card-title">GeoIP</div>';
  var geoRows=[['Country',geo.country],['Country Code',geo.country_code],['City',geo.city],['ASN',geo.asn],['ASN Name',geo.asn_name],['ISP',geo.isp],['Organization',geo.org],['Latitude',geo.latitude],['Longitude',geo.longitude]];
  var hasGeo=false;
  geoRows.forEach(function(rr){if(rr[1]){html+='<div class="e-row"><span class="e-label">'+rr[0]+'</span><span class="e-value">'+esc(rr[1])+'</span></div>';hasGeo=true}});
  if(!hasGeo)html+='<div class="empty-state" style="padding:1rem 0">No GeoIP data</div>';
  html+='</div>';

  var who=enrich.whois||{};
  html+='<div class="e-card"><div class="e-card-title">WHOIS / RDAP</div>';
  var whoRows=[['Registrar',who.registrar],['Organization',who.org],['Abuse Email',who.abuse_email],['Creation Date',who.creation_date],['Expiration Date',who.expiration_date]];
  var hasWho=false;
  whoRows.forEach(function(rr){if(rr[1]){html+='<div class="e-row"><span class="e-label">'+rr[0]+'</span><span class="e-value">'+esc(rr[1])+'</span></div>';hasWho=true}});
  if(!hasWho)html+='<div class="empty-state" style="padding:1rem 0">No WHOIS data</div>';
  html+='</div>';

  var ports=enrich.open_ports||[];
  if(ports.length){
    html+='<div class="e-card"><div class="e-card-title">Open Ports</div>';
    ports.forEach(function(p){
      var serviceName={21:'FTP',22:'SSH',25:'SMTP',80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',993:'IMAPS',995:'POP3S',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',8080:'HTTP-Alt',8443:'HTTPS-Alt'}[p]||'';
      html+='<div class="e-row"><span class="e-value" style="font-family:monospace">Port '+esc(p)+(serviceName?' <span style="opacity:0.6">('+serviceName+')</span>':'')+'</span></div>';
    });
    html+='</div>';
  }

  html+='</div>';

  var dns=enrich.dns||{};
  var rdns=enrich.reverse_dns||{};
  var ssl=enrich.ssl||{};
  var hasExtra=dns.a||dns.aaaa||dns.mx||dns.ns||rdns.hostnames||ssl.subject;

  if(hasExtra){
    html+='<div class="enrichment-slim-grid">';
    if(rdns.hostnames&&rdns.hostnames.length){
      html+='<div class="e-card"><div class="e-card-title">Reverse DNS</div>'+
        rdns.hostnames.map(function(h){return'<div class="e-row"><span class="e-value">'+esc(h)+'</span></div>'}).join('')+'</div>';
    }
    if(dns.a&&dns.a.length){
      html+='<div class="e-card"><div class="e-card-title">DNS A Records</div>'+
        dns.a.map(function(a){return'<div class="e-row"><span class="e-value">'+esc(a)+'</span></div>'}).join('')+'</div>';
    }
    if(dns.aaaa&&dns.aaaa.length){
      html+='<div class="e-card"><div class="e-card-title">DNS AAAA Records</div>'+
        dns.aaaa.map(function(a){return'<div class="e-row"><span class="e-value">'+esc(a)+'</span></div>'}).join('')+'</div>';
    }
    if(dns.mx&&dns.mx.length){
      html+='<div class="e-card"><div class="e-card-title">DNS MX Records</div>'+
        dns.mx.map(function(m){return'<div class="e-row"><span class="e-value">'+esc(m)+'</span></div>'}).join('')+'</div>';
    }
    if(ssl.subject){
      html+='<div class="e-card"><div class="e-card-title">SSL Certificate</div>'+
        [['Subject',ssl.subject],['Issuer',ssl.issuer],['Not Before',ssl.not_before],['Not After',ssl.not_after],['Serial',ssl.serial]].map(function(rr){if(rr[1])return'<div class="e-row"><span class="e-label">'+rr[0]+'</span><span class="e-value">'+esc(rr[1])+'</span></div>'}).join('')+
        (ssl.is_expired!==undefined?'<div class="e-row"><span class="e-label">Expired</span><span class="e-value" style="color:'+(ssl.is_expired?'var(--red)':'var(--green)')+'">'+(ssl.is_expired?'Yes':'No')+'</span></div>':'')+
        (ssl.days_remaining!==undefined?'<div class="e-row"><span class="e-label">Days Remaining</span><span class="e-value" style="color:'+(ssl.days_remaining<30?'var(--red)':ssl.days_remaining<90?'var(--amber)':'var(--green)')+'">'+ssl.days_remaining+'</span></div>':'')+
        (ssl.is_self_signed!==undefined?'<div class="e-row"><span class="e-label">Self-Signed</span><span class="e-value" style="color:'+(ssl.is_self_signed?'var(--amber)':'var(--green)')+'">'+(ssl.is_self_signed?'Yes':'No')+'</span></div>':'')+
        (ssl.is_wildcard!==undefined?'<div class="e-row"><span class="e-label">Wildcard</span><span class="e-value">'+(ssl.is_wildcard?'Yes':'No')+'</span></div>':'')+
        (ssl.subject_alt_names&&ssl.subject_alt_names.length?'<div class="e-row"><span class="e-label">SAN</span><span class="e-value" style="font-size:0.7rem">'+ssl.subject_alt_names.slice(0,10).join('<br>')+(ssl.subject_alt_names.length>10?'<br><span style="opacity:0.6">+ '+(ssl.subject_alt_names.length-10)+' more</span>':'')+'</span></div>':'')+
      '</div>';
    }
    html+='</div>';
  }

  var sub=enrich.subdomains||{};
  if(sub.subdomains&&sub.subdomains.length){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">Subdomains (crt.sh)</div>'+
      sub.subdomains.slice(0,20).map(function(s){return'<div class="e-row"><span class="e-value">'+esc(s)+'</span></div>'}).join('')+
      (sub.subdomains.length>20?'<div class="e-row" style="opacity:0.6">+ '+(sub.subdomains.length-20)+' more</div>':'')+
    '</div></div>';
  }

  var pdns=enrich.passive_dns||{};
  var pdnsRecords=pdns.records||[];
  if(pdnsRecords.length){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">Passive DNS</div>';
    pdnsRecords.slice(0,30).forEach(function(rr){
      var val=rr.domain||rr.hostname||rr.ip||rr.type||JSON.stringify(rr);
      html+='<div class="e-row"><span class="e-value" style="font-size:0.75rem;font-family:monospace">'+esc(val)+'</span></div>';
    });
    if(pdnsRecords.length>30)html+='<div class="e-row" style="opacity:0.6">+ '+(pdnsRecords.length-30)+' more</div>';
    html+='</div></div>';
  }

  var fi=enrich.favicon||{};
  if(fi.favicon_hash){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">Favicon</div>'+
      '<div class="e-row"><span class="e-label">mmh3 Hash</span><span class="e-value">'+fi.favicon_hash+'</span></div>'+
      (fi.favicon_url?'<div class="e-row"><span class="e-label">Source</span><span class="e-value" style="font-size:0.7rem;word-break:break-all">'+esc(fi.favicon_url)+'</span></div>':'')+
    '</div></div>';
  }

  var cv=enrich.cve||{};
  if(cv.cvss_vector||cv.is_in_kev||cv.epss_score>0||cv.public_exploits_exist||cv.poc_available){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">CVE Intelligence</div>';
    if(cv.is_in_kev)html+='<div class="e-row"><span class="e-label">CISA KEV</span><span class="e-value" style="color:var(--red);font-weight:700">Exploited in the wild'+(cv.kev_date_added?' — '+esc(cv.kev_date_added):'')+'</span></div>';
    if(cv.epss_score>0)html+='<div class="e-row"><span class="e-label">EPSS Score</span><span class="e-value">'+(cv.epss_score*100).toFixed(2)+'% (p'+(cv.epss_percentile*100).toFixed(1)+')</span></div>';
    if(cv.public_exploits_exist)html+='<div class="e-row"><span class="e-label">Exploit-DB</span><span class="e-value" style="color:var(--red);font-weight:700">Public exploits exist</span></div>';
    if(cv.poc_available)html+='<div class="e-row"><span class="e-label">GitHub PoC</span><span class="e-value" style="color:var(--red);font-weight:700">Proof of concept available</span></div>';
    if(cv.cvss_vector)html+='<div class="e-row"><span class="e-label">CVSS Vector</span><span class="e-value" style="font-size:0.7rem;word-break:break-all">'+esc(cv.cvss_vector)+'</span></div>';
    if(cv.cwe&&cv.cwe.length)html+='<div class="e-row"><span class="e-label">CWE</span><span class="e-value">'+cv.cwe.map(function(w){return esc(w)}).join(', ')+'</span></div>';
    if(cv.affected_products&&cv.affected_products.length)html+='<div class="e-row"><span class="e-label">Affected Products</span><span class="e-value">'+cv.affected_products.slice(0,5).join(', ')+(cv.affected_products.length>5?' +'+(cv.affected_products.length-5)+' more':'')+'</span></div>';
    if(cv.references&&cv.references.length)html+='<div class="e-row"><span class="e-label">References</span><span class="e-value" style="font-size:0.7rem">'+cv.references.slice(0,5).map(function(rr){return'<a href="'+esc(rr)+'" target="_blank" rel="noopener" style="color:var(--primary);display:block">'+esc(rr)+'</a>'}).join('')+(cv.references.length>5?'<span style="opacity:0.6">+ '+(cv.references.length-5)+' more</span>':'')+'</span></div>';
    html+='</div></div>';
  }

  var br=enrich.breach||{};
  if(br.breach_count>0){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">Breach Data</div>'+
      '<div class="e-row"><span class="e-label">Breaches</span><span class="e-value" style="color:var(--red);font-weight:700">'+br.breach_count+'</span></div>'+
      (br.most_recent_breach?'<div class="e-row"><span class="e-label">Most Recent</span><span class="e-value">'+esc(br.most_recent_breach)+'</span></div>':'')+
      (br.breach_names&&br.breach_names.length?'<div class="e-row"><span class="e-label">Names</span><span class="e-value">'+br.breach_names.slice(0,10).map(function(b){return esc(b)}).join(', ')+(br.breach_names.length>10?' +'+(br.breach_names.length-10)+' more':'')+'</span></div>':'')+
    '</div></div>';
  } else if(br.breach_count===0&&enrich.completeness&&enrich.completeness.breach==='ok'){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">Breach Data</div><div class="e-row"><span class="e-value" style="color:var(--green)">No known breaches</span></div></div></div>';
  }

  var es=enrich.email_security||{};
  if(es.spf||es.dkim||es.dmarc){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">Email Security</div>'+
      '<div class="e-row"><span class="e-label">SPF</span><span class="e-value '+(es.spf==='pass'?'comp-ok':'comp-error')+'">'+esc(es.spf)+'</span></div>'+
      '<div class="e-row"><span class="e-label">DKIM</span><span class="e-value '+(es.dkim==='pass'?'comp-ok':'comp-error')+'">'+esc(es.dkim)+'</span></div>'+
      '<div class="e-row"><span class="e-label">DMARC</span><span class="e-value '+(es.dmarc==='pass'?'comp-ok':'comp-error')+'">'+esc(es.dmarc)+'</span></div>'+
    '</div></div>';
  }

  var redirect=enrich.redirect_chain||[];
  if(redirect.length){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">Redirect Chain</div>';
    redirect.forEach(function(rr,idx){
      var arrow=idx<redirect.length-1?' <span style="color:var(--text-muted)">→</span>':'';
      html+='<div class="e-row" style="font-size:0.75rem;font-family:monospace;word-break:break-all">'+
        '<span class="e-label">Step '+(idx+1)+' ['+rr.status+']</span>'+
        '<span class="e-value">'+esc(rr.url)+arrow+'</span></div>';
    });
    html+='</div></div>';
  }

  var preview=enrich.url_preview||{};
  if(preview.title){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">Page Preview</div>'+
      (preview.title?'<div class="e-row"><span class="e-label">Title</span><span class="e-value" style="font-weight:600">'+esc(preview.title)+'</span></div>':'')+
      (preview.meta_description?'<div class="e-row"><span class="e-label">Description</span><span class="e-value" style="font-size:0.75rem">'+esc(preview.meta_description)+'</span></div>':'')+
      (preview.text_preview?'<div class="e-row"><span class="e-label">Text Preview</span><span class="e-value" style="font-size:0.7rem;opacity:0.8">'+esc(preview.text_preview)+'</span></div>':'')+
    '</div></div>';
  }

  var extra=enrich.extra||{};
  var dnsbl=extra.dnsbl_result||[];
  if(dnsbl.length){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">DNSBL Check</div>';
    dnsbl.forEach(function(dd){
      html+='<div class="e-row"><span class="e-value" style="color:var(--red)">Listed on '+esc(dd.blacklist)+'</span></div>';
    });
    html+='</div></div>';
  }

  var exdb=(extra.exploitdb||[]);
  var pocG=(extra.poc_github||[]);
  if(exdb.length||pocG.length){
    html+='<div class="enrichment-slim-grid"><div class="e-card"><div class="e-card-title">Exploit & PoC</div>';
    exdb.forEach(function(ex){
      html+='<div class="e-row"><span class="e-label">Exploit-DB</span><span class="e-value"><a href="'+esc(ex.url)+'" target="_blank" rel="noopener" style="color:var(--primary)">'+esc(ex.id)+'</a></span></div>';
    });
    pocG.forEach(function(pc){
      html+='<div class="e-row"><span class="e-label">GitHub PoC</span><span class="e-value"><a href="'+esc(pc.url)+'" target="_blank" rel="noopener" style="color:var(--primary)">'+esc(pc.name)+'</a> <span style="opacity:0.6">â­'+pc.stars+'</span></span></div>';
    });
    html+='</div></div>';
  }

  html+='</div>';
  return html;
}

function sourceCard(r,detailed){
  var v=r.verdict||'unknown';
  if(r.source==='URLhaus'&&r.malware_family){
    var famTag='threat: '+r.malware_family;
    if((r.tags||[]).indexOf(famTag)===-1)r.tags=r.tags||[];r.tags.push(famTag)
  }
  if(r.source==='URLhaus'&&!r.source_link&&currentData&&currentData.ioc){
    r.source_link='https://urlhaus.abuse.ch/browse.php?search='+encodeURIComponent(currentData.ioc);
  }
  var tags=(r.tags||[]).map(function(t){return'<span class="sc-tag">'+esc(t)+'</span>'}).join('');
  var cats=(r.categories||[]).map(function(c){return'<span class="cat-chip">'+esc(c)+'</span>'}).join('');
  var mitre=(r.mitre_attck||[]).map(function(m){return'<span class="mitre-chip">'+esc(m)+'</span>'}).join('');
  var link=r.source_link?'<a class="sc-link" href="'+esc(r.source_link)+'" target="_blank" rel="noopener">View on '+esc(r.source)+' &rarr;</a>':'';
  var sampleItems=r.samples||[];
  var samples=sampleItems.length?'<div class="sc-samples'+(sampleItems.length>3?' sc-samples-collapsed':'')+'">'+sampleItems.map(function(s){return esc(s)}).join('<br>')+'</div>'+(sampleItems.length>3?'<button class="sc-toggle btn-link" onclick="this.previousElementSibling.classList.toggle(\'sc-samples-collapsed\');this.textContent=this.textContent===\'Show more\'?\'Show less\':\'Show more\'">Show more</button>':'') : '';

  var tl='';
  if(r.first_seen||r.last_seen){
    var fs=r.first_seen?new Date(r.first_seen).toLocaleString():'&mdash;';
    var ls=r.last_seen?new Date(r.last_seen).toLocaleString():'&mdash;';
    tl='<div class="sc-details"><span><strong>First:</strong> '+fs+'</span><span><strong>Last:</strong> '+ls+'</span></div>';
  }

  var scoreVal=r.raw_score!=null?Math.round(r.raw_score*100):null;
  var scoreTxt=scoreVal!=null?scoreVal+'/100':'&mdash;';
  var det='<div class="sc-details">'+
    '<span><strong>Score:</strong> '+scoreTxt+'</span>'+
    (r.confidence?'<span><strong>Confidence:</strong> '+esc(r.confidence)+'</span>':'')+
    (r.malware_family?'<span><strong>Family:</strong> '+esc(r.malware_family)+'</span>':'')+
    (r.reports_count!=null?'<span><strong>Reports:</strong> '+r.reports_count+'</span>':'')+
  '</div>';

  var extra='';
  if(detailed&&cats)extra+='<div class="sc-categories">'+cats+'</div>';
  if(detailed&&mitre)extra+='<div class="sc-mitre">'+mitre+'</div>';
  if(detailed&&samples)extra+=samples;

  var torBadge=(r.source==='Tor Exit'&&r.verdict==='malicious')?'<span class="sc-badge sc-badge-tor">Tor Exit Node</span>':'';
  return '<div class="source-card"><div class="sc-header"><span class="sc-name">'+esc(r.source)+'</span><span class="sc-verdict '+sc(v)+'">'+esc(v)+'</span>'+torBadge+'</div>'+det+tl+(tags?'<div class="sc-tags">'+tags+'</div>':'')+extra+link+'</div>';
}

function confClass(c){return c==='high'?'conf-high':c==='medium'?'conf-medium':'conf-low'}

// ---- VIEW TOGGLE: Analyst / Executive ----

function switchResultView(view){
  document.querySelectorAll('.toggle-btn').forEach(function(b){if(b)b.classList.remove('is-active')});
  var btn = document.querySelector('.toggle-btn[data-view="'+view+'"]');
  if(btn)btn.classList.add('is-active');

  var ep = q('executive-summary-panel');
  var ap = q('analyst-view-panel');
  var tb = document.querySelector('.tab-bar');
  if(view==='executive'){
    if(ep)ep.style.display='block';
    if(ap)ap.style.display='none';
    if(tb)tb.style.display='none';
  } else {
    if(ep)ep.style.display='none';
    if(ap)ap.style.display='block';
    if(tb)tb.style.display='flex';
  }
}

// ---- RELATIONSHIP GRAPH (3.6) ----

function renderGraph(data){
  var rels=data.relationships||[];
  var results=data.results||[];
  if(!rels.length)return'<div class="empty-state">No relationships to visualize</div>';

  var center=data.normalized||data.input||'';
  var nodes=[{id:center,label:center,type:'center',verdict:(data.composite||{}).verdict||'unknown'}];
  var edges=[];
  var seen={};seen[center]=true;

  rels.forEach(function(rr){
    var target=rr.target_ioc;
    if(!seen[target]&&nodes.length<50){
      var nodeType='';
      if(/^\d+\.\d+\.\d+\.\d+$/.test(target))nodeType='ip';
      else if(/^[a-f0-9]{32}$/i.test(target)||/^[a-f0-9]{40}$/i.test(target)||/^[a-f0-9]{64}$/i.test(target))nodeType='hash';
      else if(/^https?:\/\//i.test(target))nodeType='url';
      else if(/@/.test(target))nodeType='email';
      else nodeType='domain';
      nodes.push({id:target,label:target,type:nodeType,verdict:'unknown'});
      seen[target]=true;
    }
    edges.push({from:center,to:target,label:rr.relationship});
  });

  var width=Math.min(600,window.innerWidth-60);
  var height=Math.min(400,window.innerHeight-200);
  var cx=width/2;var cy=height/2;
  var radius=Math.min(cx,cy)-50;

  var colors={center:'var(--primary)',malicious:'var(--red)',suspicious:'var(--amber)',clean:'var(--green)',unknown:'var(--muted)',ip:'#4299e1',domain:'#48bb78',hash:'#ed8936',url:'#9f7aea',email:'#fc8181'};
  var nodeR=12;

  var positions={};
  positions[center]={x:cx,y:cy};
  var ringNodes=nodes.filter(function(n){return n.id!==center});
  ringNodes.forEach(function(n,i){
    var angle=(2*Math.PI*i)/ringNodes.length-Math.PI/2;
    positions[n.id]={x:cx+radius*Math.cos(angle),y:cy+radius*Math.sin(angle)};
  });

  var svg='<svg viewBox="0 0 '+width+' '+height+'" style="width:100%;max-width:'+width+'px;height:auto;background:var(--bg-secondary);border-radius:8px;display:block;margin:0 auto">';

  edges.forEach(function(e){
    var p1=positions[e.from]||{x:cx,y:cy};
    var p2=positions[e.to]||{x:cx+50,y:cy+50};
    var dx=p2.x-p1.x;var dy=p2.y-p1.y;
    var dist=Math.sqrt(dx*dx+dy*dy)||1;
    var mx=(p1.x+p2.x)/2;var my=(p1.y+p2.y)/2;
    var nx=-dy/dist*8;var ny=dx/dist*8;
    var labelX=mx+nx*3;var labelY=my+ny*3;
    svg+='<line x1="'+p1.x+'" y1="'+p1.y+'" x2="'+p2.x+'" y2="'+p2.y+'" stroke="var(--border)" stroke-width="1.5" stroke-dasharray="4,3"/>';
    svg+='<text x="'+labelX+'" y="'+labelY+'" text-anchor="middle" fill="var(--text-muted)" font-size="9" transform="translate(0,-5)">'+esc(e.label)+'</text>';
  });

  nodes.forEach(function(n){
    var p=positions[n.id]||{x:cx+Math.random()*100-50,y:cy+Math.random()*100-50};
    var fill=n.id===center?colors.center:(colors[n.verdict]||colors.unknown);
    var typeColor=n.id===center?colors.center:(colors[n.type]||colors.unknown);
    svg+='<circle cx="'+p.x+'" cy="'+p.y+'" r="'+nodeR+'" fill="'+typeColor+'" stroke="var(--bg-primary)" stroke-width="2" opacity="0.9" style="cursor:pointer" onclick="doLookup(\''+esc(n.label)+'\')"/>';
    var label=n.label.length>20?n.label.substring(0,17)+'...':n.label;
    svg+='<text x="'+p.x+'" y="'+(p.y+nodeR+14)+'" text-anchor="middle" fill="var(--text-color)" font-size="10" style="cursor:pointer" onclick="doLookup(\''+esc(n.label)+'\')">'+esc(label)+'</text>';
  });

  svg+='</svg>';
  svg+='<div style="display:flex;gap:1rem;justify-content:center;margin-top:0.5rem;font-size:0.7rem;color:var(--text-muted)">'+
    '<span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+colors.center+';vertical-align:middle;margin-right:4px"></span>Center</span>'+
    '<span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+colors.ip+';vertical-align:middle;margin-right:4px"></span>IP</span>'+
    '<span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+colors.domain+';vertical-align:middle;margin-right:4px"></span>Domain</span>'+
    '<span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+colors.hash+';vertical-align:middle;margin-right:4px"></span>Hash</span>'+
    '<span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+colors.url+';vertical-align:middle;margin-right:4px"></span>URL</span>'+
  '</div>';
  svg+='<p style="text-align:center;font-size:0.7rem;color:var(--text-muted);margin-top:0.25rem">Click any node to pivot</p>';
  return svg;
}

// ---- TIMELINE (3.2) ----

function renderTimeline(){
  var html='<div class="panel-section"><h3 class="panel-title">Session Timeline</h3>';
  if(!sessionHistory.length){
    html+='<div class="empty-state">No IOCs looked up yet in this session</div></div>';
    q('timeline-content').innerHTML=html;
    return;
  }
  html+='<div class="timeline-list">';
  sessionHistory.forEach(function(h,i){
    var timeStr=new Date(h.time).toLocaleTimeString();
    var color=h.score>=70?'var(--red)':h.score>=40?'var(--amber)':'var(--green)';
    html+='<div class="tl-item" onclick="restoreHistory('+i+')">'+
      '<div class="tl-dot" style="background:'+color+'"></div>'+
      '<div class="tl-info"><span class="tl-ioc">'+esc(h.ioc)+'</span>'+
      '<span class="tl-meta"><span class="verdict-badge '+vc(h.verdict)+'" style="font-size:0.65rem">'+esc(h.verdict)+'</span> <span style="opacity:0.6">'+Math.round(h.score)+'/100</span> <span style="opacity:0.4">'+timeStr+'</span></span></div></div>';
  });
  html+='</div></div>';
  q('timeline-content').innerHTML=html;
}

function restoreHistory(idx){
  var entry=sessionHistory[idx];
  if(!entry)return;
  if(_currentLookupValue===entry.ioc&&currentData)return;
  doLookup(entry.ioc);
}

function wireExports(data){
  var handlers={
    'export-json':function(){
      var b=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
      var u=URL.createObjectURL(b);var a=el('a');a.href=u;a.download='ioc_lookup.json';a.click();URL.revokeObjectURL(u);
      toast('JSON downloaded');
    },
    'export-csv':function(){
      var results=data.results||[];
      var lines=['source,ioc_type,verdict,raw_score,confidence,malware_family,reports_count,tags'];
      results.forEach(function(r){
        var tags=(r.tags||[]).join(';');
        lines.push(['"'+ (r.source||'') +'"','"'+ (r.ioc_type||'') +'"','"'+ (r.verdict||'') +'"',r.raw_score!=null?r.raw_score:'','"'+ (r.confidence||'') +'"','"'+ (r.malware_family||'') +'"',r.reports_count!=null?r.reports_count:'','"'+tags+'"'].join(','));
      });
      var b=new Blob([lines.join('\n')],{type:'text/csv'});var u=URL.createObjectURL(b);var a=el('a');a.href=u;a.download='ioc_lookup.csv';a.click();URL.revokeObjectURL(u);
      toast('CSV downloaded');
    },
    'export-stix':function(){
      var val=(data.normalized||data.input)||'';
      apiPost('/api/export/stix',{ioc:val}).then(function(bundle){
        var b=new Blob([JSON.stringify(bundle,null,2)],{type:'application/json'});
        var u=URL.createObjectURL(b);var a=el('a');a.href=u;a.download='ioc_stix.json';a.click();URL.revokeObjectURL(u);
        toast('STIX bundle exported');
      }).catch(function(err){toast('STIX export failed: '+err.message,'error')});
    },
    'export-clipboard':function(){
      navigator.clipboard.writeText(JSON.stringify(data,null,2)).then(function(){toast('Copied to clipboard')}).catch(function(){toast('Failed to copy','error')});
    },
    'export-report':function(){
      var val=(data.normalized||data.input)||'';
      downloadText('/api/export/report',{ioc:val},'ioc_report_'+val.replace(/[^a-zA-Z0-9]/g,'-')+'.html').then(function(){
        toast('Report downloaded');
      }).catch(function(err){toast('Report failed: '+err.message,'error')});
    }
  };
  Object.keys(handlers).forEach(function(id){
    var btn=q(id);if(btn)btn.onclick=handlers[id];
  });
}

function downloadText(url,body,filename){
  return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){
    if(!r.ok)return r.text().then(function(t){throw new Error(r.status+' '+t)});
    return r.text();
  }).then(function(text){
    var blob=new Blob([text],{type:'text/plain'});
    var u=URL.createObjectURL(blob);var a=el('a');a.href=u;a.download=filename||'download.txt';a.click();URL.revokeObjectURL(u);
  });
}

function siemExport(format){
  var data=currentData;
  if(!data){toast('No data to export','error');return}
  var iocVal=data.normalized||data.input||'';
  var ext=format==='ecs'?'ndjson':'txt';
  downloadText('/api/export/siem',{ioc:iocVal,format:format},'ioc_export.'+ext).then(function(){
    toast('SIEM export downloaded ('+format+')');
  }).catch(function(err){toast('SIEM export failed: '+err.message,'error')});
}

function mispExport(){
  var data=currentData;
  if(!data){toast('No data to export','error');return}
  var iocVal=data.normalized||data.input||'';
  apiPost('/api/export/misp',{ioc:iocVal}).then(function(resp){
    var blob=new Blob([JSON.stringify(resp,null,2)],{type:'application/json'});
    var url=URL.createObjectURL(blob);
    var a=el('a');a.href=url;a.download=resp.filename||'ioc_misp_event.misp.json';
    a.click();URL.revokeObjectURL(url);
    toast('MISP event downloaded');
  }).catch(function(err){toast('MISP export failed: '+err.message,'error')});
}

// ---- SAVE TO INVESTIGATION ----

function saveCurrentToInvestigation(){
  if(!currentData)return;
  var val=currentData.normalized||currentData.input||'';
  apiGet('/api/investigations').then(function(invs){
    var html='<p style="margin-bottom:0.75rem">Select an investigation to add this IOC to:</p>';
    if(invs&&invs.length){
      html+='<div style="display:flex;flex-direction:column;gap:0.4rem;margin-bottom:0.75rem">';
      invs.forEach(function(inv){
        html+='<button class="btn btn-secondary inv-select-btn" data-id="'+inv.id+'" style="text-align:left">'+esc(inv.name)+' ('+inv.ioc_count+' IOCs)</button>';
      });
      html+='</div>';
    }
    html+='<p style="margin-bottom:0.5rem;font-size:0.82rem;color:var(--muted)">Or create a new investigation:</p>'+
      '<input class="modal-input" id="new-inv-name" placeholder="Investigation name"/>'+
      '<textarea class="modal-textarea" id="new-inv-desc" placeholder="Description (optional)"></textarea>'+
      '<button class="btn btn-primary" id="modal-save-inv">Save</button>';

    openModal('Save to Investigation',html);
    setTimeout(function(){
      document.querySelectorAll('.inv-select-btn').forEach(function(b){
        b.addEventListener('click',function(){
          var invId=parseInt(b.dataset.id);
          addIocToInv(invId,val);
        });
      });
      var si=q('modal-save-inv');
      if(si)si.addEventListener('click',function(){
        var ni=q('new-inv-name');if(!ni||!ni.value.trim())return;
        var nd=q('new-inv-desc');
        apiPost('/api/investigations',{name:ni.value.trim(),description:nd?nd.value.trim():''}).then(function(inv){
          addIocToInv(inv.id,val);
        }).catch(function(err){toast('Failed: '+err.message,'error')});
      });
    },50);
  }).catch(function(err){toast('Failed: '+err.message,'error')});
}

function addIocToInv(invId,value){
  apiPost('/api/investigations/'+invId+'/iocs',{ioc:value}).then(function(){
    closeModal();
    toast('IOC added to investigation');
  }).catch(function(err){toast('Failed: '+err.message,'error')});
}

// ---- INVESTIGATIONS ----

function loadInvestigations(){
  var grid=q('inv-grid');if(!grid)return;
  apiGet('/api/investigations').then(function(invs){
    if(!invs||!invs.length){
      grid.innerHTML='<div class="empty-state" style="grid-column:1/-1">No investigations yet. Create one to start organizing IOCs.</div>';
      return;
    }
    grid.innerHTML=invs.map(function(inv){
      return '<div class="inv-card" onclick="openInvestigation('+inv.id+')">'+
        '<div class="inv-card-title">'+esc(inv.name)+'</div>'+
        (inv.description?'<div class="inv-card-desc">'+esc(inv.description)+'</div>':'')+
        '<div class="inv-card-meta">'+
          '<span><strong>'+inv.ioc_count+'</strong> IOCs</span>'+
          '<span>'+esc(inv.created_at?new Date(inv.created_at).toLocaleDateString():'')+'</span>'+
        '</div></div>';
    }).join('');
  }).catch(function(){
    grid.innerHTML='<div class="empty-state" style="grid-column:1/-1">Failed to load investigations</div>';
  });
}

function openInvestigation(invId){
  currentInvId=invId;
  apiGet('/api/investigations/'+invId).then(function(inv){
    q('inv-grid').style.display='none';
    q('inv-detail').style.display='block';
    q('inv-detail-name').textContent=inv.name;

    q('inv-detail-iocs').innerHTML='<div class="panel-section"><h3 class="panel-title">IOCs in this investigation'+(inv.description?' <span style="font-weight:400;text-transform:none;color:var(--muted)">â€” '+esc(inv.description)+'</span>':'')+'</h3>';
    if(!inv.iocs||!inv.iocs.length){
      q('inv-detail-iocs').innerHTML+='<div class="empty-state">No IOCs in this investigation</div>';
    } else {
      q('inv-detail-iocs').innerHTML+='<div class="inv-ioc-list">';
      inv.iocs.forEach(function(ioc){
        var scoreColor='var(--muted)';
        if(ioc.verdict==='malicious')scoreColor='var(--red)';
        else if(ioc.verdict==='suspicious')scoreColor='var(--amber)';
        else if(ioc.verdict==='clean')scoreColor='var(--green)';
        q('inv-detail-iocs').innerHTML+='<div class="inv-ioc-row">'+
          '<span class="inv-ioc-value" onclick="doLookup(\''+esc(ioc.value)+'\')">'+esc(ioc.value)+'</span>'+
          '<span class="inv-ioc-type">'+esc(ioc.ioc_type)+'</span>'+
          '<span class="inv-ioc-score" style="color:'+scoreColor+'">'+(ioc.score!=null?Math.round(ioc.score):'&mdash;')+'</span>'+
          (ioc.verdict?'<span class="inv-verdict verdict-'+ioc.verdict+'">'+esc(ioc.verdict)+'</span>':'')+
          '<div class="inv-ioc-notes"><textarea placeholder="Add notes..." onchange="saveIocNotes('+invId+','+ioc.id+',this.value)">'+esc(ioc.notes||'')+'</textarea></div>'+
        '</div>';
      });
      q('inv-detail-iocs').innerHTML+='</div>';
    }
    q('inv-detail-iocs').innerHTML+='</div>';
  });
}

function saveIocNotes(invId,iiId,notes){
  apiPut('/api/investigations/'+invId+'/iocs/'+iiId,{notes:notes}).then(function(){toast('Notes saved')}).catch(function(){});
}

function apiPut(url,body){return fetch(url,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(r.status+' '+t)});return r.json()})}

// ---- BATCH ----

function initBatch(){
  var dz=q('drop-zone');if(!dz)return;
  dz.addEventListener('dragover',function(e){e.preventDefault();dz.classList.add('dragover')});
  dz.addEventListener('dragleave',function(){dz.classList.remove('dragover')});
  dz.addEventListener('drop',function(e){
    e.preventDefault();dz.classList.remove('dragover');
    var file=e.dataTransfer.files[0];if(!file)return;
    var reader=new FileReader();
    reader.onload=function(evt){
      var content=evt.target.result;
      submitBatchContent(content,file.name);
    };
    reader.readAsText(file);
  });
}

function submitBatchContent(content,filename){
  var ext=(filename||'').split('.').pop().toLowerCase();
  if(ext==='json'){
    try{var arr=JSON.parse(content);if(Array.isArray(arr)){q('batch-textarea').value=arr.join('\n')}else{toast('JSON must be an array of strings','error')}}
    catch(e){toast('Invalid JSON','error')}
  } else {
    q('batch-textarea').value=content;
  }
}

function runBatch(){
  var ta=q('batch-textarea');if(!ta)return;
  var text=ta.value.trim();
  if(!text){toast('Enter or upload IOCs first','error');return}
  var iocs=text.split('\n').map(function(s){return s.trim()}).filter(function(s){return s});
  if(!iocs.length){toast('No IOCs found','error');return}
  if(iocs.length>500){toast('Maximum 500 IOCs','error');return}

  q('batch-progress').style.display='block';
  q('batch-analyze-btn').disabled=true;
  q('batch-analyze-btn').textContent='Analyzing...';

  apiPost('/api/batch',{iocs:iocs}).then(function(data){
    pollBatch(data.batch_id);
  }).catch(function(err){
    q('batch-analyze-btn').disabled=false;q('batch-analyze-btn').textContent='Analyze All';
    toast('Batch failed: '+err.message,'error');
  });
}

function pollBatch(batchId){
  if(_batchPollTimer)clearInterval(_batchPollTimer);
  _batchPollTimer=setInterval(function(){
    apiGet('/api/batch/'+batchId).then(function(batch){
      renderBatchProgress(batch);
      if(batch.status==='done'){
        clearInterval(_batchPollTimer);_batchPollTimer=null;
        q('batch-analyze-btn').disabled=false;q('batch-analyze-btn').textContent='Analyze All';
        loadBatchResult(batchId);
      } else if(batch.status==='error'){
        clearInterval(_batchPollTimer);_batchPollTimer=null;
        q('batch-analyze-btn').disabled=false;q('batch-analyze-btn').textContent='Analyze All';
        toast('Batch error: '+batch.error,'error');
      }
    }).catch(function(err){
      clearInterval(_batchPollTimer);_batchPollTimer=null;
      q('batch-analyze-btn').disabled=false;q('batch-analyze-btn').textContent='Analyze All';
      toast('Batch poll failed: '+err.message,'error');
    });
  },500);
}

function renderBatchProgress(batch){
  var fill=q('batch-fill');if(fill)fill.style.width=batch.progress+'%';
  var sum=q('batch-summary');
  if(batch.subtasks){
    sum.innerHTML='<div class="batch-summary">'+
      '<div class="batch-stat"><div class="batch-stat-num">'+batch.total+'</div><div class="batch-stat-label">Total</div></div>'+
      '<div class="batch-stat"><div class="batch-stat-num">'+batch.completed+'</div><div class="batch-stat-label">Done</div></div>'+
      '<div class="batch-stat"><div class="batch-stat-num">'+(batch.total-batch.completed)+'</div><div class="batch-stat-label">Remaining</div></div>'+
      '<div class="batch-stat"><div class="batch-stat-num">'+Math.round(batch.progress)+'%</div><div class="batch-stat-label">Progress</div></div>'+
    '</div>';

    var st=q('batch-subtasks');
    st.innerHTML=batch.subtasks.map(function(t){
      var cls='bs-row bs-'+t.status;
      return '<div class="'+cls+'"><span class="bs-icon"></span><span class="bs-value">'+esc(t.ioc_value)+'</span><span class="bs-result">'+esc(t.status)+(t.error?' ('+esc(t.error)+')':'')+'</span></div>';
    }).join('');
  }
}

var _batchResultData=null;

function loadBatchResult(batchId){
  apiGet('/api/batch/'+batchId+'/result').then(function(data){
    _batchResultData=data;
    var sum=data.summary||{};
    var total=(sum.malicious||0)+(sum.suspicious||0)+(sum.clean||0)+(sum.unknown||0);
    var verdicts=['malicious','suspicious','clean','unknown'];
    var html='<div class="batch-summary">'+
      '<div class="batch-stat mal"><div class="batch-stat-num">'+(sum.malicious||0)+'</div><div class="batch-stat-label">Malicious</div></div>'+
      '<div class="batch-stat sus"><div class="batch-stat-num">'+(sum.suspicious||0)+'</div><div class="batch-stat-label">Suspicious</div></div>'+
      '<div class="batch-stat cln"><div class="batch-stat-num">'+(sum.clean||0)+'</div><div class="batch-stat-label">Clean</div></div>'+
      '<div class="batch-stat unk"><div class="batch-stat-num">'+(sum.unknown||0)+'</div><div class="batch-stat-label">Unknown</div></div>'+
    '</div>';

    html+='<div class="batch-filters">'+
      '<span style="color:var(--text-muted);font-size:0.75rem">Filter: </span>';
    verdicts.forEach(function(v){
      var cnt=sum[v]||0;
      html+='<button class="btn-filter" data-v="'+v+'" onclick="toggleBatchFilter(\''+v+'\')">'+v.charAt(0).toUpperCase()+v.slice(1)+' ('+cnt+')</button>';
    });
    html+='<button class="btn-filter is-active" data-v="all" onclick="toggleBatchFilter(\'all\')">All ('+total+')</button>'+
      '<input class="batch-search-input" id="batch-search-input" placeholder="Search IOCs..." oninput="applyBatchFilter()"/>'+
    '</div>';

    html+='<div class="batch-filters" style="margin-top:0.25rem">'+
      '<span style="color:var(--text-muted);font-size:0.75rem">Type: </span>'+
      '<button class="btn-filter is-active" data-t="all" onclick="toggleBatchTypeFilter(\'all\')">All</button>'+
    '</div>';

    html+='<div class="batch-results-table-wrap"><table class="data-table batch-results-table" id="batch-results-table">'+
      '<thead><tr><th>IOC</th><th>Type</th><th>Score</th><th>Verdict</th><th>Top Source</th></tr></thead><tbody id="batch-results-tbody"></tbody></table></div>'+
    '<div class="export-actions" style="margin-top:0.5rem">'+
      '<button class="btn btn-secondary" id="batch-export-json">Download JSON</button>'+
      '<button class="btn btn-secondary" id="batch-export-csv">Download CSV</button>'+
    '</div>';

    q('batch-summary').innerHTML=html;

    var btns={};
    btns['batch-export-json']=function(){
      var b=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
      var u=URL.createObjectURL(b);var a=el('a');a.href=u;a.download='batch_results.json';a.click();URL.revokeObjectURL(u);
    };
    btns['batch-export-csv']=function(){
      var results=data.results||[];
      var lines=['ioc,source,ioc_type,verdict,raw_score,confidence,malware_family'];
      results.forEach(function(r){
        lines.push(['"'+ (r._ioc||'') +'"','"'+ (r.source||'') +'"','"'+ (r.ioc_type||'') +'"','"'+ (r.verdict||'') +'"',r.raw_score!=null?r.raw_score:'','"'+ (r.confidence||'') +'"','"'+ (r.malware_family||'') +'"'].join(','));
      });
      var b=new Blob([lines.join('\n')],{type:'text/csv'});
      var u=URL.createObjectURL(b);var a=el('a');a.href=u;a.download='batch_results.csv';a.click();URL.revokeObjectURL(u);
    };
    Object.keys(btns).forEach(function(id){var btn=q(id);if(btn)btn.addEventListener('click',btns[id])});
    applyBatchFilter();
  });
}

var _batchFilterVerdict='all';
var _batchFilterType='all';

function toggleBatchFilter(v){
  _batchFilterVerdict=v;
  document.querySelectorAll('.btn-filter[data-v]').forEach(function(b){b.classList.toggle('is-active',b.dataset.v===v)});
  applyBatchFilter();
}

function toggleBatchTypeFilter(t){
  _batchFilterType=t;
  document.querySelectorAll('.btn-filter[data-t]').forEach(function(b){b.classList.toggle('is-active',b.dataset.t===t)});
  applyBatchFilter();
}

function applyBatchFilter(){
  if(!_batchResultData)return;
  var results=_batchResultData.results||[];
  var tbody=q('batch-results-tbody');
  if(!tbody)return;
  var search=(q('batch-search-input')||{}).value||'';
  var iocMap={};
  results.forEach(function(r){if(r._ioc&&!iocMap[r._ioc])iocMap[r._ioc]={verdict:r.verdict,score:r.raw_score,ioc_type:r.ioc_type,source:r.source}});
  var iocs=Object.keys(iocMap);
  var filtered=iocs.filter(function(i){
    var info=iocMap[i];
    if(_batchFilterVerdict!=='all'&&info.verdict!==_batchFilterVerdict)return false;
    if(search&&i.toLowerCase().indexOf(search.toLowerCase())===-1)return false;
    return true;
  });
  filtered.sort(function(a,b){return (iocMap[b].score||0)-(iocMap[a].score||0)});
  tbody.innerHTML=filtered.map(function(i){
    var info=iocMap[i];
    var score=info.score!=null?Math.round(info.score*100):'—';
    var sc=info.score!=null?(info.score>=0.7?'var(--red)':info.score>=0.4?'var(--amber)':'var(--green)'):'var(--muted)';
    return '<tr><td class="clickable" onclick="doLookup(\''+esc(i)+'\')">'+esc(i)+'</td>'+
      '<td>'+esc(info.ioc_type||'')+'</td>'+
      '<td style="color:'+sc+';font-weight:600">'+score+'</td>'+
      '<td><span class="verdict-badge '+vc(info.verdict)+'" style="font-size:0.65rem">'+esc(info.verdict)+'</span></td>'+
      '<td>'+esc(info.source||'')+'</td></tr>';
  }).join('');
}

// ---- INIT ----

function initNav(){
  var si=q('search-input');if(si)si.addEventListener('keydown',function(e){if(e.key==='Enter')doLookup(si.value)});
  var sb=q('search-btn');if(sb)sb.addEventListener('click',function(){doLookup(q('search-input')?q('search-input').value:'')});
  var oi=q('omnibar-input');if(oi)oi.addEventListener('keydown',function(e){if(e.key==='Enter')doLookup(oi.value)});
  var ob=q('omnibar-btn');if(ob)ob.addEventListener('click',function(){doLookup(q('omnibar-input')?q('omnibar-input').value:'')});

  document.querySelectorAll('.example-chip').forEach(function(chip){
    if(!chip)return;
    chip.addEventListener('click',function(){
      var val=chip.dataset.value;
      var si2=q('search-input');if(si2)si2.value=val;
      doLookup(val);
    });
  });

  var ni=q('new-inv-btn');
  if(ni)ni.addEventListener('click',function(){
    openModal('New Investigation',
      '<input class="modal-input" id="modal-inv-name" placeholder="Investigation name"/>'+
      '<textarea class="modal-textarea" id="modal-inv-desc" placeholder="Description (optional)"></textarea>'+
      '<button class="btn btn-primary" id="modal-create-inv">Create</button>');
    setTimeout(function(){
      var btn=q('modal-create-inv');
      if(btn)btn.addEventListener('click',function(){
        var mn=q('modal-inv-name');if(!mn||!mn.value.trim())return;
        var md=q('modal-inv-desc');
        apiPost('/api/investigations',{name:mn.value.trim(),description:md?md.value.trim():''}).then(function(inv){
          closeModal();toast('Investigation created');loadInvestigations();
        }).catch(function(err){toast('Failed: '+err.message,'error')});
      });
    },50);
  });

  var ib=q('inv-back-btn');
  if(ib)ib.addEventListener('click',function(){q('inv-grid').style.display='grid';q('inv-detail').style.display='none'});

  var ide=q('inv-delete-btn');
  if(ide)ide.addEventListener('click',function(){
    if(!currentInvId)return;
    if(!confirm('Delete this investigation and all its IOCs?'))return;
    apiDelete('/api/investigations/'+currentInvId).then(function(){
      toast('Investigation deleted');currentInvId=null;
      q('inv-grid').style.display='grid';q('inv-detail').style.display='none';
      loadInvestigations();
    }).catch(function(err){toast('Delete failed: '+err.message,'error')});
  });

  var sie=q('save-to-inv-btn');
  if(sie)sie.addEventListener('click',saveCurrentToInvestigation);

  var ba=q('batch-analyze-btn');
  if(ba)ba.addEventListener('click',runBatch);

  initBatch();
}

function apiDelete(url){return fetch(url,{method:'DELETE'}).then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(r.status+' '+t)});return r.json()})}

function loadHealth(){
  var grid=q('health-grid');var sum=q('health-summary');
  if(!grid)return;
  apiGet('/api/adapters/health').then(function(data){
    var adapters=data.adapters||[];
    var closed=adapters.filter(function(a){return a.state==='closed'}).length;
    var total=adapters.length;
    sum.textContent=closed+'/'+total+' healthy';
    grid.innerHTML=adapters.map(function(a){
      var cls=a.state==='closed'?'h-green':a.state==='open'?'h-red':'h-amber';
      var label=a.state==='closed'?'OK':a.state==='open'?'DOWN':'HALF';
      return '<span class="health-chip '+cls+'"><span class="h-dot"></span>'+esc(a.name)+' <small>('+label+')</small></span>';
    }).join('');
    if(!adapters.length)grid.innerHTML='<span class="health-chip h-gray"><span class="h-dot"></span>No adapter data yet â€” run a lookup first</span>';
  }).catch(function(){
    if(sum)sum.textContent='Could not load health';
    grid.innerHTML='<span class="health-chip h-gray"><span class="h-dot"></span>Failed to load</span>';
  });
}

// Tab switching
document.querySelectorAll('.tab-btn').forEach(function(btn){
  if(!btn)return;
  btn.addEventListener('click',function(){
    document.querySelectorAll('.tab-btn').forEach(function(b){if(b)b.classList.remove('is-active')});
    document.querySelectorAll('.tab-panel').forEach(function(p){if(p)p.classList.remove('is-active')});
    if(btn)btn.classList.add('is-active');
    var pnl=q('panel-'+btn.dataset.tab);if(pnl)pnl.classList.add('is-active');
  });
});

initNav();
loadInvestigations();
loadHealth();
setInterval(loadHealth, 60000);
