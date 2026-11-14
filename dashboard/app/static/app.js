const $ = s => document.querySelector(s);
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

// fresh options object per chart (never share — Chart.js mutates scales in place)
function opts(){
  return {
    responsive:true,
    maintainAspectRatio:false,
    animation:false,
    plugins:{legend:{display:false}},
    scales:{
      x:{ticks:{color:'#7a8c7a'},grid:{color:'#141a14'}},
      y:{beginAtZero:true,ticks:{color:'#7a8c7a',precision:0},grid:{color:'#141a14'}}
    }
  };
}
let charts = {};

function mkChart(id,type,color,horizontal){
  const o = opts();
  if(horizontal) o.indexAxis = 'y';
  return new Chart($('#'+id).getContext('2d'),{
    type,
    data:{labels:[],datasets:[{data:[],backgroundColor:color,borderColor:color,borderWidth:2,tension:.3,pointRadius:2}]},
    options:o
  });
}

async function j(u,opt){const r=await fetch(u,opt);return r.json();}

async function loadSummary(){
  const s = await j('/api/summary');
  const h = $('#health'); h.className='health '+(s.health==='up'?'up':s.health==='down'?'down':'warn');
  h.textContent = 'health: '+s.health+(s.site?' · '+s.site.replace(/^https?:\/\//,''):'');
  const vals=[s.events_24h,s.unique_ips_24h,s.alerts_open,s.crit_24h,s.high_24h,s.med_24h];
  document.querySelectorAll('#stats .stat .k').forEach((el,i)=>el.textContent=vals[i]);
}

async function loadAlerts(){
  const show = $('#showAll').checked ? 'all' : 'open';
  const a = await j('/api/alerts?limit=100&show='+show);
  const tb = $('#alerts tbody');
  if(!a.length){tb.innerHTML='<tr><td colspan="7" class="empty">no alerts</td></tr>';return;}
  tb.innerHTML = a.map(x=>`<tr>
    <td>${esc(x.ts.replace('T',' ').replace('+00:00',''))}</td>
    <td><span class="sev ${esc(x.severity)}">${esc(x.severity)}</span></td>
    <td>${esc(x.rule)}</td>
    <td class="ip">${esc(x.ip||'—')}</td>
    <td>${esc(x.summary)}${x.detail?'<br><span class="mitre">'+esc(x.detail)+'</span>':''}</td>
    <td class="mitre">${esc(x.mitre||'')}</td>
    <td>${x.acknowledged?'<span class="mitre">ack</span>':`<button class="ackbtn" onclick="ack(${x.id})">ack</button>`}</td>
  </tr>`).join('');
}
window.ack = async id => { await j('/api/alerts/'+id+'/ack',{method:'POST'}); loadAlerts(); loadSummary(); };

async function loadEvents(){
  const q = $('#eventSearch').value.trim();
  const e = await j('/api/events?limit=60&q='+encodeURIComponent(q));
  const tb = $('#events tbody');
  if(!e.length){tb.innerHTML='<tr><td colspan="7" class="empty">no events</td></tr>';return;}
  tb.innerHTML = e.map(x=>`<tr>
    <td>${esc(x.ts.replace('T',' ').replace('+00:00',''))}</td>
    <td>${esc(x.source)}</td>
    <td class="ip">${esc(x.ip||'—')}</td>
    <td>${esc(x.method||'')}</td>
    <td>${esc((x.path||'').slice(0,60))}</td>
    <td class="status-${String(x.status||'').charAt(0)}">${esc(x.status||'')}</td>
    <td>${x.rt!=null?Math.round(x.rt*1000)+'ms':''}</td>
  </tr>`).join('');
}

async function loadCharts(){
  const t = await j('/api/traffic');
  charts.t.data.labels=t.labels; charts.t.data.datasets[0].data=t.values; charts.t.update();
  const s = await j('/api/severity');
  const cmap={CRITICAL:'#ff4d4d',HIGH:'#ffa033',MEDIUM:'#ffd35c',LOW:'#39ff7a'};
  charts.s.data.labels=s.labels; charts.s.data.datasets[0].data=s.values;
  charts.s.data.datasets[0].backgroundColor=s.labels.map(l=>cmap[l]||'#39ff7a');
  charts.s.data.datasets[0].borderColor=charts.s.data.datasets[0].backgroundColor;
  charts.s.update();
  const p = await j('/api/top-ips');
  charts.p.data.labels=p.labels; charts.p.data.datasets[0].data=p.values; charts.p.update();
}

function init(){
  charts.t = mkChart('trafficChart','line','#39ff7a',false);
  charts.s = mkChart('sevChart','bar','#39ff7a',false);
  charts.p = mkChart('ipChart','bar','#1f7a3f',true);
  const refresh=()=>{loadSummary();loadAlerts();loadCharts();loadEvents();};
  refresh();
  setInterval(()=>{loadSummary();loadAlerts();},10000);
  setInterval(loadCharts,60000);
  $('#showAll').addEventListener('change',loadAlerts);
  let t; $('#eventSearch').addEventListener('input',()=>{clearTimeout(t);t=setTimeout(loadEvents,300);});
}
init();
