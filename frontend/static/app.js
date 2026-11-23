import { icon, drawTraffic } from './visuals.js';
import { drawQR } from './share-qr.js';

const $ = selector => document.querySelector(selector);
const content = $('#content'), dialog = $('#dialog');
const names = {hy2:'Hysteria 2', vless:'VLESS'};
const components = {project:'chenniXvpn', vless:'Xray', hy2:'Hysteria 2'};
const kinds = {original:'原始入口', preferred:'优选入口', manual:'自选入口'};
const diagnosticsPath = 'nodes/vless/diagnostics';
const jobOperations = {create:'创建', repair:'恢复', configure:'修改', enable:'启用', disable:'停用', upgrade:'升级', retire_certificate:'清理证书', delete_release:'清理旧版本'};
const jobStates = {queued:['等待执行','neutral'], running:['正在执行','warn'], succeeded:['已完成','good'], failed:['执行失败','bad']};
let traffic, server, report, page = [], revision = 0, noticeTimer, pendingShare, modalVersion = 0;
let scrollTarget = null;
let trafficError, nodeError, nodeVersion = 0;
let jobs = [], jobsError, updates, updatesError, checkingUpdates = false, submittingJob = false, jobVersion = 0;
let installedVersions, installedVersionsError;
let trafficDeadline = 0, trafficExpiryTimer, trafficRequest = 0;
let jobsTimer, readingJobs = false, listRequested = false;
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const link = (url, text, cls='link') => `<a href="#/${url}" class="${cls}">${esc(text)}</a>`;
const btn = (action, title, glyph='', cls='', attrs='') => `<button type="button" class="btn ${cls}" data-action="${action}" ${attrs}>${glyph ? icon(glyph) : ''}${esc(title)}</button>`;
const pill = (text, style='neutral') => `<span class="pill ${style}">${esc(text)}</span>`;
const date = ts => ts ? new Date(ts*1000).toLocaleString('zh-CN',{hour12:false}) : '暂无记录';
const beijingTime = new Intl.DateTimeFormat('zh-CN',{
  timeZone:'Asia/Shanghai', year:'numeric', month:'long', day:'numeric', hour:'2-digit', minute:'2-digit', hourCycle:'h23'
});
const beijingDate = ts => beijingTime.format(ts*1000);
const number = (n, digits=2) => Number(n).toLocaleString('zh-CN',{maximumFractionDigits:digits});
function quantity(value, units) {
  if (value == null) return ['—', units[0]];
  let i=0;
  while (value >= 1000 && i < units.length-1) { value /= 1000; i++; }
  return [number(value), units[i]];
}
const bytes = n => quantity(n,['B','KB','MB','GB','TB','PB']).join(' ');
const rate = n => quantity(n,['bps','Kbps','Mbps','Gbps']);
function stateOf(n) {
  if (n.install_state==='incomplete') return pill('安装未完成','warn');
  if (!n.installed) return pill('未安装');
  if (n.state==='active') {
    const health=n.health;
    if (health?.listener==='missing' || health?.ingress==='missing') return pill('本机监听异常','warn');
    if (['missing','invalid_dates'].includes(health?.certificate) || health?.loaded_certificate==='different') {
      return pill('证书需检查','warn');
    }
    return pill('进程运行中','good');
  }
  if (!n.enabled && n.state==='inactive') return pill('已停用');
  return pill(n.state==='failed'?'服务异常':'未运行','warn');
}
const getNode = p => server?.nodes.find(n => n.protocol === p);
const row = (label,value) => `<div class="row"><span class="muted">${esc(label)}</span><strong>${value}</strong></div>`;
const card = (title,body,action='') => `<section class="card"><div class="card-head"><h2 class="card-title">${esc(title)}</h2>${action}</div><div class="card-body">${body}</div></section>`;
const tabs = items => `<nav class="tabs" aria-label="子页面">${items.map(([url,title,on])=>link(url,title,'tab'+(on?' active':''))).join('')}</nav>`;
const empty = text => `<div class="empty">${esc(text)}</div>`;
const bind = key => `<span data-live="${key}">—</span>`;
const region = (name, markup='') => `<div data-region="${name}"${markup?'':' hidden'}>${markup}</div>`;
const stale = (error, timestamp) => error ? `<p class="muted" role="status">${esc(error)}${timestamp?' · 最近一次 '+date(timestamp):''}</p>` : '';

function replaceRegion(name, markup) {
  const element = $(`[data-region="${name}"]`);
  if (!element || element.contains(document.activeElement)) return;
  if(element.innerHTML!==markup)element.innerHTML=markup;
  element.hidden=!markup;
}

async function api(path, body) {
  const options = body === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify(body)};
  const res = await fetch('/api/'+path,{...options,cache:'no-store'});
  let data;
  try { data = await res.json(); } catch { throw Error('服务器响应无效'); }
  if (!res.ok) throw Error(data.error || '请求失败');
  return data;
}
function notice(message) {
  if (dialog.open) {
    const note = $('#dialog-note');
    note.textContent = message;
    note.hidden = false;
    note.scrollIntoView({block:'nearest'});
    return;
  }
  const el=$('#notice'); el.textContent=message; el.classList.add('visible','show');
  clearTimeout(noticeTimer); noticeTimer=setTimeout(()=>{el.classList.remove('visible','show');el.textContent='';},3500);
}
function connected() {
  const el=$('#connection');
  const ok=Boolean((server&&!nodeError)||(traffic&&!trafficError));
  el.dataset.state=ok?'online':'offline';
  el.textContent=server?.preview&&ok?'本机预览 · 示例数据':ok?
    (server?.hostname?'已连接 · '+server.hostname:'已连接'):'无法读取面板数据';
}
function layout(title, crumbs, html, actions='') {
  $('#heading').textContent=title; document.title=title+' · chenniXvpn';
  $('#breadcrumbs').innerHTML=[['','控制台'],...crumbs].map(([url,name],i,items)=>{
    const current=i===items.length-1;
    const divider=i ? '<span class="crumb-divider" aria-hidden="true">/</span>' : '';
    return `<span class="crumb"${current?' aria-current="page"':''}>${divider}${current?esc(name):link(url,name)}</span>`;
  }).join('');
  $('#page-actions').innerHTML=actions; content.innerHTML=html;
  document.querySelectorAll('.main-nav a').forEach(a=>{
    const active=a.hash==='#/'+(page[0]||''); a.classList.toggle('active',active);
    if(active)a.setAttribute('aria-current','page'); else a.removeAttribute('aria-current');
  });
}
function metric(label,value,unit,foot,glyph,style) {
  return `<div class="metric ${style}"><div class="metric-label"><span>${label}</span><span class="metric-icon">${icon(glyph)}</span></div><div class="metric-value"><span>${value}</span><span class="unit">${unit}</span></div><div class="metric-foot">${foot}</div></div>`;
}
function metrics() {
  return `<div class="metrics">${metric('实时上传',bind('tx'),bind('txUnit'),'所选网卡发送速率','up','tx')}${metric('实时下载',bind('rx'),bind('rxUnit'),'所选网卡接收速率','down','rx')}${metric('本月出口',bind('month'),bind('monthUnit'),'月度参考额度 '+bind('budget'),'gauge','month')}${metric('运行节点','<span id="active-nodes">—</span>','<span id="total-nodes"></span>','<span id="node-metric-status">本机进程状态</span>','layers','nodes')}</div>`;
}
function chart() {
  return `<section class="card chart-card"><div class="card-head"><div><h2 class="card-title">实时流量</h2><span class="card-caption">最近 15 分钟 · 每 5 秒采样</span></div><div class="chart-legend"><span><i class="swatch tx"></i>上传</span><span><i class="swatch rx"></i>下载</span></div></div><div class="chart-wrap"><canvas id="rates"></canvas></div></section>`;
}
function budget() {
  return card('月度出口用量',`
    <p class="card-caption">本机网卡估算，按北京时间自然月统计</p>
    <div class="budget-summary"><div class="budget-value">${bind('percent')}<span class="unit"> %</span></div><span id="budget-status" class="pill neutral" hidden></span></div>
    <div class="progress" aria-hidden="true"><span id="budget-bar"></span></div>
    <div class="kv">${row('本月已用',bind('used'))}${row('参考额度',bind('budget'))}
      <div class="row"><span class="muted" data-live="balanceLabel">剩余额度</span><strong>${bind('remaining')}</strong></div>
    </div>
    <p class="budget-period muted">${bind('period')}</p>`,link('traffic/month','详情'));
}
const availableProtocols = () => Object.keys(names).filter(protocol => !getNode(protocol));
const jobPending = job => ['queued','running'].includes(job.state);
const activeJob = () => jobs.find(jobPending);
const nodeMutationsDisabled = () => Boolean(nodeError || activeJob() || submittingJob);
const createNodeButton = () => server && availableProtocols().length
  ? btn('create-node','创建节点','network','primary',nodeMutationsDisabled()?'disabled':'')
  : '';

function nodesList() {
  if (!server) return empty(nodeError||'正在读取协议节点');
  const timestamp=nodeError?stale(nodeError,server.checked_at):server.checked_at?`<p class="card-caption">本机检查于 ${date(server.checked_at)}</p>`:'';
  if (!server.nodes.length) return timestamp+empty('还没有节点。创建 Hysteria 2 或 VLESS 后即可获取连接链接。');
  return timestamp+`<div class="data-list">${server.nodes.map(n=>`<a class="node-row" href="#/nodes/${n.protocol}"><span class="node-mark">${icon(n.protocol==='hy2'?'activity':'network')}</span><div><strong>${names[n.protocol]}</strong><div class="muted">${n.protocol==='hy2'?'QUIC / UDP':'WebSocket / TLS'}</div></div>${stateOf(n)}${icon('chevron')}</a>`).join('')}</div>`;
}
function latestCheck() {
  if (!server) return empty(nodeError||'正在读取客户端报告');
  if (server.sharing_error) return empty(server.sharing_error);
  const vless=getNode('vless');
  const last=vless?.latest;
  if (!last) return empty(vless?.installed?'当前配置尚无测速报告':'创建并启动 VLESS 后可导入测速报告') + link('nodes/vless/diagnostics','查看测速报告');
  return stale(nodeError,server.checked_at)+`<div class="kv">${row('检查方式','VLESS 客户端 WebSocket 握手')}${row('测试目标',last.target_verified?'已核对':'目标未验证')}${row('测试时间',date(last.measured_at))}${row('可用地址',last.usable+' / '+last.count)}${row('优选握手',last.best_ms==null?'—':number(last.best_ms)+' ms')}${row('导入时间',date(last.ts))}</div>${link('nodes/vless/diagnostics/'+last.id,'查看报告')}`;
}
function overview() {
  const actions=region('node-create',createNodeButton())+btn('refresh','刷新','refresh','ghost');
  layout('运行概览',[['','概览']],`<div class="stack">${metrics()}${region('traffic-error')}<div class="columns">${chart()}${budget()}</div><div class="columns">${card('协议节点',region('nodes-list',nodesList()),link('nodes','全部节点'))}${card('最近客户端报告',region('latest-report',latestCheck()))}</div></div>`,actions);
}
function trafficPage() {
  const monthly=page[1]==='month';
  const history=card('历史月份',`<div class="table-wrap"><table class="table month-table"><thead><tr><th scope="col">月份<span class="month-zone">（北京时间）</span></th><th scope="col">出口</th><th scope="col">入口</th></tr></thead><tbody id="months"></tbody></table></div>`);
  const totals=card('累计用量',`<div class="kv">${row('累计发送',bind('allTx'))}${row('累计接收',bind('allRx'))}${row('统计起点',bind('since'))}</div>`);
  const details=card('采集状态',`<div class="kv">${row('当前网卡',bind('iface'))}${row('最新采样',bind('last'))}${row('采集状态',bind('fresh'))}</div>`);
  layout('流量',[['traffic','流量'],[null,monthly?'月度用量':'实时速率']],
    `<div class="stack">${tabs([['traffic','实时速率',!monthly],['traffic/month','月度用量',monthly]])}${region('traffic-error')}${monthly?`<div class="columns">${totals}${budget()}</div>${history}`:`${metrics()}<div class="columns">${chart()}${details}</div>`}</div>`,btn('settings','统计设置','settings','',traffic?'':'disabled'));
}
function updateTraffic() {
  replaceRegion('traffic-error',stale(trafficError,traffic?.last));
  const settingsButton=$('#page-actions [data-action=settings]');
  if(settingsButton)settingsButton.disabled=!traffic;
  if (!traffic) return;
  const t=traffic, fresh=t.fresh && performance.now()<trafficDeadline, last=fresh?t.points.at(-1):null;
  const [tx,txUnit]=rate(last?.tx_bps), [rx,rxUnit]=rate(last?.rx_bps);
  const [month,monthUnit]=quantity(t.current.tx,['B','KB','MB','GB','TB','PB']);
  const ratio=t.current.tx/t.settings.budget*100;
  const balance=t.settings.budget-t.current.tx;
  const since=t.settings.since;
  const startMonth=since ? new Date((since+8*3600)*1000).toISOString().slice(0,7) : null;
  const partialMonth=startMonth===t.current.month;
  const v={tx,txUnit,rx,rxUnit,month,monthUnit,percent:number(ratio,2),budget:bytes(t.settings.budget),
    used:bytes(t.current.tx),remaining:bytes(Math.abs(balance)),balanceLabel:balance<0?'超出额度':'剩余额度',
    allRx:bytes(t.total_rx),allTx:bytes(t.total_tx), since:since?beijingDate(since):'等待采样',
    period:since?(partialMonth?'本月数据自 ':'统计始于 ')+beijingDate(since)+(partialMonth?' 起采集':''):'等待首次采样',
    iface:t.iface||'等待采样',last:date(t.last),fresh:fresh?'采集中':t.last?'采样已过期':'等待有效采样'};
  for(const el of content.querySelectorAll('[data-live]')) el.textContent=v[el.dataset.live];
  const bar=$('#budget-bar');
  if(bar) {
    bar.style.width=Math.min(ratio,100)+'%';
    bar.dataset.state=balance<0?'over':balance===0?'at':'within';
  }
  const status=$('#budget-status');
  if(status) {
    status.hidden=!since;
    status.className='pill '+(balance<0?'bad':balance===0?'warn':'good');
    status.textContent=balance<0?'已超出额度':balance===0?'已达额度':'额度内';
  }
  const canvas=$('#rates'); if(canvas)drawTraffic(canvas,t.points);
  const months=$('#months');
  if(months) months.innerHTML=(t.months.length?t.months:[t.current]).map(m=>`<tr>
    <td data-label="月份（北京时间）">${esc(m.month)}</td>
    <td data-label="出口">${bytes(m.tx)}</td><td data-label="入口">${bytes(m.rx)}</td>
  </tr>`).join('');
}
function nodeTabs(n,section) {
  const root='nodes/'+n.protocol;
  const list=[[root,'连接与分享',!section],[root+'/status','证书与日志',section==='status']];
  if(n.protocol==='vless')list.push([root+'/diagnostics','Cloudflare 诊断',section==='diagnostics']);
  return tabs(list);
}
const diagnosticsReady = node => Boolean(!nodeError && node?.key && node.state==='active');
function clientTools(n) {
  const links = [
    ['windows', 'Windows EXE · x64'],
    ['linux', 'Linux Python 脚本']
  ].filter(([platform]) => server?.downloads?.[platform]);
  const buttons = links.map(([platform, title]) =>
    `<a class="btn" href="${esc(server.downloads[platform])}" target="_blank" rel="noopener noreferrer">${icon('download')}${title}</a>`).join('');
  const proxyNote = n && !n.cloudflare
    ? '<p class="node-change-note">当前节点尚未勾选“使用 Cloudflare 代理”。请确认端口为受支持的 Cloudflare HTTPS 端口，并在 Cloudflare 控制台开启橙色云。</p>'
    : '';
  return card('客户端测速',`
    ${proxyNote}
    <p class="muted">下载当前节点的测速任务，在日常使用节点的网络运行客户端（测速前请先关闭本地代理与 TUN 模式）。</p>
    <div class="client-downloads" aria-label="下载客户端">${buttons || '<span class="muted">当前版本的下载链接暂不可用</span>'}</div>
    <p class="muted">Windows 双击 EXE 后选择任务文件，结果保存在 EXE 旁边。</p>
    <p class="muted">Linux 运行 <code>python3 chennixvpn-cloudflare-linux.py test --task chennixvpn-cf-task.json</code>。</p>
    ${region('task-status')}`,
    btn('download-task','下载测速任务','download','primary','disabled'));
}
async function downloadTask() {
  const task=await api('nodes/vless/speedtest-task',{key:getNode('vless').key});
  const url=URL.createObjectURL(new Blob([JSON.stringify(task,null,2)+'\n'],{type:'application/json'}));
  const anchor=document.createElement('a');
  anchor.href=url;
  anchor.download='chennixvpn-cf-task.json';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function entryCard(n,kind) {
  const addr=kind==='original'?n.domain:n.entries[kind];
  const action=kind==='manual'?btn('manual','填写地址','edit','small'):kind==='preferred'?link('nodes/vless/diagnostics','选择 IP'):'';
  const buttons=addr&&n.key?btn('share','链接与二维码','qr','',`data-kind="${kind}"`):'';
  const hy2Note=n.protocol==='hy2' && n.up_mbps && n.down_mbps
    ? `<p class="muted">服务端已设 Brutal 带宽（上行 ${n.up_mbps} / 下行 ${n.down_mbps} Mbps）。Hysteria 2 分享链接不含带宽参数，开启 Brutal 需同时在客户端本地配置中填写上下行带宽。</p>`
    : '';
  return card(kinds[kind],`<div class="kv">${row('连接地址',esc(addr||'尚未设置'))}${row('端口',n.port??'—')}</div>${hy2Note}${buttons}`,action);
}
function reportTable(report) {
  const stats = [
    {label:'落地机房', value:r=>r.colo?pill(r.colo,'neutral'):'—'},
    {label:'成功率', value:r=>`${number(100*r.successes/r.attempts,1)}% <small>（${r.successes}/${r.attempts}）</small>`},
    {label:'握手中位数', value:r=>r.median_ms==null?'—':number(r.median_ms)+' ms'},
    {label:'Cloudflare 边缘下载', value:r=>r.download_mbps!=null?number(r.download_mbps)+' Mbps':
      r.download_error?`<span class="muted">失败 · ${esc(r.download_error)}</span>`:'未测'},
  ];
  const canPrefer = report.target_verified;
  const headings = ['候选 IP', ...stats.map(s=>s.label)];
  if (canPrefer) headings.push('分享');
  return `<div class="table-wrap"><table class="table report-table"><thead><tr>
    ${headings.map(label=>`<th scope="col">${label}</th>`).join('')}
    </tr></thead><tbody>${report.rows.map((r,i)=>`<tr>
      <td class="result-address mono">${esc(r.ip)}${canPrefer && i===0 && r.successes===r.attempts?' '+pill('测速首选','good'):''}${r.error?`<div class="muted">${esc(r.error)}</div>`:''}</td>
      ${stats.map(s=>`<td class="result-stat" data-label="${s.label}">${s.value(r)}</td>`).join('')}
      ${canPrefer?`<td class="result-action">${r.successes?btn('prefer','预览','qr','small',`data-ip="${esc(r.ip)}"`):'<span class="muted">不可用</span>'}</td>`:''}
    </tr>`).join('')}</tbody></table></div>`;
}
function reportBaseline(baseline) {
  if(!baseline)return '';
  const colo=baseline.colo?' · 机房 '+esc(baseline.colo):'';
  const latency=baseline.median_ms==null?'':' · 握手中位数 '+number(baseline.median_ms)+' ms';
  const failure=baseline.error?' · '+esc(baseline.error):'';
  return `<p class="muted">原始入口 · ${baseline.successes}/${baseline.attempts} 次握手成功${colo}${latency}${failure}</p>`;
}
function reportDiagnosis(diagnosis) {
  if(!diagnosis?.length)return '';
  return diagnosis.map(text=>`<p class="node-change-note">${esc(text)}</p>`).join('');
}
function nodeHealth(n) {
  const health=n.health||{};
  const labels={listening:'已监听',missing:'未检测到',unchecked:'未检查',unknown:'无法判断',valid:'在有效期内',invalid_dates:'超出有效期',current:'与磁盘证书一致',different:'与磁盘证书不同'};
  const processes={active:'运行中',inactive:'未运行',failed:'服务异常',activating:'启动中',deactivating:'停止中'};
  return stale(nodeError,health.checked_at)+`<div class="kv">
    ${row('安装状态',n.installed?'已完成':n.install_state==='incomplete'?'未完成':'未安装')}
    ${row('进程状态',processes[n.state]||'无法判断')}
    ${row('开机自启',n.boot_state===null?'无法判断':n.enabled?'已开启':'已关闭')}
    ${row(n.protocol==='hy2'?'HY2 UDP 监听':'Xray TCP 监听',labels[health.listener]||'未检查')}
    ${n.protocol==='vless'?row('Nginx TCP 入口',labels[health.ingress]||'未检查'):''}
    ${row('本机状态检查',date(health.checked_at))}
    </div><p class="muted">${n.protocol==='hy2'?'外网 QUIC、认证与实际转发请在客户端验证。':'请从客户端验证公网 TLS、WebSocket 和实际转发。'}</p>
    <div class="kv">${row('服务域名',esc(n.domain||'—'))}${row('磁盘证书有效期',labels[health.certificate]||'未检查')}
    ${row('磁盘证书到期时间',date(n.expires))}
    ${n.protocol==='hy2'?row('HY2 启动时加载的证书',labels[health.loaded_certificate]||'未检查'):''}
    ${row('Certbot 自动续期',server.timer==='active'?'定时器运行中':esc(server.timer))}</div>`;
}
function connectionContent(n) {
  if (!n.installed || !n.key) {
    if (n.conflicts?.length) return empty('请在服务器核对冲突文件：'+n.conflicts.map(esc).join('、'));
    return empty(n.can_repair?'安装未完成。选择“恢复并启动”可继续使用原有节点凭据。':'服务端完成协议安装后，将在这里显示连接信息');
  }
  if (n.state!=='active') return empty(names[n.protocol]+' 当前未运行')+link('settings','打开设置');
  if (n.protocol==='vless' && server.sharing_error) return empty(server.sharing_error);
  const available=n.protocol==='hy2'?['original']:server.vless_entry_kinds;
  if (!available.length) return empty('所有 VLESS 分享入口均已关闭')+link('settings','选择分享入口');
  if (available.length===1) return entryCard(n,available[0]);
  return `<div class="entry-grid ${available.length===2?'entry-pair':''}">${available.map(k=>entryCard(n,k)).join('')}</div>`;
}
function reportMeta(r) {
  return `<span data-report-node="${esc(r.node)}">${reportScope(r.node)}</span> · <span>${r.target_verified?'目标已核对':'目标未验证'}</span>${r.measured_at?` · <span>测试于 ${date(r.measured_at)}</span>`:''} · <span>${date(r.ts)} 导入</span>`;
}
function reportScope(key) {
  if(nodeError || !server)return '配置状态待确认';
  return getNode('vless')?.key===key?'当前配置':'历史配置';
}
function deleteReportButton(r, label='删除') {
  return btn('delete-report',label,'','small danger',
    `data-id="${r.id}" data-name="${esc(r.name)}" aria-label="删除报告 ${esc(r.name)}"`);
}
function reportList(reports) {
  if(!reports.length)return empty('还没有测速报告');
  return `<div class="data-list">${reports.map(r=>`
    <div class="report-list-item">
      <a class="node-row" href="#/${diagnosticsPath}/${r.id}">
        <span class="node-mark">${icon('chart')}</span>
        <div><strong>${esc(r.name)}</strong><div class="muted">${reportMeta(r)} · ${r.usable}/${r.count} 可用</div></div>
        ${icon('chevron')}
      </a>
      ${deleteReportButton(r)}
    </div>`).join('')}</div>`;
}
async function nodePage(n,seq) {
  const root='nodes/'+n.protocol, section=page[2], tail=page[3];
  const crumbs=[['nodes','节点'],[root,names[n.protocol]]];
  const edit = region('node-edit', editNodeButton(n));
  let html,actions=edit,title=names[n.protocol];
  if(section==='status'){
    crumbs.push([null,'证书与日志']);
    html=card('本机状态与证书',region('node-health',nodeHealth(n)))+card('服务日志',region('node-logs',empty('正在读取日志')));
    layout(title,crumbs,`<div class="stack">${nodeTabs(n,section)}${html}</div>`,edit+btn('refresh','刷新','refresh','ghost'));
    try {
      const {logs}=await api('nodes/'+n.protocol+'/logs');
      if(seq===revision)replaceRegion('node-logs',`<pre class="log-output">${esc(logs||'暂无服务日志')}</pre>`);
    } catch(err) {
      if(seq===revision)replaceRegion('node-logs',empty(err.message));
    }
    return;
  }else if(section==='diagnostics' && n.protocol==='vless'){
    title='Cloudflare 诊断';
    crumbs.push([root+'/diagnostics','Cloudflare 诊断']);
    try {
      if(tail){
        const detail=await api('reports/'+encodeURIComponent(tail));
        if(seq!==revision)return;
        report=detail;
        title='报告详情';
        crumbs.push([null,'报告详情']);
        html=card(report.name,`<p class="report-meta">${reportMeta(report)}<span>${report.usable} / ${report.count} 个地址握手成功</span></p>${reportBaseline(report.baseline)}${reportDiagnosis(report.diagnosis)}<p class="muted">按握手成功率、Cloudflare 边缘下载速度和握手延迟排序。下载只测初筛前列候选，结果不代表 VLESS 实际吞吐量。</p>${region('report-status')}${reportTable(report)}`,
          deleteReportButton(report,'删除报告'));
      }else{
        const reports=await api('reports');
        if(seq!==revision)return;
        html=card('导入测速报告',`<p class="muted">选择客户端生成的 <code>*-report.csv</code>。</p>${region('import-status')}<input id="csv-file" type="file" accept=".csv,text/csv" hidden>`,
          btn('choose-csv','选择报告','upload','primary','disabled'))
          +card('测速报告',reportList(reports));
      }
    } catch(err) {
      html=empty(err.message);
      actions+=btn('refresh','重试','refresh','ghost');
    }
    if(!tail) html=clientTools(n)+html;
  }else if(!section){
    html=region('node-status-error',stale(nodeError,server.checked_at))+region('node-connection',connectionContent(n));
    actions+=region('node-badge',stateOf(n));
  }else{throw Error('页面不存在');}
  if(seq===revision)layout(title,crumbs,`<div class="stack">${nodeTabs(n,section)}${html}</div>`,actions);
}
function protocolSetting(n) {
  const name=names[n.protocol];
  const control=(operation,label)=>btn('set-protocol',label,'','small',
    `data-protocol="${n.protocol}" data-operation="${operation}" aria-label="${label} ${name}" ${nodeMutationsDisabled()?'disabled':''}`);
  let controls='';
  if(n.installed) {
    if(!n.enabled || n.state!=='active') controls+=control('enable','启用');
    if(n.enabled || !['inactive','failed'].includes(n.state)) controls+=control('disable','停用');
  }else if(n.can_repair) controls=control('repair','恢复并启动');
  return `<div class="protocol-setting" data-protocol-row="${n.protocol}"><div class="setting-name"><strong>${name}</strong>
    ${n.installed?`<small>开机自启${n.enabled?'已开启':'已关闭'}</small>`:''}</div>
    ${stateOf(n)}<div class="setting-actions">${controls}</div></div>`;
}
function protocolSettings() {
  if (!server) return empty(nodeError||'正在读取协议服务');
  if (!server.nodes.length) return empty('还没有节点')+link('nodes','打开节点页面');
  return stale(nodeError,server.checked_at)+server.nodes.map(protocolSetting).join('');
}
function entrySettings() {
  if (!server || server.sharing_error) return empty(server?.sharing_error||nodeError||'正在读取分享设置');
  const descriptions={original:'使用节点域名',preferred:'使用测速报告中握手成功的 IP',manual:'手动指定 IP 或域名'};
  return Object.entries(kinds).map(([kind,name])=>`<label class="entry-setting">
    <span class="setting-name"><strong id="name-${kind}">${name}</strong><small id="hint-${kind}">${descriptions[kind]}</small></span>
    <input type="checkbox" role="switch" data-entry-kind="${kind}" aria-labelledby="name-${kind}" aria-describedby="hint-${kind}" ${server.vless_entry_kinds.includes(kind)?'checked':''}>
    </label>`).join('');
}
function settingsTabs(showUpdates) {
  return tabs([['settings','常规',!showUpdates],['settings/updates','更新',showUpdates]]);
}
function updateRows() {
  const checkError = updatesError ? stale(updatesError) : '';
  return checkError+Object.entries(components).map(([target, name])=>{
    const status=updates?.[target];
    const installed=target==='project'?server?.project_version:getNode(target)?.version;
    const available=status?.available===true && status.installed===installed;
    let action='';
    if(available) action=btn('upgrade', '升级至 '+status.latest, 'up','small',
      `data-target="${target}" ${nodeMutationsDisabled() || checkingUpdates?'disabled':''}`);
    return `<div class="update-row">
      <strong>${name}</strong>
      <div class="update-versions"><span>已安装 <b>${esc(installed||(server?'未安装':'—'))}</b></span><span>最新稳定版 <b>${esc(status?.latest||'—')}</b></span></div>
      ${status?.error?`<span class="update-error" role="status">${esc(status.error)}</span>`:action}</div>`;
  }).join('');
}
function releaseSource(source) {
  if(source?.kind==='github-release')return 'GitHub Release'+(source.tag?' · '+source.tag:'');
  if(source?.kind==='git')return 'Git 源码'+(source.commit?' · '+source.commit.slice(0,12):'');
  if(source?.kind==='source')return '本地源码';
  return '来源未知';
}
function installedVersionRows() {
  if(installedVersionsError)return stale(installedVersionsError);
  if(!installedVersions)return empty('正在读取本机已保存版本');
  if(!installedVersions.releases.length)return empty('没有已保存的面板版本');
  const status={current:['当前运行','good'],rollback:['保留回滚','neutral'],deletable:['可清理','neutral'],protected:['受保护','warn']};
  return `<p class="card-caption">仅保存面板源码；当前版和最近一个旧版不可删除。</p><div class="data-list">${installedVersions.releases.map(item=>{
    const [label,style]=status[item.status]||status.protected;
    const action=item.status==='deletable'?btn('delete-release','删除','close','small danger',
      `data-id="${esc(item.id)}" ${nodeMutationsDisabled()?'disabled':''}`):'';
    return `<div class="update-row release-row"><strong>${esc(item.version)} ${pill(label,style)}</strong><div class="update-versions"><span>${date(item.deployed_at)}</span><span>${esc(releaseSource(item.source))}</span><span>${item.size_bytes==null?'大小未知':bytes(item.size_bytes)}</span>${item.reason?`<span class="muted">${esc(item.reason)}</span>`:''}</div>${action}</div>`;
  }).join('')}</div>`;
}
function updatesPage() {
  const check=btn('check-updates','检查更新','refresh','primary',checkingUpdates?'disabled':'');
  const panel=card('版本更新',region('updates-list',updateRows()),check);
  const installed=card('本机已保存版本',region('installed-versions',installedVersionRows()));
  layout('设置',[['settings','设置'],[null,'更新']],`<div class="stack">${settingsTabs(true)}${panel}${installed}</div>`);
}
function settingsPage() {
  const services=card('协议服务','<p class="muted">停用会断开该协议的连接，并关闭开机自启。重新启用后可继续使用原有节点。</p>'+region('protocol-settings',protocolSettings()));
  const sharing=card('VLESS 分享入口','<p class="muted">选择面板可以生成的链接和二维码。设置即时保存，已导入客户端的链接仍可使用。</p>'+region('entry-settings',entrySettings()));
  const certificates=server?.obsolete_certificates?.length?card('旧证书',`<p class="muted">以下证书已无节点引用，可以停止 Certbot 续期并删除。</p><div class="data-list">${server.obsolete_certificates.map(cert=>`<div class="node-row"><span class="node-mark">${icon('lock')}</span><div><strong>${esc(cert)}</strong><div class="muted">项目旧证书</div></div>${btn('retire-certificate','清理证书','close','small',`data-cert="${esc(cert)}"`)}</div>`).join('')}</div>`):'';
  layout('设置',[['settings','设置']],`<div class="stack">${settingsTabs(false)}<div class="settings-grid">${services}${sharing}</div>${certificates}</div>`);
}
function editNodeButton(node) {
  if(!node.installed) return node.can_repair?btn('set-protocol','恢复并启动','network','primary',
    `data-protocol="${node.protocol}" data-operation="repair" ${nodeMutationsDisabled()?'disabled':''}`):'';
  return btn('edit-node','修改配置','edit','',`data-protocol="${node.protocol}" ${nodeMutationsDisabled()?'disabled':''}`);
}
function updateNodeActions() {
  replaceRegion('node-create',createNodeButton());
  const node=getNode(page[1]);
  if(node)replaceRegion('node-edit',editNodeButton(node));
  replaceRegion('protocol-settings',protocolSettings());
  replaceRegion('updates-list',updateRows());
  replaceRegion('installed-versions',installedVersionRows());
  for(const button of document.querySelectorAll('[data-action="create-node"], [data-action="edit-node"], [data-action="set-protocol"], [data-action="upgrade"], [data-action="retire-certificate"], [data-action="delete-release"]')) {
    button.disabled=nodeMutationsDisabled() || (button.dataset.action==='upgrade' && checkingUpdates);
  }
}
function updateNodeViews() {
  const active=$('#active-nodes'), total=$('#total-nodes'), status=$('#node-metric-status');
  if (active) {
    active.textContent=server?server.nodes.filter(n=>n.state==='active').length:'—';
    total.textContent=server?'/ '+server.nodes.length:'';
    status.textContent=nodeError?'节点状态更新失败':'本机进程状态';
  }
  replaceRegion('nodes-list',nodesList());
  replaceRegion('latest-report',latestCheck());
  updateNodeActions();
  renderJobStatus();
  if (!$('[data-region="entry-settings"] input:disabled')) replaceRegion('entry-settings',entrySettings());
  const node=getNode(page[1]);
  if(page[2]==='diagnostics'){
    const live=diagnosticsReady(node);
    const task=$('[data-action="download-task"]');
    if(task)task.disabled=!live || task.getAttribute('aria-busy')==='true';
    replaceRegion('task-status',live?'':empty('启动 VLESS 后可下载当前节点的测速任务。'));
    const choose=$('[data-action="choose-csv"]');
    if(choose)choose.disabled=!live;
    replaceRegion('import-status',live?'':empty('启动 VLESS 后可导入当前节点的报告。'));
    for(const label of content.querySelectorAll('[data-report-node]'))label.textContent=reportScope(label.dataset.reportNode);
    if(report){
      const canPrefer=live && node.key===report.node && !server.sharing_error && server.vless_entry_kinds.includes('preferred');
      replaceRegion('report-status',canPrefer?'':empty('可查看报告。应用优选入口需运行对应配置并开启优选分享。'));
      for(const button of content.querySelectorAll('[data-action="prefer"]'))button.disabled=!canPrefer;
    }
  }
  if (!node) return;
  replaceRegion('node-health',nodeHealth(node));
  replaceRegion('node-badge',stateOf(node));
  replaceRegion('node-status-error',stale(nodeError,server?.checked_at));
  if (!dialog.open) replaceRegion('node-connection',connectionContent(node));
}
const trafficPageOpen = () => !page.length || page[0]==='traffic';
const nodesPageOpen = () => !page.length || page[0]==='nodes' || page[0]==='settings' || (page[0]==='traffic' && !page[1]);

function renderJobStatus() {
  const el=$('#job-status');
  const latest=activeJob() || jobs[0];
  const targetName=latest?.operation==='retire_certificate'?'':components[latest?.target]||names[latest?.target]||'';
  const title=latest
    ? (jobOperations[latest.operation] || '操作')+' '+targetName
    : '';
  const state=latest && jobStates[latest.state];
  const detail=jobsError || latest?.message;
  const markup=state
    ? `<div class="job-status-line"><strong>${esc(title)}</strong>${pill(...state)}</div>${detail?`<p class="muted">${esc(detail)}</p>`:''}`
    : '';
  if(el.innerHTML!==markup)el.innerHTML=markup;
  el.hidden=!markup;
}

async function refreshJobs() {
  if(readingJobs || submittingJob || document.hidden)return;
  readingJobs=true;
  clearTimeout(jobsTimer);
  const version=jobVersion;
  const before=jobs[0];
  try {
    const tracked=jobs.find(jobPending);
    const data=tracked&&!listRequested?await api('jobs/'+tracked.id):await api('jobs');
    listRequested=false;
    if(version!==jobVersion)return;
    const latest=tracked&&!data.jobs?{...data,message:data.message||'正在执行。'}:null;
    jobs=data.jobs || (latest?[latest,...jobs.filter(job=>job.id!==latest.id)]:jobs);
    jobsError=null;
    const after=jobs[0];
    if(before && jobPending(before) && after && !jobPending(after)) {
      nodeVersion++;
      if(nodesPageOpen()) {
        const seq=revision;
        await refreshNodes(seq);
        if(seq===revision && getNode(page[1]) && !dialog.open && $('[data-region="node-unavailable"]'))await render();
      }else if(after.operation==='upgrade' && after.target==='project')updates=null;
      if(after.operation==='delete_release' || (after.operation==='upgrade' && after.target==='project')) {
        installedVersions=null;
        installedVersionsError=null;
        if(page.join('/')==='settings/updates')await refreshInstalledVersions();
      }
      if(getNode(page[1])?.protocol===after.target)await render();
      if(after.operation==='retire_certificate')await render();
      if(after.state==='succeeded') {
        notice(after.message);
        if((after.operation==='create'||after.operation==='repair') && !dialog.open) {
          const n=getNode(after.target);
          if(n?.installed && location.hash!=='#/nodes/'+after.target)openPage('nodes/'+after.target);
        }
      }
    }
  } catch(err) {
    if(version!==jobVersion)return;
    jobsError='暂时无法读取操作进度，正在重试';
    if(jobs.find(jobPending))listRequested=true;
  } finally {
    readingJobs=false;
    if(version===jobVersion && !submittingJob) {
      renderJobStatus();
      updateNodeActions();
    }
    scheduleJobs();
  }
}
function scheduleJobs() {
  clearTimeout(jobsTimer);
  jobsTimer=setTimeout(refreshJobs,jobs.find(jobPending)?1500:60000);
}

async function refreshInstalledVersions() {
  try {
    installedVersions=await api('installed-versions');
    installedVersionsError=null;
  } catch(err) {
    installedVersions=null;
    installedVersionsError='本机版本读取失败：'+err.message;
  }
  if(page.join('/')==='settings/updates')replaceRegion('installed-versions',installedVersionRows());
}

async function queueJob(payload) {
  if(activeJob() || submittingJob)throw Error('请等待当前操作完成');
  submittingJob=true;
  jobVersion++;
  updateNodeActions();
  try {
    const result=await api('jobs',payload);
    jobs=[{...payload,id:result.id,state:'queued'},...jobs];
    jobsError=null;
    renderJobStatus();
  } finally {
    submittingJob=false;
    updateNodeActions();
    scheduleJobs();
  }
}

async function checkUpdates(button) {
  if(checkingUpdates)return;
  checkingUpdates=true;
  updatesError=null;
  button.disabled=true;
  button.textContent='正在检查…';
  updateNodeActions();
  try {
    updates=await api('updates/check',{});
  } catch(err) {
    updatesError=err.message;
    updates=null;
  } finally {
    checkingUpdates=false;
    const check=$('[data-action="check-updates"]');
    if(check) {
      check.disabled=false;
      check.innerHTML=icon('refresh')+'检查更新';
    }
    updateNodeActions();
  }
}

async function refreshTraffic(seq) {
  const request=++trafficRequest;
  try {
    const data=await api('traffic');
    if(seq!==revision || request!==trafficRequest)return;
    traffic=data;
    trafficError=null;
    const age=traffic.sample_age_s;
    trafficDeadline=age==null?0:performance.now()+Math.max(0,20-age)*1000;
    clearTimeout(trafficExpiryTimer);
    if(trafficDeadline>performance.now())trafficExpiryTimer=setTimeout(updateTraffic,trafficDeadline-performance.now()+50);
  } catch(err) {
    if(seq!==revision || request!==trafficRequest)return;
    trafficError='流量读取失败：'+err.message;
  }
  updateTraffic();
  connected();
}
async function refreshNodes(seq) {
  const version=nodeVersion;
  try {
    const data=await api('nodes');
    if(seq!==revision || version!==nodeVersion)return;
    server=data;
    nodeError=null;
  } catch(err) {
    if(seq!==revision || version!==nodeVersion)return;
    nodeError='节点读取失败：'+err.message;
  }
  updateNodeViews();
  connected();
}
async function render() {
  const seq=++revision;
  const startAtTop=scrollTarget===location.hash;
  scrollTarget=null;
  page=location.hash.replace(/^#\/?/,'').split('/').filter(Boolean);
  if(dialog.open)dialog.close();
  report=null;
  const nodesRequest=nodesPageOpen()?refreshNodes(seq):null;
  if(trafficPageOpen())void refreshTraffic(seq);
  listRequested=true;
  void refreshJobs();
  try{
    if(!page.length)overview();
    else if(page[0]==='traffic' && (!page[1]||page[1]==='month'))trafficPage();
    else if(page.join('/')==='nodes')layout('节点',[['nodes','节点']],card('协议节点',region('nodes-list',nodesList())),region('node-create',createNodeButton()));
    else if(page.join('/')==='settings'){
      await nodesRequest;
      if(seq!==revision)return;
      settingsPage();
    }
    else if(page.join('/')==='settings/updates'){
      updatesPage();
      void refreshInstalledVersions();
    }
    else if(page[0]==='nodes' && Object.hasOwn(names,page[1])){
      await nodesRequest;
      if(seq!==revision)return;
      const node=getNode(page[1]);
      if(node)await nodePage(node,seq);
      else {
        const create=btn('create-node','创建节点','network','primary',`data-protocol="${page[1]}"`);
        layout(names[page[1]],[['nodes','节点'],[null,names[page[1]]]],
          region('node-unavailable',empty(nodeError||'该节点尚未创建')),nodeError?btn('refresh','重试','refresh'):create);
      }
    }
    else throw Error('页面不存在');
    if(seq===revision){updateTraffic();updateNodeViews();}
  }catch(err){
    if(seq===revision)layout('无法读取页面',[[null,'读取失败']],empty(err.message),btn('refresh','重试','refresh'));
  }
  if(seq===revision && startAtTop)window.scrollTo(0,0);
}
function openPage(path) {
  scrollTarget='#/'+path;
  location.hash=scrollTarget;
}
function modal(title,body,actions='') {
  dialog.innerHTML=`<div class="dialog-head"><h2>${esc(title)}</h2>${btn('close','关闭','close','small ghost')}</div><div class="dialog-body">${body}</div>${actions?'<div class="dialog-actions">'+actions+'</div>':''}<p id="dialog-note" role="status" hidden></p>`;
  dialog.setAttribute('aria-label',title);
  if(!dialog.open)dialog.showModal();
}
async function sharing(kind, extra={}) {
  const seq=revision, token=++modalVersion, n=getNode(page[1]), payload={kind,key:n.key,...extra};
  const data=await api('nodes/'+n.protocol+'/share',payload);
  if(seq!==revision||token!==modalVersion)return;
  pendingShare={protocol:n.protocol,payload,uri:data.uri};
  modal(kinds[kind],`<div class="share-details"><canvas id="share-code" class="qr"></canvas><label class="field">节点链接<textarea readonly rows="3" class="share-link" id="share-uri"></textarea></label></div>`,
    btn('copy','复制链接','copy')+(extra.address?btn('save-entry','保存为'+kinds[kind],'check','primary'):''));
  $('#share-uri').value=data.uri;
  try{drawQR($('#share-code'),data.uri);}catch(err){notice(err.message);}
}
function settings() {
  const s=traffic.settings;
  modal('流量统计设置',`<form id="settings-form"><label class="field">采集网卡<select name="iface"><option value="">自动选择主网卡</option>${traffic.interfaces.map(n=>`<option value="${esc(n)}" ${s.iface===n?'selected':''}>${esc(n)}</option>`).join('')}</select></label><label class="field">每月出口参考额度（TB）<input type="number" name="tb" required min="0.001" max="10000" step="0.001" value="${s.budget/1e12}"></label><p class="muted">按北京时间自然月累计所选网卡的发送量。</p><button class="btn primary" type="submit">保存设置</button></form>`);
}
function updateNodeForm(form) {
  const target=form.elements['target'].value;
  const node=getNode(target);
  const proxyLabel=form.querySelector('.proxy-option');
  const hy2Bandwidth=form.querySelector('#hy2-bandwidth');
  proxyLabel.hidden=target!=='vless';
  form.querySelector('#cloudflare-hint').hidden=target!=='vless';
  hy2Bandwidth.hidden=target!=='hy2';
  form.elements['cloudflare'].checked=target==='vless' && Boolean(node?.cloudflare);
  form.elements['up_mbps'].value=target==='hy2' && node?.up_mbps ? node.up_mbps : '';
  form.elements['down_mbps'].value=target==='hy2' && node?.down_mbps ? node.down_mbps : '';
  form.elements['domain'].value=node?.domain||'';
  form.elements['domain'].placeholder=target==='vless'?'ws.example.com':'hy2.example.com';
  form.elements['email'].value=node?.email||'';
  form.elements['port'].value=node?.port||(target==='hy2'?8443:443);
  form.querySelector('#port-label').textContent=target==='vless'?'VLESS 公网端口（TCP）':'Hysteria 2 公网端口（UDP）';
  form.querySelector('#node-port-hint').textContent=target==='vless'
    ? '使用 Cloudflare 代理时，请填写受支持的 HTTPS 端口（443、2053、2083、2087、2096、8443）。'
    : '请将节点域名直接解析到 VPS（仅 DNS），并在防火墙放行该 UDP 端口（推荐避开 443）。';
}
function nodeForm(preferred, editing=false) {
  const protocols = editing ? [preferred] : availableProtocols();
  if(!protocols.length)return;
  const target=protocols.includes(preferred)?preferred:protocols[0];
  const protocolField=protocols.length===1 ? `<input type="hidden" name="target" value="${target}">`
    : `<label class="field">协议<select name="target" autofocus>${protocols.map(p=>`<option value="${p}" ${p===target?'selected':''}>${names[p]}</option>`).join('')}</select></label>`;
  const action=editing?'应用设置':'创建并启动';
  const title=editing?'修改 '+names[target]:protocols.length===1?'创建 '+names[target]:'创建节点';
  modal(title,`
    <form id="node-form" data-operation="${editing?'configure':'create'}">
      ${protocolField}
      <label class="field">节点域名<input name="domain" autocomplete="off" required maxlength="253" spellcheck="false" inputmode="url" ${protocols.length===1?'autofocus':''}></label>
      <label class="field">证书邮箱<input name="email" type="email" autocomplete="email" required maxlength="254"></label>
      <label class="field"><span id="port-label">公网端口</span><input name="port" type="number" required min="1" max="65535" step="1" aria-describedby="node-port-hint"><small id="node-port-hint"></small></label>
      <div id="hy2-bandwidth">
        <label class="field">服务端上行带宽（Mbps，可选）<input name="up_mbps" type="number" min="1" max="10000" step="1" placeholder="留空使用 BBR，如 100"></label>
        <label class="field">服务端下行带宽（Mbps，可选）<input name="down_mbps" type="number" min="1" max="10000" step="1" placeholder="同时填写上下行以启用 Brutal，如 300"></label>
        <p class="muted">留空使用 BBR；Hysteria 2 分享链接不含带宽参数，填写服务器上下行带宽后，还需在客户端本地配置中填写带宽以激活 Brutal 抗丢包拥塞控制。</p>
      </div>
      <label class="proxy-option"><input type="checkbox" name="cloudflare">使用 Cloudflare 代理</label>
      <p class="muted" id="cloudflare-hint">首次创建建议先在 Cloudflare 设为“仅 DNS”（灰色云）以签发证书；节点启动后再点亮“已代理”（橙色云），并将 Cloudflare SSL/TLS 加密模式设为“完全（严格）/ Full (Strict)”。</p>
      <p class="muted">先把节点域名指向这台 VPS，再在安全组和防火墙放行 TCP 80 和节点端口。</p>
      ${editing?`<p class="node-change-note">域名或端口变更后，请重新导入该节点的分享链接。${target==='vless'?'优选地址需要重新测速。':''}</p>`:''}
      <button class="btn primary" type="submit">${action}</button>
    </form>`);
  updateNodeForm($('#node-form'));
}
function confirmUpgrade(target) {
  const version=updates?.[target]?.latest;
  if(!version)return;
  modal('升级 '+components[target],`
    <form id="upgrade-form" data-target="${target}" data-version="${esc(version)}">
      <p>将 ${components[target]} 升级至 <strong>${esc(version)}</strong>。${target==='project'?'面板会短暂重启。':'运行中的节点会短暂断开。'}</p>
      <button class="btn primary" type="submit">确认升级</button>
    </form>`);
}
function confirmCertificate(cert) {
  modal('清理旧证书',`<form id="certificate-form" data-cert="${esc(cert)}">
    <p>将停止 Certbot 对 <strong>${esc(cert)}</strong> 的续期并删除证书文件。</p>
    <button class="btn primary" type="submit">确认清理</button>
  </form>`);
}
function confirmReleaseDeletion(id) {
  const item=installedVersions?.releases.find(release=>release.id===id && release.status==='deletable');
  if(!item){notice('该版本已变化或受保护，请刷新后重试');return;}
  modal('删除本机旧版本',`<form id="delete-release-form" data-id="${esc(item.id)}">
    <p>确定删除 <strong>${esc(item.version)}</strong> 的旧源码？此操作无法恢复。</p>
    <p class="muted">只删除旧源码，不影响数据库、节点、密码、证书或测速报告。当前版和最近一个旧版会保留。</p>
    <button class="btn danger" type="submit">确认删除</button>
  </form>`);
}
function confirmReportDeletion(id,name) {
  modal('删除测速报告',`<form id="delete-report-form" data-id="${id}">
    <p>确定删除 <strong>${esc(name)}</strong>？删除后无法恢复。</p>
    <button class="btn danger" type="submit">确认删除</button>
  </form>`);
}
document.addEventListener('click',async e=>{
  const routeLink=e.target.closest('a[href^="#/"]');
  if(routeLink){
    if(!e.defaultPrevented && !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey){
      if(routeLink.hash===location.hash)window.scrollTo(0,0);
      else scrollTarget=routeLink.hash;
    }
    return;
  }
  const b=e.target.closest('button[data-action]'); if(!b)return;
  if(b.getAttribute('aria-disabled')==='true')return;
  const action=b.dataset.action;
  try{
    if(action==='close'){dialog.close();return;}
    if(action==='refresh'){await render();return;}
    if(action==='settings'){settings();return;}
    if(action==='create-node'){nodeForm(b.dataset.protocol);return;}
    if(action==='edit-node'){nodeForm(b.dataset.protocol,true);return;}
    if(action==='set-protocol'){await queueJob({operation:b.dataset.operation,target:b.dataset.protocol});return;}
    if(action==='check-updates'){await checkUpdates(b);return;}
    if(action==='upgrade'){confirmUpgrade(b.dataset.target);return;}
    if(action==='retire-certificate'){confirmCertificate(b.dataset.cert);return;}
    if(action==='choose-csv'){$('#csv-file').click();return;}
    if(action==='delete-report'){confirmReportDeletion(b.dataset.id,b.dataset.name);return;}
    if(action==='delete-release'){confirmReleaseDeletion(b.dataset.id);return;}
    if(action==='manual'){
      modal('自选入口',`<form id="manual-form"><label class="field">IP 或域名<input required maxlength="253" name="address" value="${esc(getNode('vless').entries.manual||'')}" placeholder="输入自选优选 IP 或优选域名（自动保留原域名 SNI/Host）"></label><button class="btn primary" type="submit">预览链接与二维码</button></form>`);return;
    }
    b.disabled=true;
    if(action==='download-task'){
      b.setAttribute('aria-busy','true');
      await downloadTask();
      return;
    }
    if(action==='share')await sharing(b.dataset.kind);
    if(action==='prefer')await sharing('preferred',{address:b.dataset.ip,report:report.id});
    if(action==='copy'){
      try{await navigator.clipboard.writeText(pendingShare.uri);notice('已复制节点链接');}
      catch{$('#share-uri').select();if(document.execCommand('copy'))notice('已复制节点链接');else notice('请复制已选中的链接');}
    }
    if(action==='save-entry'){
      await api('nodes/'+pendingShare.protocol+'/share',{...pendingShare.payload,save:true});
      dialog.close();notice('已保存入口');if(location.hash==='#/nodes/vless')await render();else openPage('nodes/vless');
    }
  }catch(err){notice(err.message);}finally{
    if(action==='download-task')b.removeAttribute('aria-busy');
    b.disabled=action==='download-task' && !diagnosticsReady(getNode('vless'));
    updateNodeActions();
  }
});
dialog.addEventListener('submit',async e=>{
  e.preventDefault(); const f=e.target, data=new FormData(f), button=f.querySelector('button[type=submit]');button.disabled=true;
  try{
    if(f.id==='manual-form'){await sharing('manual',{address:String(data.get('address')).trim()});}
    if(f.id==='settings-form'){
      await api('settings',Object.fromEntries(data));dialog.close();notice('已保存流量设置');await render();
    }
    if(f.id==='node-form'){
      const target=data.get('target');
      const payload={
        operation:f.dataset.operation,target,domain:data.get('domain').trim(),
        email:data.get('email').trim(),port:Number(data.get('port'))
      };
      if(target==='vless')payload.cloudflare=data.has('cloudflare');
      if(target==='hy2'){
        const up=String(data.get('up_mbps')||'').trim();
        const down=String(data.get('down_mbps')||'').trim();
        payload.up_mbps=up?Number(up):0;
        payload.down_mbps=down?Number(down):0;
        if(Boolean(payload.up_mbps)!==Boolean(payload.down_mbps))throw Error('配置 Hysteria 2 Brutal 带宽时，需同时填写上行和下行带宽');
      }
      await queueJob(payload);
      if(dialog.open && f.isConnected)dialog.close();
    }
    if(f.id==='upgrade-form'){
      await queueJob({operation:'upgrade',target:f.dataset.target,version:f.dataset.version});
      if(dialog.open && f.isConnected)dialog.close();
    }
    if(f.id==='certificate-form'){
      await queueJob({operation:'retire_certificate',target:'project',cert:f.dataset.cert});
      if(dialog.open && f.isConnected)dialog.close();
    }
    if(f.id==='delete-report-form'){
      const seq=revision, id=f.dataset.id;
      await api('reports/'+encodeURIComponent(id)+'/delete',{});
      if(seq!==revision)return;
      if(dialog.open && f.isConnected)dialog.close();
      notice('已删除测速报告');
      if(page[3])openPage(diagnosticsPath);
      else await render();
    }
    if(f.id==='delete-release-form'){
      await queueJob({operation:'delete_release',target:'project',release_id:f.dataset.id});
      if(dialog.open && f.isConnected)dialog.close();
    }
  }catch(err){notice(err.message);}finally{button.disabled=false;}
});
dialog.addEventListener('change',e=>{
  if(e.target.matches('#node-form select[name="target"]'))updateNodeForm(e.target.form);
});
dialog.addEventListener('close',()=>{if(!dialog.open){modalVersion++;pendingShare=null;dialog.replaceChildren();}});
content.addEventListener('change',async e=>{
  if(e.target.matches('[data-entry-kind]')){
    const input=e.target, kind=input.dataset.entryKind, enabled=input.checked, seq=revision;
    input.disabled=true;
    nodeVersion++;
    try {
      await api('settings/entries/'+kind,{enabled});
      nodeVersion++;
      if(seq===revision){
        const selected=new Set(server.vless_entry_kinds);
        if(enabled)selected.add(kind);else selected.delete(kind);
        server.vless_entry_kinds=Object.keys(kinds).filter(value=>selected.has(value));
        notice(kinds[kind]+(enabled?'已开启':'已关闭'));
      }
    } catch(err) {
      nodeVersion++;
      if(seq===revision){await render();notice(err.message);}
    } finally {input.disabled=false;}
    return;
  }
  if(e.target.id!=='csv-file')return;
  const input=e.target,file=input.files[0];if(!file)return;
  const seq=revision,key=getNode('vless').key;input.disabled=true;
  try{
    if(file.size>1000000)throw Error('请选择小于 1 MB 的 CSV');
    const data=await api('reports',{key,name:file.name,csv:await file.text()});
    if(seq===revision)openPage(diagnosticsPath+'/'+data.id);
  }catch(err){notice(err.message);}finally{input.value='';input.disabled=false;}
});
function poll(refresh, isOpen, every) {
  let pending=false;
  setInterval(async()=>{
    if(pending || document.hidden || !isOpen())return;
    const seq=revision;
    pending=true;
    try{
      await refresh(seq);
      if(refresh===refreshNodes && seq===revision && getNode(page[1]) && !dialog.open && $('[data-region="node-unavailable"]'))await render();
    }finally{pending=false;}
  },every);
}
poll(refreshTraffic,trafficPageOpen,5000);
poll(refreshNodes,nodesPageOpen,15000);
document.querySelectorAll('[data-icon]').forEach(el=>el.innerHTML=icon(el.dataset.icon));
window.addEventListener('hashchange',render);
document.addEventListener('visibilitychange',()=>{if(!document.hidden){if(trafficPageOpen())refreshTraffic(revision);refreshJobs();}});
render();
