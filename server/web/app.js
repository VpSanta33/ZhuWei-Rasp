/* ZhuWei-RASP console. Plain Vue 3 (global build), hash routing, no build step. */
(function () {
  const { createApp, reactive, ref, computed, onMounted, watch } = Vue;

  const TYPES = ['sql', 'command', 'readFile', 'writeFile', 'ssrf', 'deserialization', 'jndi'];
  const TYPE_NAMES = {
    sql: 'SQL', command: '命令执行', readFile: '文件读取', writeFile: '文件写入',
    ssrf: 'SSRF', deserialization: '反序列化', jndi: 'JNDI',
  };
  const STATUS_NAMES = { new: '待处理', confirmed: '已确认', false_positive: '误报', fixed: '已修复', ignored: '已忽略' };

  const state = reactive({ token: localStorage.getItem('rasp_token') || '', user: '', route: location.hash.slice(1) || '/overview' });
  window.addEventListener('hashchange', () => { state.route = location.hash.slice(1) || '/overview'; });

  async function api(method, path, body) {
    const res = await fetch('/api/v1' + path, {
      method,
      headers: Object.assign({ 'Content-Type': 'application/json' }, state.token ? { Authorization: 'Bearer ' + state.token } : {}),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = null;
    try { data = await res.json(); } catch (e) { /* empty body */ }
    if (res.status === 401 && path !== '/login') {
      state.token = '';
      localStorage.removeItem('rasp_token');
    }
    if (!res.ok) throw new Error((data && data.message) || ('HTTP ' + res.status));
    return data ? data.data : null;
  }

  const fmtTime = (ms) => ms ? new Date(ms).toLocaleString('zh-CN', { hour12: false }) : '-';
  const ago = (ms) => {
    if (!ms) return '-';
    const s = Math.floor((Date.now() - ms) / 1000);
    if (s < 60) return s + ' 秒前';
    if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
    if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
    return Math.floor(s / 86400) + ' 天前';
  };
  const helpers = { fmtTime, ago, TYPES, TYPE_NAMES, STATUS_NAMES, typeName: (t) => TYPE_NAMES[t] || t };

  // ------------------------------------------------------------------ components

  const Bars = {
    props: ['items', 'names'],
    computed: { max() { return Math.max(1, ...(this.items || []).map((i) => i.count)); } },
    template: `<div class="bars">
      <div v-if="!items || !items.length" class="muted">暂无数据</div>
      <div class="bar" v-for="i in items" :key="i.key">
        <div class="label" :title="i.key">{{ (names && names[i.key]) || i.key || '(空)' }}</div>
        <div class="track"><div class="fill" :style="{ width: (i.count / max * 100) + '%' }"></div></div>
        <div class="n">{{ i.count }}</div>
      </div></div>`,
  };

  const Login = {
    setup() {
      const form = reactive({ username: 'admin', password: '' });
      const err = ref('');
      async function submit() {
        err.value = '';
        try {
          const r = await api('POST', '/login', form);
          state.token = r.token; state.user = r.user;
          localStorage.setItem('rasp_token', r.token);
        } catch (e) { err.value = e.message; }
      }
      return { form, err, submit };
    },
    template: `<div class="login card">
      <h2 style="margin-top:0">ZhuWei-RASP 控制台</h2>
      <form class="form" @submit.prevent="submit">
        <label><span>用户名</span><input v-model="form.username" autocomplete="username"></label>
        <label><span>密码</span><input v-model="form.password" type="password" autocomplete="current-password"></label>
        <div class="error" v-if="err">{{ err }}</div>
        <button class="btn primary" type="submit">登录</button>
      </form>
      <p class="muted">初始密码由服务端启动日志输出，或通过环境变量 RASP_ADMIN_PASSWORD 设置。</p></div>`,
  };

  const Overview = {
    components: { Bars },
    setup() {
      const s = ref(null); const err = ref(''); const days = ref(7);
      async function load() { try { s.value = await api('GET', '/stats?days=' + days.value); } catch (e) { err.value = e.message; } }
      onMounted(load); watch(days, load);
      const total = computed(() => s.value ? (s.value.by_action || []).reduce((a, b) => a + b.count, 0) : 0);
      const blocked = computed(() => { const b = s.value && (s.value.by_action || []).find((i) => i.key === 'block'); return b ? b.count : 0; });
      return Object.assign({ s, err, days, total, blocked, actionNames: { block: '阻断', log: '告警' } }, helpers);
    },
    template: `<div>
      <div class="topbar"><h1>安全总览</h1>
        <select v-model.number="days"><option :value="1">近 1 天</option><option :value="7">近 7 天</option><option :value="30">近 30 天</option></select></div>
      <div class="error" v-if="err">{{ err }}</div>
      <div v-if="s && s.kill_switch" class="banner">全局紧急开关已开启：所有 Agent 已停止检测。可在“系统设置”中关闭。</div>
      <div class="grid" v-if="s">
        <div class="stat"><div class="v">{{ total }}</div><div class="k">告警总数</div></div>
        <div class="stat"><div class="v" style="color:var(--danger)">{{ blocked }}</div><div class="k">阻断次数</div></div>
        <div class="stat"><div class="v">{{ s.apps_total }}</div><div class="k">接入应用</div></div>
        <div class="stat"><div class="v">{{ s.instances_online }} / {{ s.instances_total }}</div><div class="k">在线实例 / 全部实例</div></div>
        <div class="stat"><div class="v" :style="{color: s.instances_breaker ? 'var(--warn)' : ''}">{{ s.instances_breaker }}</div><div class="k">熔断中的实例</div></div>
      </div>
      <div class="two" v-if="s">
        <div class="card"><h3>按检测类型</h3><Bars :items="s.by_attack_type" :names="TYPE_NAMES"/></div>
        <div class="card"><h3>每日趋势</h3><Bars :items="s.by_day"/></div>
        <div class="card"><h3>Top 应用</h3><Bars :items="s.by_app"/></div>
        <div class="card"><h3>Top 来源 IP</h3><Bars :items="s.by_client_ip"/></div>
      </div></div>`,
  };

  const Apps = {
    setup() {
      const apps = ref([]); const err = ref(''); const form = reactive({ name: '', env: 'prod', owner: '', description: '' });
      const created = ref(null);
      async function load() { try { apps.value = await api('GET', '/apps') || []; } catch (e) { err.value = e.message; } }
      async function create() {
        err.value = '';
        try { created.value = await api('POST', '/apps', form); form.name = ''; load(); } catch (e) { err.value = e.message; }
      }
      onMounted(load);
      return Object.assign({ apps, err, form, create, created }, helpers);
    },
    template: `<div>
      <div class="topbar"><h1>应用管理</h1></div>
      <div class="card"><h3>新建应用</h3>
        <div class="row">
          <input v-model="form.name" placeholder="应用名，如 order-service">
          <select v-model="form.env"><option>prod</option><option>staging</option><option>test</option><option>dev</option></select>
          <input v-model="form.owner" placeholder="负责人">
          <input v-model="form.description" placeholder="描述" style="flex:1">
          <button class="btn primary" @click="create" :disabled="!form.name">创建</button>
        </div>
        <div class="error" v-if="err">{{ err }}</div>
        <div v-if="created" class="notice">应用已创建。把下面的内容写入 Agent 的 <code>conf/rasp.properties</code>（AppSecret 只在应用详情中可见，请妥善保管）：
          <pre>{{ created.properties }}</pre></div>
      </div>
      <div class="card"><table>
        <tr><th>ID</th><th>应用</th><th>环境</th><th>负责人</th><th>实例（在线/全部）</th><th>策略版本</th><th>创建时间</th><th></th></tr>
        <tr v-for="a in apps" :key="a.id">
          <td>{{ a.id }}</td><td><a :href="'#/apps/' + a.id">{{ a.name }}</a></td><td>{{ a.env }}</td><td>{{ a.owner || '-' }}</td>
          <td>{{ a.online }} / {{ a.total }}</td><td>r{{ a.policy_rev }}</td><td>{{ fmtTime(a.created_at) }}</td>
          <td><a :href="'#/apps/' + a.id">配置</a></td></tr>
        <tr v-if="!apps.length"><td colspan="8" class="muted">还没有应用，先在上方创建一个。</td></tr>
      </table></div></div>`,
  };

  const AppDetail = {
    props: ['id'],
    setup(props) {
      const info = ref(null); const policy = ref(null); const rulesText = ref(''); const err = ref(''); const msg = ref('');
      const wl = ref([]); const wlForm = reactive({ url: '', match: 'prefix', types: 'all', note: '' });
      const showSecret = ref(false);
      async function load() {
        try {
          info.value = await api('GET', '/apps/' + props.id);
          const p = await api('GET', '/apps/' + props.id + '/policy');
          const pol = p.policy;
          pol.checks = pol.checks || {};
          TYPES.forEach((t) => { pol.checks[t] = Object.assign({ enabled: true, action: 'block' }, pol.checks[t] || {}); });
          pol.block_response = pol.block_response || { status: 403 };
          if (pol.body_max_bytes === undefined) pol.body_max_bytes = 65536;
          if (pol.async_context === undefined) pol.async_context = true;
          policy.value = pol;
          rulesText.value = JSON.stringify(pol.rules || [], null, 2);
          wl.value = (await api('GET', '/whitelists?app_id=' + props.id) || []);
        } catch (e) { err.value = e.message; }
      }
      async function save() {
        err.value = ''; msg.value = '';
        let rules;
        try { rules = JSON.parse(rulesText.value); } catch (e) { err.value = '规则不是合法的 JSON：' + e.message; return; }
        if (policy.value.mode === 'block' && !confirm('确认将该应用切换到阻断模式？命中阻断规则的请求将被拦截。')) return;
        const body = Object.assign({}, policy.value, { rules });
        try { await api('PUT', '/apps/' + props.id + '/policy', body); msg.value = '已保存，Agent 将在下一次心跳（约 30 秒内）生效。'; load(); }
        catch (e) { err.value = e.message; }
      }
      async function resetDefault() {
        if (!confirm('用内置默认策略覆盖当前编辑内容？（需点击保存才会生效）')) return;
        const d = await api('GET', '/policy/default');
        rulesText.value = JSON.stringify(d.rules || [], null, 2);
      }
      async function addWl() {
        err.value = '';
        try { await api('POST', '/whitelists', Object.assign({ app_id: Number(props.id) }, wlForm)); wlForm.url = ''; load(); } catch (e) { err.value = e.message; }
      }
      async function delWl(w) { if (confirm('删除白名单 ' + w.url + '？')) { await api('DELETE', '/whitelists/' + w.id); load(); } }
      async function delApp() {
        if (!confirm('删除应用 ' + info.value.app.name + '？其实例和白名单会一并删除，已上报的告警保留。')) return;
        await api('DELETE', '/apps/' + props.id); location.hash = '#/apps';
      }
      onMounted(load);
      return Object.assign({ info, policy, rulesText, err, msg, save, resetDefault, wl, wlForm, addWl, delWl, delApp, showSecret }, helpers);
    },
    template: `<div v-if="info">
      <div class="topbar"><h1>{{ info.app.name }} <span class="muted" style="font-size:14px">{{ info.app.env }}</span></h1>
        <button class="btn danger" @click="delApp">删除应用</button></div>
      <div class="error" v-if="err">{{ err }}</div>
      <div class="notice" v-if="msg">{{ msg }}</div>
      <div class="card"><h3>接入方式</h3>
        <p class="muted">1. 将 dist/rasp 目录复制到主机 /opt/rasp；2. 写入以下配置到 /opt/rasp/conf/rasp.properties；3. 在 Java 启动参数中加入 -javaagent。</p>
        <pre v-if="showSecret">{{ info.properties }}</pre>
        <button v-else class="btn sm" @click="showSecret = true">显示 AppKey / AppSecret</button>
        <pre>{{ info.command }}</pre></div>
      <div class="card" v-if="policy"><h3>防护策略</h3>
        <div class="form">
          <label><span>防护模式</span>
            <select v-model="policy.mode"><option value="off">关闭</option><option value="monitor">观察（只告警）</option><option value="block">阻断</option></select>
          </label>
          <label><span>读取表单参数</span><input type="checkbox" v-model="policy.read_form_params">
            <span class="muted" style="width:auto">开启后会读取 POST 表单参数，可能影响自行读取请求体的应用</span></label>
          <label><span>请求体采集</span><input type="number" v-model.number="policy.body_max_bytes" min="0" max="1048576" style="width:120px">
            <span class="muted" style="width:auto">字节/请求，0 表示关闭；只复制业务自己读取的请求体，解析 JSON 与表单参数</span></label>
          <label><span>线程池上下文</span><input type="checkbox" v-model="policy.async_context">
            <span class="muted" style="width:auto">把请求信息带入 ThreadPoolExecutor 任务，异步执行的危险操作也能关联到请求</span></label>
          <label><span>阻断状态码</span><input type="number" v-model.number="policy.block_response.status" style="width:100px"></label>
        </div>
        <table><tr><th>检测类型</th><th>启用</th><th>最高动作</th></tr>
          <tr v-for="t in TYPES" :key="t"><td>{{ typeName(t) }} <code class="muted">{{ t }}</code></td>
            <td><input type="checkbox" v-model="policy.checks[t].enabled"></td>
            <td><select v-model="policy.checks[t].action"><option value="block">阻断</option><option value="log">仅告警</option></select></td></tr>
        </table>
        <h3 style="margin-top:16px">检测规则（JSON）</h3>
        <p class="muted">每条规则的 conditions 需全部满足才命中。op 可选：eq、ne、contains、not_contains、prefix、suffix、regex、in、not_in、exists、contains_user_input。字段为 Hook 参数名，或 $in_request / $url / $method。</p>
        <textarea class="code" rows="18" v-model="rulesText"></textarea>
        <div class="row" style="margin-top:10px"><button class="btn primary" @click="save">保存策略</button><button class="btn" @click="resetDefault">载入默认规则</button></div>
      </div>
      <div class="card"><h3>白名单</h3>
        <div class="row">
          <input v-model="wlForm.url" placeholder="URL 路径，如 /api/report" style="flex:1">
          <select v-model="wlForm.match"><option value="exact">精确</option><option value="prefix">前缀</option><option value="regex">正则</option></select>
          <select v-model="wlForm.types"><option value="all">全部类型</option><option v-for="t in TYPES" :value="t">{{ typeName(t) }}</option></select>
          <input v-model="wlForm.note" placeholder="备注">
          <button class="btn" @click="addWl" :disabled="!wlForm.url">添加</button></div>
        <table><tr><th>URL</th><th>匹配</th><th>类型</th><th>范围</th><th>备注</th><th>创建</th><th></th></tr>
          <tr v-for="w in wl" :key="w.id"><td><code>{{ w.url }}</code></td><td>{{ w.match }}</td><td>{{ w.types }}</td>
            <td>{{ w.app_id ? '本应用' : '全局' }}</td><td>{{ w.note }}</td><td>{{ w.created_by }} {{ fmtTime(w.created_at) }}</td>
            <td><a @click="delWl(w)">删除</a></td></tr>
          <tr v-if="!wl.length"><td colspan="7" class="muted">无</td></tr></table></div>
    </div>`,
  };

  const Instances = {
    setup() {
      const list = ref([]); const err = ref('');
      async function load() { try { list.value = await api('GET', '/instances') || []; } catch (e) { err.value = e.message; } }
      const metric = (i, k) => { try { return JSON.parse(i.metrics)[k]; } catch (e) { return undefined; } };
      onMounted(load);
      return Object.assign({ list, err, load, metric }, helpers);
    },
    template: `<div>
      <div class="topbar"><h1>实例管理</h1><button class="btn" @click="load">刷新</button></div>
      <div class="error" v-if="err">{{ err }}</div>
      <div class="card"><table>
        <tr><th>状态</th><th>应用</th><th>主机</th><th>PID</th><th>Agent</th><th>运行时</th><th>配置版本</th><th>平均检测耗时</th><th>熔断</th><th>最后心跳</th></tr>
        <tr v-for="i in list" :key="i.agent_id">
          <td><span class="tag" :class="i.online ? 'on' : 'off'">{{ i.online ? '在线' : '离线' }}</span></td>
          <td>{{ i.app_name }}</td><td :title="i.ips">{{ i.hostname }}</td><td>{{ i.pid }}</td>
          <td>{{ i.agent_version }} <span class="muted">{{ i.start_mode }}</span></td><td>{{ i.runtime }}</td>
          <td><code>{{ i.config_version || '-' }}</code></td>
          <td class="num">{{ metric(i, 'check_avg_us') ?? '-' }} μs</td>
          <td><span class="tag" :class="metric(i, 'breaker_state') === 'closed' ? 'on' : 'log'">{{ metric(i, 'breaker_state') || '-' }}</span></td>
          <td>{{ ago(i.last_heartbeat) }}</td></tr>
        <tr v-if="!list.length"><td colspan="10" class="muted">暂无实例。Agent 配置好 server.url 后启动应用即会自动注册。</td></tr>
      </table></div></div>`,
  };

  const Alarms = {
    setup() {
      const q = reactive({ type: '', action: '', status: '', q: '', app_id: '', page: 1, page_size: 20 });
      const data = ref({ items: [], total: 0 }); const apps = ref([]); const err = ref(''); const detail = ref(null);
      async function load() {
        const params = new URLSearchParams(Object.entries(q).filter(([, v]) => v !== '' && v !== null));
        try { data.value = await api('GET', '/alarms?' + params); } catch (e) { err.value = e.message; }
      }
      async function open(a) {
        const d = await api('GET', '/alarms/' + encodeURIComponent(a.event_id));
        try { d.rawObj = JSON.parse(d.raw); } catch (e) { d.rawObj = {}; }
        detail.value = d;
      }
      async function setStatus(s) { await api('POST', '/alarms/' + encodeURIComponent(detail.value.event_id) + '/status', { status: s }); detail.value.status = s; load(); }
      async function whitelist() {
        if (!confirm('为该 URL 的 ' + detail.value.attack_type + ' 检测添加精确匹配白名单，并将告警标记为误报？')) return;
        try { await api('POST', '/alarms/' + encodeURIComponent(detail.value.event_id) + '/whitelist'); detail.value.status = 'false_positive'; load(); }
        catch (e) { alert(e.message); }
      }
      const pages = computed(() => Math.max(1, Math.ceil(data.value.total / q.page_size)));
      function search() { q.page = 1; load(); }
      onMounted(async () => { apps.value = await api('GET', '/apps') || []; load(); });
      return Object.assign({ q, data, apps, err, detail, open, setStatus, whitelist, pages, search, load }, helpers);
    },
    template: `<div>
      <div class="topbar"><h1>告警中心</h1></div>
      <div class="card">
        <div class="row">
          <select v-model="q.app_id"><option value="">全部应用</option><option v-for="a in apps" :value="a.id">{{ a.name }} ({{ a.env }})</option></select>
          <select v-model="q.type"><option value="">全部类型</option><option v-for="t in TYPES" :value="t">{{ typeName(t) }}</option></select>
          <select v-model="q.action"><option value="">全部动作</option><option value="block">阻断</option><option value="log">告警</option></select>
          <select v-model="q.status"><option value="">全部状态</option><option v-for="(n, k) in STATUS_NAMES" :value="k">{{ n }}</option></select>
          <input v-model="q.q" placeholder="URL / IP / 主机 / 命中输入" @keyup.enter="search" style="flex:1;min-width:160px">
          <button class="btn primary" @click="search">查询</button></div>
        <div class="error" v-if="err">{{ err }}</div>
        <table>
          <tr><th>时间</th><th>应用</th><th>类型</th><th>动作</th><th>URL</th><th>来源 IP</th><th>规则</th><th>状态</th></tr>
          <tr class="click" v-for="a in data.items" :key="a.event_id" @click="open(a)">
            <td>{{ fmtTime(a.event_time) }}</td><td>{{ a.app_name }}</td><td>{{ typeName(a.attack_type) }}</td>
            <td><span class="tag" :class="a.action">{{ a.action === 'block' ? '阻断' : '告警' }}</span></td>
            <td class="trunc" :title="a.url">{{ a.url || '(非 HTTP 请求)' }}</td><td>{{ a.client_ip }}</td>
            <td><code>{{ a.algorithm }}</code></td><td>{{ STATUS_NAMES[a.status] || a.status }}</td></tr>
          <tr v-if="!data.items || !data.items.length"><td colspan="8" class="muted">没有符合条件的告警</td></tr>
        </table>
        <div class="pager"><span class="muted">共 {{ data.total }} 条</span>
          <button class="btn sm" :disabled="q.page <= 1" @click="q.page--; load()">上一页</button>
          <span>{{ q.page }} / {{ pages }}</span>
          <button class="btn sm" :disabled="q.page >= pages" @click="q.page++; load()">下一页</button></div>
      </div>
      <div class="modal-mask" v-if="detail" @click.self="detail = null"><div class="drawer">
        <div class="topbar"><h1>告警详情</h1><button class="btn" @click="detail = null">关闭</button></div>
        <div class="kv">
          <div>时间</div><div>{{ fmtTime(detail.event_time) }}</div>
          <div>应用 / 主机</div><div>{{ detail.app_name }} / {{ detail.hostname }}</div>
          <div>类型</div><div>{{ typeName(detail.attack_type) }}</div>
          <div>动作</div><div><span class="tag" :class="detail.action">{{ detail.action }}</span> 置信度 {{ detail.confidence }}</div>
          <div>命中规则</div><div><code>{{ detail.algorithm }}</code> — {{ detail.reason }}</div>
          <div>命中的输入</div><div><code>{{ detail.matched_input || '-' }}</code></div>
          <div>请求</div><div class="trunc" style="max-width:none;white-space:normal;word-break:break-all">{{ detail.url || '(非 HTTP 请求)' }}</div>
          <div>来源 IP</div><div>{{ detail.client_ip || '-' }}</div>
          <div>状态</div><div>{{ STATUS_NAMES[detail.status] }}</div>
        </div>
        <div class="row">
          <button class="btn" @click="setStatus('confirmed')">确认攻击</button>
          <button class="btn" @click="setStatus('fixed')">已修复</button>
          <button class="btn" @click="setStatus('ignored')">忽略</button>
          <button class="btn danger" @click="whitelist" :disabled="!detail.url">误报并加白</button></div>
        <h3>检测参数</h3><pre>{{ JSON.stringify(detail.rawObj.params, null, 2) }}</pre>
        <h3>请求信息</h3><pre>{{ JSON.stringify(detail.rawObj.request, null, 2) }}</pre>
        <h3>调用栈</h3><pre>{{ (detail.rawObj.stack || []).join('\\n') }}</pre>
      </div></div></div>`,
  };

  const Components = {
    setup() {
      const list = ref([]); const apps = ref([]); const err = ref(''); const q = reactive({ app_id: '', q: '' });
      const uses = ref(null); const usesOf = ref(null);
      async function load() {
        const params = new URLSearchParams(Object.entries(q).filter(([, v]) => v !== ''));
        try { list.value = await api('GET', '/components?' + params) || []; } catch (e) { err.value = e.message; }
      }
      async function showUses(c) {
        usesOf.value = c;
        const p = new URLSearchParams({ group: c.group, artifact: c.artifact, version: c.version });
        uses.value = await api('GET', '/components/uses?' + p) || [];
      }
      function exportCsv() {
        const esc = (v) => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
        const rows = [['group', 'artifact', 'version', 'instances', 'apps', 'sha1', 'source']]
          .concat(list.value.map((c) => [c.group, c.artifact, c.version, c.instances, c.apps, c.sha1, c.source]));
        const blob = new Blob(['﻿' + rows.map((r) => r.map(esc).join(',')).join('\n')], { type: 'text/csv;charset=utf-8' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'components.csv'; a.click();
        URL.revokeObjectURL(a.href);
      }
      const versions = computed(() => {
        const m = {};
        list.value.forEach((c) => { const k = c.group + ':' + c.artifact; (m[k] = m[k] || new Set()).add(c.version); });
        return m;
      });
      const multi = (c) => (versions.value[c.group + ':' + c.artifact] || new Set()).size > 1;
      onMounted(async () => { apps.value = await api('GET', '/apps') || []; load(); });
      return Object.assign({ list, apps, err, q, load, uses, usesOf, showUses, exportCsv, multi }, helpers);
    },
    template: `<div>
      <div class="topbar"><h1>组件资产</h1><button class="btn" @click="exportCsv" :disabled="!list.length">导出 CSV</button></div>
      <div class="card">
        <p class="muted" style="margin-top:0">Agent 在应用启动约 30 秒后扫描实际加载过类的 jar 包（含 Spring Boot 内嵌 jar 和 shade 合并包），每 10 分钟检查一次变化。
          同一组件存在多个版本时标记为“多版本”。漏洞匹配需接入漏洞库（尚未实现），可先导出清单交给安全团队比对。</p>
        <div class="row">
          <select v-model="q.app_id" @change="load"><option value="">全部应用</option><option v-for="a in apps" :value="a.id">{{ a.name }} ({{ a.env }})</option></select>
          <input v-model="q.q" placeholder="组件名 / groupId / 版本 / 文件名" @keyup.enter="load" style="flex:1;min-width:160px">
          <button class="btn primary" @click="load">查询</button><span class="muted">共 {{ list.length }} 个组件版本</span></div>
        <div class="error" v-if="err">{{ err }}</div>
        <table>
          <tr><th>组件</th><th>版本</th><th>groupId</th><th>实例数</th><th>应用</th><th>识别方式</th></tr>
          <tr class="click" v-for="c in list" :key="c.group + c.artifact + c.version" @click="showUses(c)">
            <td><b>{{ c.artifact }}</b></td>
            <td><code>{{ c.version || '?' }}</code> <span v-if="multi(c)" class="tag log">多版本</span></td>
            <td class="muted">{{ c.group || '-' }}</td><td class="num">{{ c.instances }}</td>
            <td class="trunc" :title="c.apps">{{ c.apps }}</td><td class="muted">{{ c.source }}</td></tr>
          <tr v-if="!list.length"><td colspan="6" class="muted">暂无数据。Agent 连接平台并运行约 30 秒后会自动上报。</td></tr>
        </table></div>
      <div class="modal-mask" v-if="uses" @click.self="uses = null"><div class="drawer">
        <div class="topbar"><h1>{{ usesOf.artifact }} <code style="font-size:14px">{{ usesOf.version }}</code></h1><button class="btn" @click="uses = null">关闭</button></div>
        <div class="kv"><div>groupId</div><div>{{ usesOf.group || '-' }}</div><div>SHA-1</div><div><code>{{ usesOf.sha1 || '-' }}</code></div></div>
        <table><tr><th>应用</th><th>主机</th><th>jar 路径</th></tr>
          <tr v-for="u in uses" :key="u.agent_id + u.path"><td>{{ u.app_name }} / {{ u.env }}</td><td>{{ u.hostname }}</td>
            <td style="word-break:break-all"><code>{{ u.path }}</code></td></tr></table>
      </div></div></div>`,
  };

  const Settings = {
    setup() {
      const s = ref(null); const audit = ref([]); const err = ref(''); const msg = ref('');
      async function load() {
        try { s.value = await api('GET', '/settings'); audit.value = await api('GET', '/audit?limit=100') || []; } catch (e) { err.value = e.message; }
      }
      async function save(patch) {
        err.value = ''; msg.value = '';
        try { await api('PUT', '/settings', patch); msg.value = '已保存'; load(); } catch (e) { err.value = e.message; }
      }
      function toggleKill() {
        const on = s.value.kill_switch !== 'true';
        if (!confirm(on ? '开启全局紧急开关？所有应用的 Agent 将在 30 秒内停止检测与阻断。' : '关闭全局紧急开关，恢复各应用的防护策略？')) return;
        save({ kill_switch: on ? 'true' : 'false' });
      }
      onMounted(load);
      return Object.assign({ s, audit, err, msg, save, toggleKill }, helpers);
    },
    template: `<div v-if="s">
      <div class="topbar"><h1>系统设置</h1></div>
      <div class="error" v-if="err">{{ err }}</div><div class="notice" v-if="msg">{{ msg }}</div>
      <div class="card"><h3>全局紧急开关</h3>
        <p>当前状态：<span class="tag" :class="s.kill_switch === 'true' ? 'block' : 'on'">{{ s.kill_switch === 'true' ? '已开启（全部停止检测）' : '未开启' }}</span></p>
        <button class="btn danger" :class="{ solid: s.kill_switch !== 'true' }" @click="toggleKill">{{ s.kill_switch === 'true' ? '关闭紧急开关' : '开启紧急开关' }}</button></div>
      <div class="card"><h3>告警通知</h3>
        <div class="form">
          <label><span>Webhook</span><input v-model="s.notify_webhook" placeholder="企业微信/钉钉机器人或 SIEM 接收地址" style="width:min(520px,100%)"></label>
          <label><span>通知级别</span><select v-model="s.notify_level"><option value="block">仅阻断</option><option value="all">全部告警</option></select></label>
          <label><span>告警保留天数</span><input type="number" v-model="s.alarm_retention_days" style="width:100px"></label>
          <button class="btn primary" @click="save({ notify_webhook: s.notify_webhook, notify_level: s.notify_level, alarm_retention_days: String(s.alarm_retention_days) })">保存</button>
        </div></div>
      <div class="card"><h3>操作审计</h3><table>
        <tr><th>时间</th><th>用户</th><th>操作</th><th>对象</th><th>详情</th></tr>
        <tr v-for="a in audit" :key="a.id"><td>{{ fmtTime(a.at) }}</td><td>{{ a.user }}</td><td>{{ a.action }}</td><td>{{ a.target }}</td><td>{{ a.detail }}</td></tr>
      </table></div></div>`,
  };

  // ------------------------------------------------------------------ shell

  const App = {
    components: { Login, Overview, Apps, AppDetail, Instances, Alarms, Components, Settings },
    setup() {
      const view = computed(() => {
        const r = state.route;
        if (r.startsWith('/apps/')) return { c: 'AppDetail', props: { id: r.split('/')[2] } };
        const map = { '/overview': 'Overview', '/apps': 'Apps', '/instances': 'Instances', '/alarms': 'Alarms',
          '/components': 'Components', '/settings': 'Settings' };
        return { c: map[r] || 'Overview', props: {} };
      });
      const nav = [['/overview', '安全总览'], ['/alarms', '告警中心'], ['/apps', '应用管理'], ['/instances', '实例管理'],
        ['/components', '组件资产'], ['/settings', '系统设置']];
      async function logout() { try { await api('POST', '/logout'); } catch (e) { /* ignore */ } state.token = ''; localStorage.removeItem('rasp_token'); }
      onMounted(async () => { if (state.token) { try { state.user = (await api('GET', '/me')).user; } catch (e) { /* handled */ } } });
      return { state, view, nav, logout };
    },
    template: `<Login v-if="!state.token"/>
      <div v-else class="layout">
        <aside class="side"><div class="brand">ZhuWei-RASP<small>运行时应用自我保护</small></div>
          <nav class="nav"><a v-for="n in nav" :key="n[0]" :href="'#' + n[0]" :class="{ active: state.route === n[0] || (n[0] === '/apps' && state.route.startsWith('/apps/')) }">{{ n[1] }}</a>
            <a @click="logout">退出 {{ state.user }}</a></nav></aside>
        <main class="main"><component :is="view.c" v-bind="view.props" :key="state.route"/></main>
      </div>`,
  };

  createApp(App).mount('#app');
})();
