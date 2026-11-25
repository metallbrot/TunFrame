"""Offline repros for TunFrame harness findings. No Docker calls are made."""
import sys, os, time, json, tempfile, threading, logging
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
import main  # module-level code only; main.main() is not called
from detection import evaluate as ev
from detection.detector_base.detector_base import Detector
from detection.detector_base.readfile import readjson
logging.getLogger('dns_detector').setLevel(logging.ERROR)  # silence harness output

FAILS = []
def check(label, ok, detail):
    """Print a PASS/FAIL line for a fixed finding and remember failures."""
    print(("PASS " if ok else "FAIL ") + label + ": " + detail)
    if not ok:
        FAILS.append(label)

def evt(qname, qr=False, qtype='A', ts='2026-11-24T10:00:00.000000000Z'):
    return {"dns": {"qname": qname, "qtype": qtype, "flags": {"qr": qr}, "qdcount": 1, "ancount": 0, "length": 50, "qclass": "IN"},
            "network": {"query-ip": "172.16.40.40"}, "dnstap": {"timestamp-rfc3339ns": ts}}

class Never(Detector):
    def detect(self, logline): pass
class FlagTunnel(Detector):
    def detect(self, logline):
        from detection.detector_base.feature_extraction import get_registered_domain
        if get_registered_domain(logline) == 'tunnel.com': self.alarms.add('tunnel.com')

fd = (ev.format_duration(64.435775), ev.format_duration(60.0), ev.format_duration(7200.0), ev.format_duration(0))
check("D1 format_duration", fd == ('1m4s', '1m', '2h', '0s'), "got %s" % (fd,))

d = Never(); d.alarms = set()
r = d.evaluate({'tunnel.com'}, {'tunnel.com', 'a.com', 'b.com'}, 10, 2, set())
check("M1 TN excludes FN", (r['tp'], r['fp'], r['tn'], r['fn']) == (0, 0, 2, 1),
      "tp=%d fp=%d tn=%d fn=%d for 3 domains (1 tunnel missed)" % (r['tp'], r['fp'], r['tn'], r['fn']))

d = Never()
d.process_line(evt('abcdefghij.tunnel.com'), True)          # single data label
one = d.lv_up
d.process_line(evt('seq.abcdefghij.tunnel.com'), True)      # two labels
check("M3 uplink counts full payload", (one, d.lv_up - one) == (10, 13),
      "single-label query adds %d bytes (expected 10); two-label query adds %d bytes (expected 13)" % (one, d.lv_up - one))

def gen(events):
    for e in events: yield e
def resp(qname, answers):
    e = evt(qname, qr=True)
    e["dns"]["resource-records"] = {"an": answers}
    return e
d = Never()
d.process_line(resp('abc.tunnel.com', [{"rdatatype": "A", "rdata": "1.2.3.4"}, {"rdatatype": "AAAA", "rdata": "::1"}]), True)
a = d.lv_down
d.process_line(resp('abc.tunnel.com', []), True)
d.process_line(resp('abc.tunnel.com', [{"rdatatype": "TXT", "rdata": "hello"}]), True)
check("M4 downlink from answer records", (a, d.lv_down - a) == (20, 5),
      "A+AAAA answer=%d bytes (expected 20); empty + TXT 'hello'=%d bytes (expected 5)" % (a, d.lv_down - a))

d = Never()
lines = [evt('aa.tunnel.com'), resp('aa.tunnel.com', [{"rdatatype": "A", "rdata": "1.2.3.4"}]),
         evt('bb.tunnel.com'), resp('bb.tunnel.com', []), evt('x.org')]
ev.wartime_stop_event.clear()
out = ev.run_wartime([d], gen(lines), {'tunnel.com'}, set())
c, r5 = out[5], out[0][0]
check("M5 tunnel counts are queries", (c['tunnel_queries'], c['tunnel_responses'], r5['tunneling_missed'], r5['tunneling_missed_responses']) == (2, 2, 2, 2),
      "tunnel_queries=%d tunnel_responses=%d missed=%d missed_responses=%d (expected 2 each)" % (
      c['tunnel_queries'], c['tunnel_responses'], r5['tunneling_missed'], r5['tunneling_missed_responses']))

d = Never(); d.allowlist = {'allowed.com'}
for q in ['a.allowed.com', 'b.allowed.com', 'c.allowed.com', 'x.other.org']:
    d.process_line(evt(q), False)
r6 = d.evaluate(set(), {'allowed.com', 'other.org'}, 4, 0, set())
check("M6 avg time over detect() calls", d.detect_calls == 1 and abs(r6['avg_process_time_ms'] - d.total_process_time * 1000) < 1e-9,
      "detect_calls=%d of %d lines (expected 1)" % (d.detect_calls, d.processed_lines))

d = Never(); d.allowlist = {'tunnel.com'}
d.process_line(evt('abcdef.tunnel.com'), True)
d.process_line(resp('abcdef.tunnel.com', [{"rdatatype": "A", "rdata": "1.2.3.4"}]), True)
r11 = d.evaluate({'tunnel.com'}, {'tunnel.com'}, 2, 1, set(), tunneling_responses=1)
check("M11 allowlisted tunnel traffic accounted", (r11['allowlisted_tunnel_queries'], r11['allowlisted_tunnel_responses'],
      r11['allowlisted_tunnel_up_bytes'], r11['allowlisted_tunnel_down_bytes'], r11['tunneling_missed'], d.detect_calls) == (1, 1, 6, 4, 0, 0),
      "allowlisted q=%d r=%d up=%d down=%d; missed=%d detect_calls=%d (expected 1,1,6,4,0,0)" % (
      r11['allowlisted_tunnel_queries'], r11['allowlisted_tunnel_responses'], r11['allowlisted_tunnel_up_bytes'],
      r11['allowlisted_tunnel_down_bytes'], r11['tunneling_missed'], d.detect_calls))

d = Never()
d.process_line(evt('abcdefghijklmnop.tunnel.com'), True)    # 16 payload bytes
r_c1 = d.evaluate({'tunnel.com'}, {'tunnel.com'}, 1, 1, set(), expansion_factor=main.config_expansion_factor({'encoding': 'base32map'}))
check("C1 per-config expansion factor", abs(r_c1['estimated_real_traffic_up_bytes'] - 16 / 4.8) < 1e-9 and r_c1['expansion_factor'] == 4.8,
      "base32map: 16 B ULV -> %.3f B real (expected 3.333)" % r_c1['estimated_real_traffic_up_bytes'])

c2cfg = {'dnsexfiltrator': {'enabled': True,
          'baseline': {'throttle': 0, 'label_max_size': 50, 'domains': ['tunnel.com']},
          'sweeps': [{'name': 's', 'parameter': 'throttle', 'values': [5]}],
          'profiles': [{'name': 'p', 'encoding': 'base64'}]}}
cs = {c['name']: c for c in main.get_dnsexfiltrator_configs(c2cfg)}
p = cs['p']
ok_inherit = p['domains'] == ['tunnel.com'] and p['throttle'] == 0 and p['label_max_size'] == 50 and p['encoding'] == 'base64'
try:
    main.get_dnsexfiltrator_configs({'dnsexfiltrator': {'enabled': True, 'baseline': {'domains': ['t.com']},
                                     'sweeps': [{'name': 'x', 'parameter': 'throtle', 'values': [1]}]}})
    ok_validate = False
except ValueError:
    ok_validate = True
check("C2 profiles inherit baseline; params validated", ok_inherit and ok_validate,
      "profile p=%s; typo rejected=%s" % ({k: p[k] for k in ('domains', 'throttle', 'label_max_size', 'encoding')}, ok_validate))

# S1: domain_count sweeps take the first N domains of the sweep's pool (default: tunneling_domains).
_ds = {'traffic': {'tunnel': {'tunneling_domains': ['a.com', 'b.net', 'c.org']}},
       'dnsexfiltrator': {'enabled': True, 'baseline': {'domains': ['a.com']},
                          'sweeps': [{'name': 'dom', 'parameter': 'domain_count', 'values': [1, 3]},
                                     {'name': 'pool', 'parameter': 'domain_count', 'values': [2], 'domains': ['c.org', 'b.net', 'a.com']}]}}
_dc = {c['name']: c for c in main.get_dnsexfiltrator_configs(_ds)}
try:
    main.get_dnsexfiltrator_configs(dict(_ds, dnsexfiltrator=dict(_ds['dnsexfiltrator'], sweeps=[{'name': 'x', 'parameter': 'domain_count', 'values': [4]}])))
    _dc_bad = False
except ValueError:
    _dc_bad = True
check("S1 domain_count sweep uses the first N domains of its pool",
      _dc['dom_domain_count_1']['domains'] == ['a.com'] and _dc['dom_domain_count_3']['domains'] == ['a.com', 'b.net', 'c.org']
      and _dc['pool_domain_count_2']['domains'] == ['c.org', 'b.net'] and _dc['dom_domain_count_3']['_value'] == 3 and _dc_bad,
      "dom_1=%s dom_3=%s pool_2=%s; count above the pool rejected=%s"
      % (_dc['dom_domain_count_1']['domains'], _dc['dom_domain_count_3']['domains'], _dc['pool_domain_count_2']['domains'], _dc_bad))

# G1: every configuration is tagged with its dashboard group (Baseline / sweep name / Profiles).
_grp = {n: (c.get('_group'), c.get('_kind')) for n, c in cs.items()}
check("G1 configs tagged with their group for the dashboard",
      _grp.get('baseline') == ('Baseline', 'baseline') and _grp.get('s_throttle_5') == ('s', 'sweep')
      and _grp.get('p') == ('Profiles', 'profile'),
      "groups=%s" % _grp)

# B4: the client runs under a PTY (script) so mono line-buffers and keeps colour; the server does not.
_calls = []
class _FakeRun:
    returncode = 0; stdout = ''; stderr = ''
_orig_run = main.subprocess.run
main.subprocess.run = lambda cmd, **kw: (_calls.append(cmd), _FakeRun())[1]
try:
    main.docker_exec_bg_logged('dnsexfiltrator-client', '/data/logs/client.log', 'mono', '/app/x.exe', 'a b', pty=True)
    main.docker_exec_bg_logged('dnsexfiltrator-server', '/app/logs/server.log', 'python3', '-u', 'x.py')
finally:
    main.subprocess.run = _orig_run
_pty, _plain = _calls[0], _calls[1]
_ok_pty = ('-e' in _pty and 'TERM=xterm' in _pty and any(a.startswith('TUNFRAME_CMD=') for a in _pty)
           and 'script -qec "$TUNFRAME_CMD" /dev/null' in _pty[-1] and 'tee -a /data/logs/client.log' in _pty[-1])
_ok_plain = ('TERM=xterm' not in _plain and 'script' not in _plain[-1]
             and 'python3 -u x.py 2>&1 | tee -a /app/logs/server.log' in _plain[-1])
check("B4 client runs under a PTY wrapper, server runs directly", _ok_pty and _ok_plain,
      "pty ok=%s, plain ok=%s" % (_ok_pty, _ok_plain))

import tempfile as _tf, pathlib as _pl
_old_dir = main.RESULTS_DIR
main.RESULTS_DIR = _pl.Path(_tf.mkdtemp())
f3 = main.save_status_result({'global': {'name': 'T'}}, 'cfgX', 'skipped', 'client failed')
d3 = json.load(open(f3))
main.close_run_report(); main.REPORT = None
main.RESULTS_DIR = _old_dir
ri = d3['metadata']['run_info']
check("C4 results are self-contained", len(ri['git_commit']) == 40 and ri['libraries']['tldextract'] != '' and 'dnsexfiltrator_config' in d3['metadata'],
      "git %s dirty=%s, tldextract %s, docker '%s'" % (ri['git_commit'][:8], ri['git_dirty'], ri['libraries']['tldextract'], ri['docker_version']))
check("C3 skipped configs leave a results file", d3['metadata']['run_status'] == {'status': 'skipped', 'reason': 'client failed'} and d3['detectors'] == [],
      "written %s with status %s" % (f3.name, d3['metadata']['run_status']['status']))

try:
    main.validate_dnsexfil_domains([{'name': 'a', 'domains': ['tunnel.com', 'other.net']}], ['tunnel.com'])
    c5 = False
except ValueError:
    c5 = True
main.validate_dnsexfil_domains([{'name': 'b', 'domains': ['Tunnel.com']}], ['tunnel.com'])   # must pass
check("C5 unrouted exfil domains rejected", c5, "other.net outside tunneling_domains raised ValueError=%s" % c5)

dets = [FlagTunnel()]
cfg1 = [evt('x%d.tunnel.com' % i) for i in range(5)] + [evt('a.com')]
ev.wartime_stop_event.clear()
res1 = ev.run_wartime(dets, gen(cfg1), {'tunnel.com'}, set())
cfg2 = [evt('benign%d.org' % i) for i in range(3)] + [evt('y%d.tunnel.com' % i) for i in range(5)]
for x in dets:
    x.reset()                # what main.py now does at every config boundary
ev.wartime_stop_event.clear()
res2 = ev.run_wartime(dets, gen(cfg2), {'tunnel.com'}, set())
check("M7 no carry-over between configs", (res2[1], res2[0][0]['processed_lines'], res2[0][0]['tp'], res2[0][0]['fp']) == (4, 4, 1, 0),
      "config2 logcount=%d processed_lines=%d tp=%d fp=%d (expected 4, 4, 1, 0)" % (
      res2[1], res2[0][0]['processed_lines'], res2[0][0]['tp'], res2[0][0]['fp']))
main_src = open(os.path.join(ROOT, "main.py")).read()
check("M7 main resets detectors per config", "detector.reset()" in main_src, "reset() call present in main.py")

ev.peacetime_done.clear()
ev.peacetime_stop_event.clear()
ev.run_peacetime([Never()], gen([evt('p.net')]), {'tunnel.com'})
check("M13 run_peacetime sets peacetime_done", ev.peacetime_done.is_set() and not hasattr(ev, 'evaluate'),
      "peacetime_done set=%s, legacy evaluate() present=%s" % (ev.peacetime_done.is_set(), hasattr(ev, 'evaluate')))

det = [Never()]
peace = [evt('peace%d.net' % i) for i in range(20)]
ev.peacetime_stop_event.clear()
plc, pdomains = ev.run_peacetime(det, gen(peace), {'tunnel.com'})
ev.generate_allowlists(det, set())
det[0].alarms = {'war1.org'}  # pretend one false positive in wartime
war = [evt('war%d.org' % i) for i in range(4)]
ev.wartime_stop_event.clear()
res = ev.run_wartime(det, gen(war), {'tunnel.com'}, set())
check("M2 wartime universe excludes peacetime domains", len(res[4]) == 4 and abs(res[0][0]['fpr'] - 0.25) < 1e-9,
      "all_domains=%d (4 wartime domains), FPR=%.3f (expected 0.250)" % (len(res[4]), res[0][0]['fpr']))

with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
    for i in range(3000): f.write(json.dumps(evt('q%d.example.com' % i)) + "\n")
    path = f.name
g = readjson(path)
t0 = time.time(); n = 0
while n < 3000:
    if next(g) is not None: n += 1
rate = 3000 / max(time.time() - t0, 1e-9)
check("M9 reader reads bursts", rate > 1000, "readjson delivered %.0f lines/s (expected > 1000)" % rate)
os.unlink(path)

with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
    idle_path = f.name                                  # empty, idle log
ev.wartime_stop_event.clear()
t12 = main.PhaseTimer(ev.wartime_stop_event, 0.3).start()
t0 = time.time()
ev.run_wartime([Never()], readjson(idle_path), {'tunnel.com'}, set())
t12.cancel()
el = time.time() - t0
check("M12 idle phase ends on time", 0.25 <= el <= 0.6, "idle wartime of 0.3 s ended after %.2f s" % el)
os.unlink(idle_path)

from detection.detector_base.readfile import log_end_offset
with tempfile.NamedTemporaryFile('wb', suffix='.json', delete=False) as f:
    f.write((json.dumps(evt('old.example.com')) + "\n").encode())
    p14 = f.name
off = log_end_offset(p14)
g = readjson(p14, start_offset=off)
with open(p14, 'ab') as f:
    f.write(b"\x00" * 64 + (json.dumps(evt('nul.example.com')) + "\n").encode())   # NUL-padded line
    half = json.dumps(evt('split.example.com'))
    f.write(half[:20].encode())                                               # partial line
got = []
for _ in range(5):
    x = next(g)
    if x: got.append(x['dns']['qname'])
with open(p14, 'ab') as f:
    f.write((half[20:] + "\n").encode())                                      # rest of the line
for _ in range(5):
    x = next(g)
    if x: got.append(x['dns']['qname'])
g2 = readjson(p14, start_offset=5)                                           # offset inside line 1
first = next(x for x in g2 if x)['dns']['qname']
check("M14 offset reading, NUL strip, partial lines", got == ['nul.example.com', 'split.example.com'] and first == 'nul.example.com',
      "read %s; mid-line start resumes at %s" % (got, first))
os.unlink(p14)

e = threading.Event()
t1 = main.PhaseTimer(e, 0.3).start()      # config 1 timer
t1.cancel()                                # config 1 ended early
e.clear()
t0 = time.time(); t2 = main.PhaseTimer(e, 1.0).start()   # config 2 should run 1.0 s
e.wait(3)
el = time.time() - t0
check("M8 old timer cannot stop next phase", 0.9 <= el <= 1.5, "config 2 stop event fired after %.2f s (expected ~1.0 s)" % el)

calls = []
main.replay_fire_and_forget = lambda pcap, pps, label: calls.append(label)   # no docker
main._started_replays.clear()
main.start_replay("benign", "x.pcap", 10)      # peacetime
main.start_replay("benign", "x.pcap", 10)      # wartime must continue, not restart
time.sleep(0.2)
check("M10 benign replay started once", calls == ["benign"], "replay starts: %s (expected ['benign'])" % calls)
check("M10 peacetime replay only with peacetime", "    if peacetime_duration:\n        if benign_enabled:" in open(os.path.join(ROOT, "main.py")).read(),
      "peacetime phase starts replays only when peacetime_duration > 0")

src_w = open(os.path.join(ROOT, "main.py")).read()
war_part = src_w[src_w.index("def run_wartime_phase("):]
# Wartime now resumes benign/wildcard from the packet after peacetime stopped:
# it slices a wartime segment and starts a managed replay per window.
check("C6 wildcard replay in wartime",
      'prepare_wartime_segment("wildcard"' in war_part and 'managed_replay_start("wildcard"' in war_part,
      "run_wartime_phase slices a wildcard wartime segment and replays it per window")

_d7 = tempfile.mkdtemp()
with open(os.path.join(_d7, 'top.csv'), 'w') as f:
    f.write("1,Google.com\n2,example.org.\n# comment\n\n0.0.0.0 ads.example.net\nplain.de\n")
al = ev.load_global_allowlist('top.csv', base_dir=_d7)
check("C7 allowlist parsing and path", al == {'google.com', 'example.org', 'example.net', 'plain.de'}, "parsed %s" % sorted(al))

from detection.detector_base.feature_extraction import get_txt_content
from detection.detector_base.metrics import true_positive_rate, false_positive_rate
txt = get_txt_content(resp('a.tunnel.com', [{"rdatatype": "TXT", "rdata": "ND"}, {"rdatatype": "A", "rdata": "1.2.3.4"}]))
check("F1 TXT content uses collector schema", txt == ["ND"], "got %s (expected ['ND'])" % txt)
gt = main.ground_truth_domain('Tunnel.Example.com.')
check("F2 ground truth at registered-domain level", gt == 'example.com', "tunnel.example.com -> %s (expected example.com)" % gt)
check("F3 rates guard the denominator", (true_positive_rate(0, 0), false_positive_rate(0, 4), true_positive_rate(1, 1)) == (0, 0.0, 0.5),
      "tpr(0,0), fpr(0,4), tpr(1,1) = %s" % ((true_positive_rate(0, 0), false_positive_rate(0, 4), true_positive_rate(1, 1)),))
_war = src_w[src_w.index("def run_wartime_phase("):]
check("F4 background traffic starts before the client",
      _war.index("start_background_replays()\n\n            logger.info(f\"[+] Starting DNSExfiltrator client") < _war.index('"mono", "/app/DNSExfiltrator.exe"'),
      "benign/wildcard replays start before the one-shot client")

try:
    main.check_config_keys({'timing': {'duration': 60}})
    c8 = False
except ValueError:
    c8 = True
c8_dir = main.resolve_results_dir({'output': {'logdir': './results/'}}) == (main.CONFIG_PATH.parent / 'results').resolve()
check("C8 renamed keys rejected, output.logdir used", c8 and c8_dir, "timing.duration rejected=%s, logdir resolved=%s" % (c8, c8_dir))

import subprocess as _sp
_out = _sp.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); import detection.detectors.MarkAll.detector; print('main' in sys.modules)" % ROOT],
               capture_output=True, text=True).stdout.strip()
d4 = Never(); d4.allowlist = {'keep.com'}; d4.alarms = {'x.com'}; d4.lv_up = 5
d4.reset()
check("D4 single reset API", not hasattr(d4, 'full_reset') and not hasattr(d4, 'phase_reset') and d4.allowlist == {'keep.com'} and not d4.alarms and d4.lv_up == 0,
      "reset() keeps allowlist, clears alarms/leakage; old reset names removed")
check("D2 detectors do not import main", _out == "False", "'main' imported when loading a detector: %s" % _out)

noq = evt('x.org'); del noq['dns']['qname']
ev.peacetime_stop_event.clear()
try:
    pc, _ = ev.run_peacetime([Never()], gen([noq, evt('ok.net')]), {'tunnel.com'})
    d5 = pc == 1
except AttributeError:
    d5 = False
dl = FlagTunnel()
ev.wartime_stop_event.clear()
o6 = ev.run_wartime([dl], gen([evt('AbC.TuNnEl.CoM')]), {main.normalize_domain('Tunnel.COM.')}, set())
check("D6 case-insensitive ground truth and alarms", o6[0][0]['tp'] == 1 and o6[2] == 1, "mixed-case query vs mixed-case config: tp=%d tunnel_lines=%d" % (o6[0][0]['tp'], o6[2]))
loaded = ev.load_detectors(os.path.join(ROOT, "detection", "detectors"), ["MarkAll"])
try:
    ev.load_detectors(os.path.join(ROOT, "detection", "detectors"), ["NoSuchDetector"])
    d7 = False
except RuntimeError:
    d7 = True
check("D7 load_detectors returns Detector instances; missing requested detector fails", [type(x).__name__ for x in loaded] == ["MarkAll"] and isinstance(loaded[0], Detector) and d7,
      "loaded %s; missing requested detector raised=%s" % ([type(x).__name__ for x in loaded], d7))
def interrupting():
    yield evt('aa.tunnel.com'); yield evt('x.org')
    raise KeyboardInterrupt
ev.wartime_stop_event.clear()
o8 = ev.run_wartime([Never()], interrupting(), {'tunnel.com'}, set())
check("D8 interrupt yields partial evaluation", o8[5]['interrupted'] and o8[1] == 2 and o8[0][0]['fn'] == 1,
      "interrupted=%s, %d lines evaluated, fn=%d" % (o8[5]['interrupted'], o8[1], o8[0][0]['fn']))
msrc = open(os.path.join(ROOT, "main.py")).read()
check("D9 dead helpers removed", all(x not in msrc for x in ("def get_dnsexfiltrator_status", "def start_dnsexfiltrator_server", "def start_dnsexfiltrator_client", "port_ok")),
      "unused helpers and the always-true port_ok flag are gone")
check("D5 peacetime skips events without qname", d5, "event without qname skipped, valid event processed")

check("D3 broken aggregator module removed", not os.path.exists(os.path.join(ROOT, "detection", "detector_base", "aggregator.py")),
      "detection/detector_base/aggregator.py removed (it had no importers)")

# Early end of a wartime window once the exfiltrated file has arrived
with tempfile.NamedTemporaryFile('wb', suffix='.json', delete=False) as f:
    _lines = [(json.dumps(evt('t%d.tunnel.com' % i)) + "\n").encode() for i in range(3)]
    f.write(b"".join(_lines)); _tp = f.name
_r = readjson(_tp); _ends, _pos = [], 0
for _ln in _lines:
    _pos += len(_ln); next(_r); _ends.append(_r.offset == _pos)
check("T1 reader reports its log offset", all(_ends), "offset after each line matches the line end: %s" % _ends)

class Appender(Detector):
    """Appends lines to the log while the window drains, like ongoing benign traffic."""
    def detect(self, logline):
        if not getattr(self, 'done', False):
            self.done = True
            with open(_tp, 'ab') as fa:
                for i in range(10): fa.write((json.dumps(evt('late%d.org' % i)) + "\n").encode())
ev.wartime_stop_event.clear(); _te = threading.Event(); _te.set()
_t2 = main.PhaseTimer(ev.wartime_stop_event, 5).start(); _s = time.time()
_o2 = ev.run_wartime([Appender()], readjson(_tp), {'tunnel.com'}, set(), transfer_event=_te)
_t2.cancel(); _el2 = time.time() - _s
check("T2 transfer end drains the log up to that moment", _o2[1] == 3 and _o2[5]['stop_reason'] == 'transfer_complete' and _el2 < 1.0,
      "processed %d lines (expected 3, 10 appended later ignored), stop_reason=%s after %.2fs" % (_o2[1], _o2[5]['stop_reason'], _el2))
os.unlink(_tp)

# Net exfiltration volume decoded from the DNSExfiltrator query format (init / data / dilution).
from detection import exfil_payload as xp
import base64 as _b64
_b32 = _b64.b32encode(b"1|3030").decode().rstrip("=")
_init = "".join(xp.WORDS["ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".index(c)] for c in _b32)
_sizes = (xp.chunk_bytes("a" * 63, "base32"), xp.chunk_bytes("kit" * 21, "base32map"), xp.chunk_bytes("ab" * 31, "hex"))
check("X1 chunk sizes per encoding; init decoded also when split",
      _sizes == (39, 13, 31) and xp.decode_init(_init) == ("1", 3030) and xp.decode_init(_init[:9]) is None,
      "63 base32 chars=%d B, 21 base32map words=%d B, 62 hex chars=%d B; init %s" % (_sizes + (xp.decode_init(_init),)))

class AlarmAfter(Detector):
    """Raises an alarm on the tunnel domain at its n-th data query."""
    def __init__(self, n):
        super().__init__(); self.n, self.seen = n, 0
    def detect(self, logline):
        if logline['dns']['qname'].count('.') == 3:
            self.seen += 1
            if self.seen >= self.n: self.alarms.add('tunnel.com')
_c1, _c2, _c3 = "a" * 16, "b" * 16, "c" * 8          # base32: 10, 10, 5 bytes
_x = [evt(_init[:12] + '.tunnel.com'), evt(_init[12:] + '.tunnel.com'), evt('0.%s.tunnel.com' % _c1),
      evt('eee.tunnel.com'), evt('0.%s.tunnel.com' % _c1), evt('1.%s.tunnel.com' % _c2),
      evt('2.%s.tunnel.com' % _c3), evt('www.example.org')]
with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
    f.write("".join(json.dumps(e) + "\n" for e in _x)); _xpath = f.name
ev.wartime_stop_event.clear()
_xo = ev.run_wartime([Never(), AlarmAfter(3)], readjson(_xpath, max_idle_seconds=0.3),
                     {'tunnel.com'}, set(), payload=xp.DNSExfilPayload('base32'))
os.unlink(_xpath)
_xc, _xr = _xo[5], _xo[0]
main.add_leak_shares(_xr, dict(_xc))
check("X2 net volume: unique data chunks, per detector up to its alarm, ULV % of the announced file",
      (_xc['tunnel_init_queries'], _xc['tunnel_data_queries'], _xc['tunnel_dilution_queries'], _xc['tunnel_retried_queries']) == (2, 4, 1, 1)
      and _xc['tunnel_net_up_bytes'] == 25 and _xc['exfil_file_bytes'] == 3030
      and [r['net_up_bytes'] for r in _xr] == [25, 10] and _xr[0]['estimated_real_traffic_up_bytes'] == 25
      and _xr[0]['ulv_basis'] == 'file' and abs(_xr[0]['ulv_percent'] - 100 * 25 / 3030) < 1e-9
      and main.net_volume_check({'tunnel_net_up_bytes': 3030, 'exfil_file_bytes': 3030}, True) == 'match'
      and main.net_volume_check({'tunnel_net_up_bytes': 25, 'exfil_file_bytes': 3030}, False) == 'incomplete',
      "queries init/data/dilution/retried=%s net=%s file=%s per detector=%s"
      % ((_xc['tunnel_init_queries'], _xc['tunnel_data_queries'], _xc['tunnel_dilution_queries'], _xc['tunnel_retried_queries']),
         _xc['tunnel_net_up_bytes'], _xc['exfil_file_bytes'], [r['net_up_bytes'] for r in _xr]))

# ULV% / DLV%: leaked (plus allowlisted) tunnel payload over the window's whole tunnel payload.
_u = [{'traffic_volume_up_bytes': 25, 'allowlisted_tunnel_up_bytes': 5, 'traffic_volume_down_bytes': 0},
      {'traffic_volume_up_bytes': 500, 'traffic_volume_down_bytes': 10}]
main.add_leak_shares(_u, {'tunnel_up_bytes': 100, 'tunnel_down_bytes': 0})
check("U1 window counts tunnel payload; ULV%/DLV% relate leakage to it",
      _o2[5]['tunnel_up_bytes'] == 6 and _o2[5]['tunnel_down_bytes'] == 0
      and _u[0]['ulv_percent'] == 30.0 and _u[1]['ulv_percent'] == 100.0 and _u[0]['dlv_percent'] is None
      and 'ulv_percent' in __import__('detection.reporting', fromlist=['SUMMARY_KEYS']).SUMMARY_KEYS,
      "tunnel_up_bytes=%s (t0..t2: 6 B), ulv=%s, capped=%s, dlv without downlink=%s"
      % (_o2[5]['tunnel_up_bytes'], _u[0]['ulv_percent'], _u[1]['ulv_percent'], _u[0]['dlv_percent']))

with tempfile.NamedTemporaryFile('wb', suffix='.log', delete=False) as f:
    f.write(b"[+] File saved successfully\n"); _sl = f.name          # from an earlier configuration
_we = threading.Event()
_w = main.TransferWatcher(_sl, os.path.getsize(_sl), _we, settle_seconds=0.1, poll_interval=0.05).start()
time.sleep(0.3); _early = _we.is_set()
with open(_sl, 'ab') as f: f.write(b"[+] All data received!\n[+] File saved succ")
time.sleep(0.3); _partial = _we.is_set()
with open(_sl, 'ab') as f: f.write(b"essfully\n")
_fired = _we.wait(2); _w.cancel()
check("T3 watcher signals only this configuration's transfer", not _early and not _partial and _fired and _w.completed_after is not None,
      "old marker ignored=%s, partial line ignored=%s, fired=%s after %.2fs" % (not _early, not _partial, _fired, _w.completed_after or -1))
os.unlink(_sl)

with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
    _idle = f.name
ev.wartime_stop_event.clear(); _t4 = main.PhaseTimer(ev.wartime_stop_event, 0.2).start()
_o4 = ev.run_wartime([Never()], readjson(_idle), {'tunnel.com'}, set()); _t4.cancel()
ev.wartime_stop_event.clear()
_o4b = ev.run_wartime([FlagTunnel()], gen([evt('a.tunnel.com')] + [evt('x.org')] * 3), {'tunnel.com'}, set())
check("T4 other stop reasons unchanged", _o4[5]['stop_reason'] == 'timer' and _o4b[5]['stop_reason'] == 'all_detected',
      "idle window: %s, all detected: %s" % (_o4[5]['stop_reason'], _o4b[5]['stop_reason']))
os.unlink(_idle)
_war = open(os.path.join(ROOT, "main.py")).read()
check("T5 stop_on_transfer_complete switches the watcher", "['dnsexfiltrator', 'stop_on_transfer_complete'], True)" in _war
      and "if stop_on_transfer else None" in _war and "transfer_event=transfer_complete_event if stop_on_transfer else None" in _war,
      "watcher and transfer_event only when dnsexfiltrator.stop_on_transfer_complete is true (default)")

# Cached tunnel answers are flushed between configurations
from config import dns_config_generator as _dcg
_bd = tempfile.mkdtemp()
_dcg.generate_all_configs(['tunnel.com'], '192.168.4.4', '1.1.1.1', os.path.join(ROOT, 'config', 'templates'), _bd)
_keys = [open(os.path.join(_bd, s, 'config', 'rndc.key')).read() for s in _dcg.BIND_SERVERS]
_confs = [open(os.path.join(_bd, s, 'config', 'named.conf')).read() for s in _dcg.BIND_SERVERS]
check("B1 BIND servers get an rndc control channel", len(set(_keys)) == 1 and 'hmac-sha256' in _keys[0]
      and all(c.startswith('include "/etc/bind/rndc.key";') and 'inet 127.0.0.1 port 953 allow { 127.0.0.1; }' in c for c in _confs),
      "one key for %s, loopback-only controls in every named.conf" % (_dcg.BIND_SERVERS,))
_calls = []
class _R: returncode = 0; stdout = ''; stderr = ''
_orig_run = main.subprocess.run
main.subprocess.run = lambda cmd, **kw: (_calls.append(cmd), _R())[1]
_ok = main.flush_tunnel_cache(['tunnel.com'])
main.subprocess.run = _orig_run
check("B2 flush covers resolver, root and TLD", _ok and [c[2] for c in _calls] == list(_dcg.BIND_SERVERS)
      and all(c[-2:] == ['flushtree', 'tunnel.com'] for c in _calls), "rndc flushtree on %s" % [c[2] for c in _calls])
_war = open(os.path.join(ROOT, "main.py")).read()
check("B3 flush runs before each server start", _war.index("if flush_tunnel_cache(domains):") < _war.index('"python3", "-u", "/app/dnsExfiltrator.py",')
      and _war.index("server_log_offset = log_end_offset(SERVER_LOG)") > _war.index("if flush_tunnel_cache(domains):"),
      "flush after stopping the previous server, before offsets are taken and the new server starts")

# Live monitoring and dashboard controls
from detection import monitoring as mon
from detection.reporting import RunReport
_md = tempfile.mkdtemp()
_srv = os.path.join(_md, 'server.log')
with open(_srv, 'wb') as f: f.write(b"[==] 99.0%\tReceiving\t\r\n")              # previous configuration
_xp = mon.ExfilProgress(_srv, os.path.getsize(_srv))
with open(_srv, 'ab') as f: f.write(b"\x1b[1;34m[+] File size: 3030 bytes\x1b[0m\n[=-] 12.5%\tReceiving\t\r[==-] 40.0%\tReceiving\t\r")
_p1 = _xp.poll()
with open(_srv, 'ab') as f: f.write(b"\n[+] All data received!\n[+] File saved successfully\n")
_p2 = _xp.poll()
check("O1 transfer progress from the server log", _p1 == {'percent': 40.0, 'file_size': 3030, 'saved': False} and _p2['percent'] == 100.0 and _p2['saved'],
      "mid-transfer %s, after save %s" % (_p1, _p2))

_mrep = RunReport(_pl.Path(_md), 'monitor test')
_dns = os.path.join(_md, 'dns.json'); open(_dns, 'w').close()
_smp = mon.MetricsSampler(_mrep, _dns, {'tunnel.com'}, [], interval=0.3, resource_interval=60).start()
with open(_dns, 'a') as f:
    for q in ['a.example.org'] * 4 + ['x1.tunnel.com', 'x2.tunnel.com']:
        f.write(json.dumps(evt(q)) + "\n")
    _nx = resp('a.example.org', []); _nx['dns']['rcode'] = 'NXDOMAIN'; f.write(json.dumps(_nx) + "\n")
time.sleep(1.2); _smp.stop()
_samples = [json.loads(l) for l in open(_mrep.metrics_path)]
_q = sum(s['dns']['queries'] for s in _samples); _tq = sum(s['dns']['tunnel_queries'] for s in _samples)
check("O2 metrics count DNS traffic", _q == 6 and _tq == 2 and _samples[-1]['rcodes'].get('NXDOMAIN') == 1
      and _samples[-1]['top_domains'][0] == ['example.org', 4, False] and _samples[-1]['host']['cpu'] is not None,
      "queries=%d tunnel=%d rcodes=%s top=%s" % (_q, _tq, _samples[-1]['rcodes'], _samples[-1]['top_domains'][:2]))
_dd = _smp._detail()
check("O6 DNS details split benign and tunnel traffic",
      _dd['qtypes'] == {'b': {'A': 4}, 't': {'A': 2}} and _dd['qname_len']['b'] == {'10': 4}
      and sum(_dd['entropy']['t'].values()) == 2 and _dd['avg']['b']['query_bytes'] == 50.0
      and any('dns_detail' in x for x in _samples),
      "qtypes=%s qname_len=%s avg=%s" % (_dd['qtypes'], _dd['qname_len'], _dd['avg']['b']))

_rc = main.RunControl(); _old_report = main.REPORT; main.REPORT = _mrep
_mrep.set_phase('wartime', 'cfg1'); _rc.open_window()
_cw = mon.ControlWatcher(_mrep, _rc.handle, poll_interval=0.05).start()
_mrep.control_path.write_text(json.dumps({"id": 1, "action": "skip_config"}))
ev.wartime_stop_event.wait(2)
_os = ev.run_wartime([Never()], gen([evt('a.org')]), {'tunnel.com'}, set())
_mrep.control_path.write_text(json.dumps({"id": 2, "action": "stop_run"}))
_rc.stop_requested.wait(2); time.sleep(0.2)
check("O3 dashboard skip and stop reach the run", _os[5]['stop_reason'] == 'user_skip' and _rc.stop_requested.is_set()
      and ev.peacetime_stop_event.is_set() and _mrep.state['control']['id'] == 2 and _mrep.state['control']['accepted'],
      "skip -> stop_reason=%s; stop -> stop_requested=%s, ack=%s" % (_os[5]['stop_reason'], _rc.stop_requested.is_set(), _mrep.state['control']))
_cw.stop(); _rc.close_window(); main.REPORT = _old_report; ev.peacetime_stop_event.clear(); ev.reset_wartime_stop()

sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import dashboard as _db, urllib.request, urllib.error
from http.server import ThreadingHTTPServer
_db.DashboardHandler.results_dir = _pl.Path(_md).resolve(); _db.DashboardHandler.token = 'tok123'
_httpd = ThreadingHTTPServer(('127.0.0.1', 0), _db.DashboardHandler); _db.DashboardHandler.port = _httpd.server_address[1]
threading.Thread(target=_httpd.serve_forever, daemon=True).start()
_base = 'http://127.0.0.1:%d' % _db.DashboardHandler.port
def _post(headers):
    req = urllib.request.Request(_base + '/api/run/%s/control' % _mrep.dir.name, data=b'{"action": "skip_config"}', method='POST', headers=headers)
    try: return urllib.request.urlopen(req).status
    except urllib.error.HTTPError as e: return e.code
_codes = (_post({}), _post({'X-TunFrame-Token': 'tok123', 'Origin': 'http://evil.example'}), _post({'X-TunFrame-Token': 'tok123', 'Origin': _base}))
_page = urllib.request.urlopen(_base + '/').read().decode()
_httpd.shutdown()
check("O4 dashboard control needs token and local origin", _codes == (403, 403, 200) and json.load(open(_mrep.control_path))['id'] == 3 and 'tok123' in _page,
      "no token / foreign origin / valid -> %s" % (_codes,))
_rc2 = _db.read_chunk(_pl.Path(_srv), 0, 30, align_lines=True)
check("O5 dashboard never serves partial lines; progress bars collapse; SGR colour kept, other escapes dropped",
      _rc2['data'].endswith(b"\n")
      and _db.clean_tool_log("\x1b[1m[=] 10%\r[==] 20%\x1b[0m\ndone") == "[==] 20%\x1b[0m\ndone"
      and _db.clean_tool_log("\x1b[2K\x1b[31mred\x1b[0m") == "\x1b[31mred\x1b[0m",
      "chunk ends at a line break, '\\r' progress collapses, colour codes survive, cursor/erase codes removed")

# Per-run report directory, charts, report.html and dashboard API
import pathlib as _pl2, datetime as _dt
_old_dir = main.RESULTS_DIR
main.RESULTS_DIR = _pl2.Path(tempfile.mkdtemp())
_cfg = {'global': {'name': 'harness run'}}
main.logger.setLevel(logging.INFO); main.console_handler.setLevel(logging.ERROR)   # run.log needs INFO; console stays quiet
_rep = main.start_run_report(_cfg)
_rep.set_planned_configs(['cfgA', 'cfgB'])
_d = FlagTunnel(); ev.wartime_stop_event.clear()
_o = ev.run_wartime([_d], gen([evt('aa.tunnel.com'), evt('x.org')]), {'tunnel.com'}, set())
_t = _dt.datetime.now()
main.build_and_save_metadata(_rep.config_file('cfgA'), _o[0], _o[1], _o[2], _o[3], _o[4], _t, _t, 60, 0, {'tunnel.com'},
                             False, '', None, '192.168.4.4', '1.1.1.1', _cfg, counts=_o[5], config_name='cfgA')
main.save_status_result(_cfg, 'cfgB', 'skipped', 'no traffic')
main.logger.info("progress line", extra={'progress': True})
main.finalize_run_report('completed')
_state = json.load(open(_rep.dir / 'run.json'))
_log = open(_rep.dir / 'run.log').read()
check("R1 one directory per run", _rep.dir.parent == main.RESULTS_DIR and sorted(p.name for p in (_rep.dir / 'configs').iterdir()) == ['cfgA.json', 'cfgB.json'],
      "run dir %s with configs %s" % (_rep.dir.name, sorted(p.name for p in (_rep.dir / 'configs').iterdir())))
check("R2 run.json tracks status per config", _state['status'] == 'completed' and [(c['name'], c['status']) for c in _state['configs']] == [('cfgA', 'completed'), ('cfgB', 'skipped')]
      and _state['configs'][0]['detectors'][0]['f1'] == 1.0, "status=%s configs=%s" % (_state['status'], [(c['name'], c['status']) for c in _state['configs']]))
check("R3 run.log mirrors console without progress lines", 'RUN SUMMARY' in _log and 'progress line' not in _log, "run.log has %d lines" % _log.count('\n'))
_charts = _rep.dir / 'charts'
_r4 = {n: (_charts / n).exists() for n in ('bars_f1.png', 'bars_f1-dark.png', 'heatmap_f1.png', 'heatmap_f1-dark.png')}
_html = (_rep.dir / 'report.html').read_text() if (_rep.dir / 'report.html').exists() else ''
check("R4 report.html and charts written in light and dark", all(_r4.values()) and "tunframe-theme" in _html
      and "bars_f1-dark.png" in _html and "Detector comparison" in _html,
      "charts=%s, theme toggle and dark images in report.html=%s" % (_r4, "tunframe-theme" in _html))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import dashboard
_runs = dashboard.list_runs(main.RESULTS_DIR)
check("R5 dashboard lists runs", [r['id'] for r in _runs] == [_rep.dir.name] and _runs[0]['status'] == 'completed', "runs %s" % [(r['id'], r['status']) for r in _runs])
main.REPORT = None
main.RESULTS_DIR = _old_dir
main.logger.setLevel(logging.ERROR)

sys.exit(1 if FAILS else 0)
