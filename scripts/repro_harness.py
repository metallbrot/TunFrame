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

print("1) format_duration:", repr(ev.format_duration(64.435775)), repr(ev.format_duration(60.0)))

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

import tempfile as _tf, pathlib as _pl
_old_dir = main.RESULTS_DIR
main.RESULTS_DIR = _pl.Path(_tf.mkdtemp())
f3 = main.save_status_result({'global': {'name': 'T'}}, 'cfgX', 'skipped', 'client failed')
d3 = json.load(open(f3))
main.RESULTS_DIR = _old_dir
ri = d3['metadata']['run_info']
check("C4 results are self-contained", len(ri['git_commit']) == 40 and ri['libraries']['tldextract'] != '' and 'dnsexfiltrator_config' in d3['metadata'],
      "git %s dirty=%s, tldextract %s, docker '%s'" % (ri['git_commit'][:8], ri['git_dirty'], ri['libraries']['tldextract'], ri['docker_version']))
check("C3 skipped configs leave a results file", d3['metadata']['run_status'] == {'status': 'skipped', 'reason': 'client failed'} and d3['detectors'] == [],
      "written %s with status %s" % (f3.name, d3['metadata']['run_status']['status']))

dets = [FlagTunnel()]
cfg1 = [evt('x%d.tunnel.com' % i) for i in range(5)] + [evt('a.com')]
ev.wartime_stop_event.clear()
res1 = ev.run_wartime(dets, gen(cfg1), {'tunnel.com'}, set())
cfg2 = [evt('benign%d.org' % i) for i in range(3)] + [evt('y%d.tunnel.com' % i) for i in range(5)]
for x in dets:
    x.phase_reset()          # what main.py now does at every config boundary
ev.wartime_stop_event.clear()
res2 = ev.run_wartime(dets, gen(cfg2), {'tunnel.com'}, set())
check("M7 no carry-over between configs", (res2[1], res2[0][0]['processed_lines'], res2[0][0]['tp'], res2[0][0]['fp']) == (4, 4, 1, 0),
      "config2 logcount=%d processed_lines=%d tp=%d fp=%d (expected 4, 4, 1, 0)" % (
      res2[1], res2[0][0]['processed_lines'], res2[0][0]['tp'], res2[0][0]['fp']))
main_src = open(os.path.join(ROOT, "main.py")).read()
check("M7 main resets detectors per config", "detector.phase_reset()" in main_src, "phase_reset() call present in main.py")

ev.peacetime_done.clear()
ev.peacetime_stop_event.clear()
ev.run_peacetime([Never()], gen([evt('p.net')]), {'tunnel.com'})
check("M13 run_peacetime sets peacetime_done", ev.peacetime_done.is_set() and not hasattr(ev, 'evaluate'),
      "peacetime_done set=%s, legacy evaluate() present=%s" % (ev.peacetime_done.is_set(), hasattr(ev, 'evaluate')))

det = [Never()]
peace = [evt('peace%d.net' % i) for i in range(20)]
ev.peacetime_stop_event.clear()
plc, pdomains = ev.run_peacetime(det, gen(peace), {'tunnel.com'})
ev.generate_allowlists(det, set(), plc)
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

import tldextract
try:
    tldextract.extract(None); print("8) tldextract.extract(None) did not raise")
except Exception as ex:
    print("8) tldextract.extract(None) raises", type(ex).__name__, "- run_peacetime has no None guard")

try:
    import detection.detector_base.aggregator
    print("9) aggregator imports fine")
except Exception as ex:
    print("9) aggregator import fails:", type(ex).__name__, ex)

sys.exit(1 if FAILS else 0)
