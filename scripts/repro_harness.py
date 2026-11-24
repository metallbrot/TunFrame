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
print("2) TN double count: tp=%d fp=%d tn=%d fn=%d for 3 domains (1 tunnel missed) accuracy=%.3f" % (r['tp'], r['fp'], r['tn'], r['fn'], r['accuracy']))

d = Never()
d.process_line(evt('abcdefghij.tunnel.com'), True)          # single data label
one = d.lv_up
d.process_line(evt('seq.abcdefghij.tunnel.com'), True)      # two labels
print("3) ULV single-label query adds %d bytes; two-label query adds %d bytes" % (one, d.lv_up - one))

def gen(events):
    for e in events: yield e
dets = [FlagTunnel()]
cfg1 = [evt('x%d.tunnel.com' % i) for i in range(5)] + [evt('a.com')]
ev.wartime_stop_event.clear()
res1 = ev.run_wartime(dets, gen(cfg1), {'tunnel.com'}, set(), set())
cfg2 = [evt('benign%d.org' % i) for i in range(3)] + [evt('y%d.tunnel.com' % i) for i in range(5)]
ev.wartime_stop_event.clear()
res2 = ev.run_wartime(dets, gen(cfg2), {'tunnel.com'}, set(), set())
print("4) config1 logcount=%d, config2 logcount=%d of %d lines (stopped early), config2 processed_lines=%d, config2 tp=%d with no tunnel line read" % (
      res1[1], res2[1], len(cfg2), res2[0][0]['processed_lines'], res2[0][0]['tp']))

det = [Never()]
peace = [evt('peace%d.net' % i) for i in range(20)]
ev.peacetime_stop_event.clear()
plc, pdomains = ev.run_peacetime(det, gen(peace), {'tunnel.com'})
ev.generate_allowlists(det, set(), plc)
det[0].alarms = {'war1.org'}  # pretend one false positive in wartime
war = [evt('war%d.org' % i) for i in range(4)]
ev.wartime_stop_event.clear()
res = ev.run_wartime(det, gen(war), {'tunnel.com'}, set(), pdomains)   # same call pattern as main.py
fresh = Never(); fresh.alarms = {'war1.org'}
ref = fresh.evaluate(set(), {'war%d.org' % i for i in range(4)}, 4, 0, set())
print("5) wartime-only domains=4; all_domains passed to evaluate=%d; FPR reported=%.3f vs FPR on wartime domains=%.3f" % (
      len(res[4]), res[0][0]['fpr'], ref['fpr']))

with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
    for i in range(300): f.write(json.dumps(evt('q%d.example.com' % i)) + "\n")
    path = f.name
g = readjson(path, timeout_seconds=60, max_timeouts=2)
t0 = time.time(); n = 0
while n < 300:
    if next(g) is not None: n += 1
print("6) readjson delivered 300 ready lines in %.2f s (%.0f lines/s max)" % (time.time() - t0, 300 / (time.time() - t0)))

e = threading.Event()
main.start_timer_event(e, 0.5)          # config 1 timer (config ends early)
e.clear()
t0 = time.time(); main.start_timer_event(e, 2.0)   # config 2 should run 2.0 s
e.wait(5)
print("7) config 2 stop event fired after %.2f s although its timer was 2.0 s" % (time.time() - t0))

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
