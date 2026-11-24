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

dets = [FlagTunnel()]
cfg1 = [evt('x%d.tunnel.com' % i) for i in range(5)] + [evt('a.com')]
ev.wartime_stop_event.clear()
res1 = ev.run_wartime(dets, gen(cfg1), {'tunnel.com'}, set())
cfg2 = [evt('benign%d.org' % i) for i in range(3)] + [evt('y%d.tunnel.com' % i) for i in range(5)]
ev.wartime_stop_event.clear()
res2 = ev.run_wartime(dets, gen(cfg2), {'tunnel.com'}, set())
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
res = ev.run_wartime(det, gen(war), {'tunnel.com'}, set())
check("M2 wartime universe excludes peacetime domains", len(res[4]) == 4 and abs(res[0][0]['fpr'] - 0.25) < 1e-9,
      "all_domains=%d (4 wartime domains), FPR=%.3f (expected 0.250)" % (len(res[4]), res[0][0]['fpr']))

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

sys.exit(1 if FAILS else 0)
