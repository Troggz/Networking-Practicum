import sys, random
import dns.message, dns.query, dns.rdatatype, dns.exception

ROOTS = [ 
    "198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13",
    "192.203.230.10","192.5.5.241","192.112.36.4","198.97.190.53",
]

def ask(server, name, rdtype="A", timeout=2.0):
    q = dns.message.make_query(name, getattr(dns.rdatatype, rdtype))
    return dns.query.udp(q, server, timeout=timeout)

def pick_next(resp):

    ips = []
    for rr in resp.additional:
        if rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            for r in rr: ips.append(r.address)

    ns = []
    for rr in resp.authority:
        if rr.rdtype == dns.rdatatype.NS:
            for r in rr: ns.append(str(r.target).rstrip("."))
    return ips, ns

def parse_answer(resp):
    cn = None; addrs = []
    for rr in resp.answer:
        if rr.rdtype == dns.rdatatype.CNAME:
            cn = str(rr[0].target).rstrip(".")
        elif rr.rdtype == dns.rdatatype.A:
            for r in rr: addrs.append(r.address)
    return addrs, cn

def resolve(name, timeout=2.0, maxsteps=40):
    name = name.rstrip(".")
    servers = ROOTS[:]; random.shuffle(servers)
    for _ in range(maxsteps):
        if not servers: servers = ROOTS[:]; random.shuffle(servers)
        s = servers.pop(0)
        try: resp = ask(s, name, "A", timeout)
        except dns.exception.Timeout: continue
        addrs, cname = parse_answer(resp)
        if addrs: return addrs
        if cname:  
            name = cname; servers = ROOTS[:]; random.shuffle(servers); continue
        ips, ns = pick_next(resp)
        if ips: servers = ips + servers; continue
      
        for host in ns[:2]: 
            ns_ips = resolve(host, timeout, maxsteps//2)
            if ns_ips: servers = ns_ips + servers; break
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mini_resolver.py <hostname>"); sys.exit(1)
    answers = resolve(sys.argv[1])
    if answers:
        print("A records for", sys.argv[1])
        for a in sorted(set(answers)): print(" ", a)
    else:
        print("No A records found.")
