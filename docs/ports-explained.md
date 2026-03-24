# Ports explained

If you've followed the setup guide, you've run into the word "port" a few times.
Here's what it actually means — and why you have to care about it.

---

## What is a port?

Your computer has one network connection to the internet, but dozens of programs
use it at the same time: your browser, your chat app, rmail, and so on. Ports are
how the OS sorts incoming traffic to the right program.

Think of your computer as an apartment building. The building has one street
address (your IP address), but each apartment has its own number. When a letter
arrives, the mailman looks at the apartment number to know which slot to put it in.
Ports are the apartment numbers. When rmail starts, it claims one port — say,
8025 — and tells the OS: "anything arriving on apartment 8025 is mine."

Port numbers run from 1 to 65535. Numbers below 1024 are reserved for
well-known services (80 for web, 443 for HTTPS, 25 for email servers, etc.).
rmail uses a number in the high range — either one you pick or a random one the
installer chose — to stay out of the way of everything else.

---

## Why does your computer need a port open?

When someone sends you a message, their computer reaches out to yours over the
internet. That connection has to land somewhere. If no port is open and listening,
the OS discards the packet, and the message never arrives.

"Opening a port" just means telling the OS to accept incoming connections on that
number and hand them off to rmail instead of dropping them.

---

## What is port forwarding?

If your computer is connected through a home router (which is almost always the
case), there's a complication: the internet sees your *router's* address, not your
computer's address. Your computer has a private address that's only meaningful
inside your home network — something like `192.168.1.10`.

When rmail traffic arrives at your router addressed to port 8025, the router
doesn't know which device inside your home to send it to. You have to tell it.
That's port forwarding: a rule in your router's settings that says "anything
arriving on port 8025, send it to 192.168.1.10."

You set this up once in your router's admin panel. After that, your router handles
it automatically every time a message comes in.

---

## What is hairpin NAT?

Most of the time, your contacts are on different networks and their messages reach
you from the internet. But what if a contact is on the same local network as you —
same router, same WiFi? Their message goes to the router, which sees it's addressed
to the public IP (the router's own address), and has to decide what to do with it.

**Hairpin NAT** (also called NAT loopback) is when the router recognizes this
situation and routes the packet back to the right device on the LAN instead of
dropping it. It "loops back" through the NAT, like a hairpin.

Many consumer routers do not support this. If yours doesn't, contacts on your local
network can't reach you via your public IP — the packet is silently dropped.

If your router doesn't support hairpin NAT, contacts on your local network should
use your local IP address (e.g. `192.168.1.10`) instead of your public IP. LAN
traffic bypasses the router's NAT entirely and goes directly between devices — no
hairpin support needed, and no port forwarding rule required either.

```
# reachable from anywhere (requires hairpin NAT for LAN use)
alice.ip    = 203.0.113.1
alice.port  = 8025
alice.token = "shared-secret"

# reachable only from the same local network
alice_home.ip    = 192.168.1.10
alice_home.port  = 8025
alice_home.token = "shared-secret"
```

To find out if your router supports hairpin NAT, run `scripts/validate-router-settings.sh`
after opening your firewall port.

---

## What is a firewall, and why do you open a hole in it?

A firewall is software — either in your OS or on your router — that blocks
incoming connections by default. It's a reasonable default: you probably don't
want random strangers on the internet connecting to arbitrary programs on your
machine.

"Opening a port in the firewall" means adding an exception: "connections to port
8025 are allowed through." The firewall still blocks everything else. You're not
turning off protection — you're making a precise, narrow exception for the one port
rmail uses.

---

## What is UPnP and why is it risky?

Port forwarding normally requires logging into your router's admin panel and adding
a rule manually. UPnP (Universal Plug and Play) is a protocol that lets software
ask the router to create that rule automatically, without you having to log in.

The problem is that UPnP has no authentication. Any device on your local network
can open any port on your router, without a password or your approval. Malware
routinely exploits this to punch holes in home routers. Many security-conscious
people and organizations disable UPnP entirely.

rmail supports UPnP as a fallback for situations where you genuinely can't reach
your router's admin panel — but the README warns against relying on it, and for
good reason. Manual port forwarding is one extra step up front and much safer.

---

## Only one port is opened — not your whole network

When you open port 8025, only port 8025 is opened. Everything else remains blocked.
Your router and your firewall continue rejecting connections to every other port
on your machine. You haven't "opened your network" in any broad sense — you've made
one small, specific exception.

Your contacts need to know your router's public IP and your port number. That's it.
They can't reach any other service on your machine through the same connection.

---

## The OS only delivers packets to the right application

When a packet arrives on port 8025, the OS checks which program registered for that
port. Only rmail did. The OS hands the packet to rmail and to nothing else.
A program can't snoop on another program's port without the right system privileges
— the separation is enforced by the OS itself, not by convention.

---

## Properly written software only accepts what it expects

rmail expects messages formatted in a specific way. Anything that doesn't match
that format is rejected and discarded. Sending rmail a packet that says "run this
command" or "delete these files" doesn't work — rmail doesn't parse that as a valid
message structure. It just drops it.

This is a property of any well-designed network application: it validates every
incoming packet against a strict schema and rejects anything malformed. The port
being open doesn't mean arbitrary code can be delivered and executed; it means
connections to that port are handed to a specific program, which then decides what
to do with them.

---

## Why does the Android app need a home computer?

When you send a message from your phone, it goes outward — your phone connects to
the recipient's computer. That works fine. The tricky part is receiving.

For your computer to receive messages, it needs an open port: it sits there listening,
and senders connect to it. But your phone can't do this. Here's why.

Your phone is on a mobile network. The carrier runs its own version of the router
NAT described above — called **carrier-grade NAT (CGNAT)** — but at a much larger
scale. Thousands of phones share a single public IP address. There's no router admin
panel you can log into, no port forwarding rule you can set. The carrier controls all
of it. Incoming connections to your phone from the internet simply have nowhere to
land.

The rmail Android app works around this by flipping the direction. Instead of waiting
for messages to arrive, the phone regularly checks your home computer: "any new
messages for me?" Your home computer does have an open port and does receive the
incoming connections from your contacts. The phone just polls it on a schedule and
picks them up.

This is why a home daemon (a desktop or laptop, or a small always-on machine like a
VPS) is required. The phone is a frontend, not a standalone node.

For a technical explanation of why alternatives like hole punching and IP spoofing
don't work, see [nat-traversal-report.md](nat-traversal-report.md#part-9-cgnat-and-mobile-devices).

---

## What if a contact has a local IP address?

If you put a local IP address (like `192.168.1.10`) in a contact's entry, messages
will work normally as long as both of you are on the same local network. Your router
handles LAN-to-LAN traffic internally — no packets leave your network, and your ISP
never sees them.

From outside that network (a different house, a mobile connection), the connection
will fail. Private IP ranges (`192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`) are
non-routable: your router won't forward those packets out to the internet, so a
machine on a different network simply can't reach a private IP.

So a local IP in the contacts file works fine for local-only use, but won't work
when either side is away from home. If you want to communicate from anywhere, use
the public IP of their router instead.
