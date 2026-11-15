# AI analyst

[← Back to the README](../README.md)

The AI analyst, Ask AI, AI-written reports, timeouts and privacy mode.

## What it does

Chat with the model (any OpenAI-compatible endpoint; with Claude it uses Anthropic's
[OpenAI SDK compatibility layer](https://platform.claude.com/docs/en/api/openai-sdk)). It can run read-only SQL against the log database, search events, profile an
IP, read alerts, OPNsense + Unraid status and traffic statistics, and answers with evidence and remediation steps.
Credentials (users, MFA secrets, API keys) are never accessible to it. Data sent to the AI provider consists of the
query results the model asks for (IPs, domains, log lines) - with **privacy mode** on, local addresses and names
in them are pseudonyms (see [AI privacy mode](#ai-privacy-mode-pseudonyms)). It also reads your comments on alerts.

## AI analysis: timeouts and "504 Gateway Timeout"

A report's AI analysis is an agent run of several model calls (the model looks into the data with its tools) and runs
in the background: the report opens right away, the AI part fills in when ready, and a failure shows the reason with
**Retry AI analysis**. Answers are **streamed** (*Settings › AI analyst › Stream answers*, on by default): gateways and
proxies in front of a model (OpenRouter, LiteLLM, Cloudflare, nginx) often cut off requests that send nothing for 60-100
seconds, which is what a 504 means - a streamed answer keeps the connection busy. Overload / gateway errors (429, 502,
503, 504) are retried twice. Still 504? Raise the timeout of your own proxy (e.g. LiteLLM `timeout`, nginx
`proxy_read_timeout`), use a faster model or lower *Max tool rounds*.

The **AI chat** works the same way: the question starts the run on the server and the page asks for the result
every few seconds, so a reverse proxy in front of Looking Glass itself (nginx `proxy_read_timeout`, 60 s by default)
no longer cuts long answers off.

## AI privacy mode (pseudonyms)

Off by default. When it is on, local identifiers (your private IPs, MAC addresses, device and user names, your WAN
address …) are replaced by consistent pseudonyms **before anything leaves Looking Glass**, and translated back in what
the AI returns - its answer and every query it runs. You keep seeing the real values, the tools keep querying the real
data; only the AI provider sees pseudonyms.

**Turning it on** (Looking Glass web UI › **Settings** › **AI analyst** tab):

1. Tick **Privacy mode: pseudonymize local data**.
2. Leave **Privacy mode: also replace names** ticked (device, Wi-Fi and user names), unless you only want addresses
   replaced.
3. Optional: under **Privacy mode: always replace these** enter, one per line, anything else that identifies you and
   Looking Glass cannot know - your own domain(s) (subdomains are included), your family name, a static WAN address.
4. Optional: under **Privacy mode: never replace these** enter names that should stay readable (e.g. a device whose
   name is also an ordinary word in your logs).
5. Optional: under **Privacy mode: never use these networks for fake addresses** enter networks or ranges the fake
   addresses must stay out of, one per line: `10.0.0.0/8`, a single address, or `192.168.0.0-192.168.50.255`.
6. **Save**. It applies from the next question / report on, no restart needed. A **🔒 Privacy mode** badge appears next
   to the model name on the **AI Analyst** page.

**Where it applies**: everything that is sent to the AI - the AI Analyst chat, **Ask AI** on an alert or an event, and the AI
analysis of **reports** (written by hand, scheduled, or *Retry AI analysis*; the report's statistics are sent to the AI
as part of the prompt and are pseudonymized too). Not affected (nothing goes to the AI): the report itself and its
numbers, report and notification **mails** (they go through your own mail server and keep the real values), and
*Test connection* (sends only "Reply with OK").

**Example** - what the AI receives for one log line, and what you read in the answer:

| | |
|---|---|
| In the database | `Accepted password for john from 192.168.1.20 (Johns-iPhone, aa:bb:cc:11:22:33) via 84.12.33.4` |
| Sent to the AI | `Accepted password for user-p9rd from 192.168.124.20 (iphone-9hfj, aa:bb:cc:9d:06:7a) via 198.51.100.41` |
| The AI answers | "*iphone-9hfj* (192.168.124.20) logged in as *user-p9rd* …" |
| You read | "*Johns-iPhone* (192.168.1.20) logged in as *john* …" |

| Replaced | By |
|---|---|
| Private IPv4 (10/8, 172.16/12, 192.168/16, 100.64/10) | another network of the same range, per /24; the last number stays (`.1` is still the gateway), so subnets and CIDR filters keep working - see *How fake addresses are chosen* below |
| Your own public / WAN addresses (OPNsense interfaces, *Extra internal networks*) | documentation addresses `203.0.113.x`, `198.51.100.x`, `192.0.2.x` |
| IPv6: unique local `fd…`, your own prefixes, link-local | a fake site prefix (`2001:db8:…` / `fd…`), the subnet id stays, a random interface id (it can contain the MAC) |
| MAC addresses | the vendor part (first three bytes) stays, the rest is random |
| Email addresses | `mail-xxxx@example.net` |
| *Also replace names* (on by default): device names / UniFi aliases, Wi-Fi names (also neighbouring ones - they can locate you), user names that logged in, Unraid server names | tokens such as `iphone-k7q2`, `ssid-iot-m3xa`, `user-p9rd` - a generic word in the name (iphone, camera, tv …) is kept as a hint |
| *Always replace these*: your domains (with subdomains), family names, a street … | `name-xxxx`, `domain-xxxx.example` |

**How fake addresses are chosen**: per /24. Devices in the same /24 get fake addresses in the same fake /24 with the
same last number (`192.168.20.3` and `192.168.20.7` → `192.168.120.3` and `192.168.120.7`), a device in another /24
gets a different fake /24, and the private range stays the same (192.168.x stays 192.168.y), so the AI still sees which
devices share a network / VLAN. Subnets smaller than a /24 keep their exact structure; a subnet larger than a /24
(e.g. a /16 with devices in several /24s) becomes several unrelated fake /24s. The fake networks are picked at random
but never one of your own networks (devices, OPNsense interfaces, *Extra internal networks*) and never one listed
under *never use these networks for fake addresses* - when a whole range is excluded, another private range is used,
and fake addresses already in an excluded network are replaced on the next question.

Not replaced, because the analysis needs them and they don't identify you on their own: internet addresses, domains,
ports, countries, container / program names, rule names and signatures. Generic names (root, admin, nas, router …) and
the entries under *Never replace these* stay readable.

Good to know:

* Values are replaced by kind **everywhere** (columns, raw log lines, alert titles, report data, your own question),
  never per field, so the model always sees one consistent picture. A device keeps its pseudonym in every request,
  report and conversation (stored in the table `ai_pseudonyms`, a few kB).
* Conversations and reports are stored with the real values, and only the outgoing request is changed, so turning the
  mode on or off never breaks an old conversation. Logs and the database don't grow (apart from that small table).
* Free text in log lines (container logs, file paths, notifications) can still hold a name Looking Glass does not
  know: add it under *Always replace these*. The AI provider still knows *your account*; for complete privacy use a
  local model (Ollama, LM Studio).
* Costs a few milliseconds per request; the analysis stays about as good - only meaning carried by a name is lost.
* If the pseudonyms cannot be prepared (e.g. the database is unreachable), the request is **not sent** - the mode never
  falls back to sending the real values.
* *Settings › Data & detection › Delete collected data › AI analyst conversations* also empties `ai_pseudonyms`; devices simply get new
  pseudonyms from then on (stored conversations keep working, they hold the real values).
* **See for yourself what is sent**: open a chat on the **AI Analyst** page and click **What the AI sees** (top right
  of the conversation). It shows the whole conversation exactly as the AI receives it with your next question - the
  instructions (system prompt), your questions, the queries the AI ran, the data returned to it and its answers. The
  pseudonyms are highlighted: hover one to see the real value it stands for, or click / tap it to swap. A real name you
  can still read there was not recognised - add it under *Always replace these*. With privacy mode off the same view
  shows that everything is sent as it is. Click the button again for the normal view.
