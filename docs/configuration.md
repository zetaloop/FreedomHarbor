# Configuration

Load a TOML file with `freedomharbor -c path/to/config.toml`. Omitted fields use their defaults. Restart FreedomHarbor after changing the configuration.

The [example configuration](../examples/freedomharbor.toml) enables packet handling and uses the listener addresses expected by the [nftables rules](../examples/freedomharbor.nft).

## TCP

These options are at the top level of the TOML file.

| Option | Default | Description |
|---|---|---|
| `listen` | `["127.0.0.1:15000", "[::1]:15000"]` | Transparent TCP listeners. Match these to the TPROXY targets in the nftables rules. |
| `tls` | `true` | Split the initial TLS ClientHello across multiple TLS records. |
| `sniff_timeout_ms` | `10` | How long to buffer TCP data while its application protocol is unclear, in milliseconds. Detection continues after forwarding starts. |

Recognizable HTTP, TLS and MMTLS prefixes are buffered until enough data is available for parsing. The top-level `tls` option changes TLS record boundaries; `packet.tls` controls TCP segmentation.

## HTTP

Options under `[http]`:

| Option | Default | Description |
|---|---|---|
| `enabled` | `true` | Parse and handle HTTP requests and responses. |
| `upgrade` | `true` | Attempt HTTPS upstream connections for HTTP requests. |
| `normalize` | `true` | Normalize request headers on plaintext HTTP upstream connections. |
| `user_agent` | Bundled Chrome desktop UA | User-Agent used by header normalization. |
| `tls_timeout_ms` | `3000` | HTTPS connection timeout, in milliseconds. |
| `cache_ttl_ms` | `300000` | Lifetime of cached HTTPS connection results, in milliseconds. |

Header normalization replaces `User-Agent` and sorts header names. It removes `Sec-CH-*`, device and network hints, and the forwarding headers `Forwarded`, `Via`, `X-Forwarded-For` and `X-Real-IP`. Responses from plaintext upstreams have `Accept-CH` and `Critical-CH` removed.

HTTPS upgrades connect to the original destination IP. An omitted port or port 80 maps to 443; other explicit ports are retained. If the HTTPS connection fails, the request uses HTTP.

For ordinary GET and HEAD requests, `Upgrade-Insecure-Requests: 1` enables a 307 redirect when HTTPS is available. MMTLS carried over HTTP uses its original HTTP endpoint.

## Content rules

Options under `[http.probe]`:

| Option | Default | Description |
|---|---|---|
| `enabled` | `true` | Apply content rules to traffic handled by the HTTP proxy. |
| `capture` | `true` | Save samples when a content rule matches. |
| `samples` | `/var/lib/freedomharbor/samples` | Directory for saved samples. |
| `rules` | Built-in `usershare` rule | List of filtering rules. |

The built-in rule matches the `/usershare/flash.js` and `/usershare/1.swf` resources, related embedded elements and inline detection scripts. Defining `[[http.probe.rules]]` entries replaces the default list.

Each rule requires a `name`. Its match lists default to empty.

| Field | Description |
|---|---|
| `name` | Rule name used in logs and sample metadata. |
| `scope` | Regular expression selecting request URLs. Omit to apply the rule to all requests. |
| `urls` | Patterns matched against request URLs and response `Location` headers. Matching requests and redirects return an empty 204 response. |
| `elements` | CSS selectors for HTML elements to remove. |
| `scripts` | Patterns matched against inline script text. The contents of a matching script are removed. |
| `cookies` | Cookie name patterns to remove from request `Cookie` and response `Set-Cookie` headers. |

`scope`, `urls`, `scripts` and `cookies` use Rust regular expressions. All rules whose scope matches the request apply.

This example applies a rule to `example.com`:

```toml
[[http.probe.rules]]
name = "site-probe"
scope = '^https?://example\.com/'
urls = ['/probe\.js(?:[?#]|$)']
elements = ['script[src*="/probe.js"]']
scripts = ['\bcheckClient\s*\(']
cookies = ['^client_probe$']
```

HTML filtering supports gzip, deflate, Brotli and Zstandard content encodings. Filtered bodies are encoded in the same format as the input.

### Samples

With `capture` enabled, matched HTTP exchanges are saved under `samples`. Response bodies are stored as received, including their original content encoding.

| File | Contents |
|---|---|
| `request.headers` | Request method, URL, HTTP version and headers before filtering. |
| `response.headers` | Response status and headers before filtering. |
| `request.body` | Body of a blocked request. |
| `response.body` | Response body before filtering. |
| `trailers.headers` | Trailers received with the body. |
| `event.json` | Time, source, destination, URL, rule matches and completion details. |

In `event.json`, `complete` indicates whether the entire body was received. `error` describes any interruption or processing failure.

## Packet handling

Adding `[packet]` enables NFQUEUE processing. Include this table when using the supplied nftables rules.

| Option | Default | Description |
|---|---|---|
| `queue` | `200` | NFQUEUE number. Match it to `qnum` in the nftables rules. |
| `http` | `true` | Split the HTTP method and `Host` header across TCP segments. |
| `tls` | `true` | Split TCP segments around TLS ClientHello fields. |
| `mmtls` | `true` | Split TCP segments at MMTLS record headers. |
| `quic` | `true` | Reorder QUIC Initial CRYPTO frames and use IP fragmentation when needed. |
| `spoof` | `true` | Inject decoy TLS ClientHellos and hostname fragments. |

## nftables rules

The example redirects WAN-bound TCP connections from the LAN to the proxy. It uses NFQUEUE for packet-level handling of TCP and QUIC traffic.

Variables in `examples/freedomharbor.nft`:

| Variable | Example | Description |
|---|---|---|
| `lan` | `lan0` | LAN ingress interface. |
| `wan` | `wan0` | WAN egress interface. |
| `port` | `15000` | TCP proxy port, matching `listen`. |
| `qnum` | `200` | NFQUEUE number, matching `packet.queue`. |
| `hops` | `64` | TTL/Hop Limit for forwarded traffic. |

The routing commands in the README use mark `0x1` and table `100` to deliver traffic to the proxy.

The `freedomharbor_headers` table adjusts TTL/Hop Limit, IPv4 identification and IPv6 flow labels on forwarded traffic.

Disable IP header normalization at runtime:

```sh
sudo nft 'add table inet freedomharbor_headers { flags dormant; }'
```

Enable it again:

```sh
sudo nft add table inet freedomharbor_headers
```
