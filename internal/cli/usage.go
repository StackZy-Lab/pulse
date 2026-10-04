package cli

const helpText = `pulse checks the health of a URL.

Usage:
  pulse [flags] [url]

  Runs one or more HTTP(S) checks against a URL and prints each result: HTTP
  status, per-phase latency, TLS details and redirects. If url is omitted,
  pulse prompts for it, and a value without a scheme defaults to https.

Examples:
  pulse https://example.com
  pulse -n 5 --timeout 10s example.com
  pulse --json https://api.example.com/health
  pulse --expect-status 200 -H "Authorization: Bearer $TOKEN" https://api.example.com

Flags:
  -n, --count int             number of checks to run (default 3)
  -t, --timeout duration      timeout for each check (default 20s)
      --method string         HTTP method (default GET)
  -H, --header "Name: value"  add a request header; repeatable
  -d, --data string           request body
      --expect-status spec    accepted status codes: "200", "200,204", "200-299" or "2xx"
                              (default: any status below 400)
      --no-redirect           do not follow redirects
      --max-body bytes        read up to this many response bytes (default 0: body is not read)
      --insecure              skip TLS certificate verification and report a warning
      --min-tls version       minimum TLS version: 1.0, 1.1, 1.2 or 1.3 (default 1.2)
  -o, --output format         output format: text or json (default text)
      --json                  shorthand for --output json
      --color mode            color output: auto, always or never (default auto)
      --ascii                 use ASCII symbols instead of Unicode
  -q, --quiet                 suppress the header and progress indicator
  -V, --version               print the version and exit
  -h, --help                  show this help

Exit status:
  0  every check succeeded
  1  at least one check failed
  2  invalid usage or configuration

Environment:
  NO_COLOR                 disable color when --color is auto
  CLICOLOR_FORCE           force color when --color is auto
  LC_ALL, LC_CTYPE, LANG   control Unicode symbol detection
`
