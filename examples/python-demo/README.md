# Python demo

Records a Playwright run of a local page that hides a prompt injection, then analyzes it with the Steplight CLI.

```bash
pip install "steplight-sdk[playwright]"
playwright install chromium
npm i -D steplight                 # the CLI (analyze, view, check, diff, report)

python demo.py
npx steplight view                 # timeline, replay, the hidden text highlighted
npx steplight check --latest --rules steplight.rules.yml   # exits 1: hidden instruction found
```

The page is served from `127.0.0.1` by the script itself; no network access is needed. See [docs/python.md](../../docs/python.md).
