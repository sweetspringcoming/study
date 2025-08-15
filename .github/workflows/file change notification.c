name: file change notification

on:
  schedule:
    # 改.yml恢复自动运行
    # 每 5 分钟一次（GitHub Actions 使用 UTC）
    - cron: '*/5 * * * *'
  workflow_dispatch: {}

permissions:
  contents: write

jobs:
  check-and-send:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository (allow pushing)
        uses: actions/checkout@v4
        with:
          persist-credentials: true

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install requests pycryptodome

      - name: Compare remote sha, decrypt token, send GET and update sha
        env:
          GE_URL: ${{ secrets.GE_URL }}
          BE_GET: ${{ secrets.BE_GET }}
          BE_HOST: ${{ secrets.BE_HOST }}
          BE_AU: ${{ secrets.BE_AU }}
          BE_AC: ${{ secrets.BE_AC }}
          BE_UA: ${{ secrets.BE_UA }}
          BE_V: ${{ secrets.BE_V }}
          BE_K: ${{ secrets.BE_K }}
        run: |
          python - <<'PY'
          import os, sys, subprocess, base64, time, shlex
          import requests
          from Crypto.Cipher import AES

          # --- envs ---
          GE_URL = os.getenv('GE_URL')
          BE_GET = os.getenv('BE_GET')
          BE_HOST = os.getenv('BE_HOST','').strip()
          BE_AU = os.getenv('BE_AU','').strip()
          BE_AC = os.getenv('BE_AC','').strip()
          BE_UA = os.getenv('BE_UA','').strip()
          BE_V = os.getenv('BE_V')
          BE_K = os.getenv('BE_K')

          if not GE_URL or not BE_GET:
              print('ERROR: GE_URL and BE_GET must be set', file=sys.stderr); sys.exit(1)

          # --- helper to get sha via curl ---
          def get_remote_sha():
              # 使用 cut 而不是 awk，避免大括号转义问题
              cmd_str = f"curl -sSL {shlex.quote(GE_URL)} | sha256sum | cut -d ' ' -f1"
              p = subprocess.run(["bash","-lc", cmd_str], capture_output=True, text=True)
              if p.returncode != 0:
                  raise RuntimeError('curl/sha256sum failed: ' + p.stderr.strip())
              return p.stdout.strip().lower()

          # --- 第一次取远端 sha ---
          try:
              remote_sha = get_remote_sha()
              if not remote_sha:
                  raise RuntimeError('empty remote sha')
          except Exception as e:
              print('ERROR: failed to get remote sha:', e, file=sys.stderr); sys.exit(1)

          # 读取本地 sha（若存在）
          local_sha = ''
          if os.path.exists('sha'):
              local_sha = open('sha','r',encoding='utf-8').read().strip().lower()

          # 若相同，立即退出（不解密、不发送 GET）
          if local_sha and local_sha == remote_sha:
              print('sha identical; stopping job (no further action).')
              sys.exit(0)

          # --- 走到这里表示需要发送 ---
          # 仅此时才解密 token
          if not os.path.exists('t.c'):
              print('ERROR: t.c not found in repo root', file=sys.stderr); sys.exit(1)
          ct_b64 = open('t.c','r',encoding='utf-8').read().strip()
          try:
              ct = base64.b64decode(ct_b64)
              iv = base64.b64decode(BE_V)
              key = base64.b64decode(BE_K)
          except Exception as e:
              print('ERROR: base64 decode failed:', e, file=sys.stderr); sys.exit(1)
          if len(iv)!=16 or len(key)!=16:
              print('ERROR: expect 16-byte IV and 16-byte Key', file=sys.stderr); sys.exit(1)

          try:
              cipher = AES.new(key, AES.MODE_CBC, iv)
              pt = cipher.decrypt(ct)
              pad = pt[-1]
              if pad<1 or pad>16:
                  raise ValueError('Invalid PKCS#7 padding')
              token = pt[:-pad].decode('utf-8')
          except Exception as e:
              print('ERROR: decryption failed:', e, file=sys.stderr); sys.exit(1)
          print('Token length', len(token))

          # --- 组装 headers（全部来自 secrets）---
          headers = {}
          def parse_header(raw, default_name):
              if not raw:
                  return None, None
              if ':' in raw:
                  k,v = raw.split(':',1)
                  return k.strip(), v.strip()
              return default_name, raw

          k,v = parse_header(BE_HOST, 'Host')
          if k and v: headers[k]=v
          k,v = parse_header(BE_AC, 'Accept')
          if k and v: headers[k]=v
          k,v = parse_header(BE_UA, 'User-Agent')
          if k and v: headers[k]=v

          # Authorization header: `BE_AU` 可以是 'Authorization: Bearer' 或 'Bearer'
          if BE_AU:
              if ':' in BE_AU:
                  aname, aval = BE_AU.split(':',1)
                  aname = aname.strip(); aval = aval.strip()
                  headers[aname] = f"{aval} {token}"
              else:
                  headers['Authorization'] = f"{BE_AU} {token}"
          else:
              headers['Authorization'] = f"Bearer {token}"

          # --- 发送 GET（初始 + 失败重试 2 次，间隔 3 秒）---
          max_attempts = 3
          wait_seconds = 3
          success = False
          last_err = None
          for attempt in range(1, max_attempts+1):
              try:
                  r = requests.get(BE_GET, headers=headers, timeout=15)
                  print('Attempt', attempt, 'HTTP', r.status_code)
                  if r.status_code == 200:
                      success = True
                      break
                  else:
                      last_err = f'HTTP {r.status_code}: {r.text[:300]}'
                      raise RuntimeError(last_err)
              except Exception as e:
                  last_err = str(e)
                  print(f'Attempt {attempt} failed: {e}')
                  if attempt < max_attempts:
                      time.sleep(wait_seconds)
                      continue
                  else:
                      print('All attempts failed, will continue to update sha file', file=sys.stderr)

          # --- 不论成功或失败，都写入最新 remote sha ---
          try:
              new_sha = get_remote_sha()
          except Exception as e:
              print('ERROR: failed to fetch remote sha for writing:', e, file=sys.stderr)
              new_sha = remote_sha

          # 使用 print 写入，避免在 YAML 中出现转义字符导致解析问题
          with open('sha','w',encoding='utf-8') as f:
              print(new_sha, file=f)

          # --- 提交并 push ---
          try:
              subprocess.check_call(['git','config','--global','user.email','github-actions[bot]@users.noreply.github.com'])
              subprocess.check_call(['git','config','--global','user.name','github-actions[bot]'])
              subprocess.check_call(['git','add','sha'])
              try:
                  subprocess.check_call(['git','commit','-m','Update remote file sha'])
              except subprocess.CalledProcessError:
                  print('No changes to commit (sha unchanged).')
              else:
                  subprocess.check_call(['git','push','origin','HEAD'])
          except Exception as e:
              print('WARNING: git commit/push failed:', e, file=sys.stderr)

          if success:
              print('GET request succeeded')
              sys.exit(0)
          else:
              print('GET request failed after retries:', last_err, file=sys.stderr)
              sys.exit(1)
          PY
