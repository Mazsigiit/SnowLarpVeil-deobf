# SnowLarpVeil-deobf
Nig

```bash
python3 snowveil_deobfuscator.py input.lua -o recovered.lua
```

Export the reconstructed program and optional analysis files:

```bash
python3 snowveil_deobfuscator.py input.lua \
  -o recovered.lua \
  --simplified simplified.lua \
  --report analysis.json \
  --disassembly disassembly.txt \
  --dump-dir decoded
```

| Option | Output |
| --- | --- |
| `-o`, `--output` | Structured Lua reconstruction |
| `--simplified` | Lua containing statically resolved external calls |
| `--report` | JSON with constants, instructions, checksums, and the symbolic trace |
| `--disassembly` | Human-readable VM instruction listing |
| `--dump-dir` | Decrypted constant pools and prototype binaries |

When `-o` is omitted, the output is written beside the input using the suffix `.deobfuscated.lua`.
