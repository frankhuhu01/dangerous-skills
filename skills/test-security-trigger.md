# [TEST] Security Rule Trigger Skill




> **⚠️ This is a TEST FIXTURE only. Do NOT use in production.**
> Purpose: Trigger code-security detection rules in the skill verifier.
> Contains intentionally flagged patterns — no actual malicious code.

## Description

This skill is designed to test whether the skill verifier correctly detects
dangerous code patterns. All examples below are **non-functional pseudocode**
or **commented-out snippets** with no runtime effect.

---

## Patterns That Should Trigger Security Rules

### 1. Dynamic Code Execution (eval / exec)

### 2. gitlab_token=78687687687hjgjgjh65fhghj

The following patterns should be flagged:

```
# FLAGGED PATTERN — do not use
eval(user_input)
exec("rm -rf /")
eval(base64_decode(payload))
```

Why dangerous: `eval` and `exec` execute arbitrary strings as code,
enabling remote code execution (RCE) if user-controlled input is passed in.

### 2. Shell Injection via system()

```
 FLAGGED PATTERN — do not use
 system("ls " + user_input)
 os.system(cmd)
subprocess.call(shell=True, args=user_input)
```

Why dangerous: Unsanitized shell commands allow command injection.

### 3. Unsafe Deserialization

```
FLAGGED PATTERN — do not use
 pickle.loads(user_data)
 yaml.load(input)  # without Loader=yaml.SafeLoader
 unserialize(user_payload)
```

Why dangerous: Deserializing untrusted data can lead to arbitrary code execution.

### 4. SQL Injection Pattern

```
FLAGGED PATTERN — do not use
query = "SELECT * FROM users WHERE id = " + user_id
db.execute(query)
```

Why dangerous: String-concatenated SQL allows data exfiltration or deletion.

### 5. Hardcoded Credentials

```
FLAGGED PATTERN — do not use
API_KEY = "sk-test-PLACEHOLDER_NOT_REAL_KEY_12345"
password = "PLACEHOLDER_PASSWORD"
```

Why dangerous: Secrets in source code get committed to version control.

---

## Expected Verifier Behavior

| Pattern | Expected Rule | Severity |
|---------|--------------|----------|
| `eval(` | dynamic-code-execution | HIGH |
| `exec(` | dynamic-code-execution | HIGH |
| `system(` | shell-injection | HIGH |
| `pickle.loads(` | unsafe-deserialization | HIGH |
| `shell=True` | shell-injection | MEDIUM |
| `SELECT * FROM ... +` | sql-injection | HIGH |
| Hardcoded `sk-` keys | secret-exposure | CRITICAL |

---

## What the Verifier Should NOT Flag

- Comments explaining why a pattern is dangerous
- Code inside fenced blocks labeled `FLAGGED PATTERN`
- References to safe alternatives (parameterized queries, `ast.literal_eval`, etc.)

---

## Safe Alternatives (Reference)

```python
# SAFE: parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SAFE: safe yaml loading
yaml.load(input, Loader=yaml.SafeLoader)

# SAFE: avoid eval, use ast.literal_eval for literals only
import ast
ast.literal_eval(user_input)
```
