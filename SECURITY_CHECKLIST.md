# Security Checklist for Public Release

This checklist ensures the LADON repository is safe for public release without exposing sensitive data.

## ✅ Completed Security Tasks

### 1. API Keys and Secrets Removed
- [x] Deleted `/services/collection/.env` containing real API keys
- [x] Verified `.gitignore` includes `.env` files
- [x] Confirmed `.env.example` contains only placeholders
- [x] No hardcoded secrets in Python files
- [x] No hardcoded secrets in YAML/JSON files

### 2. Credentials and Keys
- [x] No `.pem` files committed
- [x] No `.key` files committed
- [x] No `credentials.json` files committed
- [x] No private keys in repository

### 3. Project Renaming
- [x] Renamed "XDR" to "LADON" in all files
- [x] Renamed `threat_xdr_project_plan.md` to `ladon_project_plan.md`
- [x] Updated all references to project plan filename
- [x] Fixed double "LADON LADON" references

### 4. Git History
- [ ] **CRITICAL**: Check git history for committed secrets
- [ ] If secrets found in history, use BFG Repo-Cleaner or `git filter-branch`

---

## 🔍 Manual Verification Steps

Before making the repo public, manually verify:

### Step 1: Search for Sensitive Patterns

```bash
# Search for potential API keys (long alphanumeric strings)
grep -r -E "['\"][a-zA-Z0-9]{32,}['\"]" \
  --include="*.py" --include="*.yaml" --include="*.json" \
  --exclude-dir=".git" --exclude-dir="venv" \
  | grep -v -i "example\|placeholder\|your_"

# Search for IP addresses that might be internal
grep -r -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
  --include="*.py" --include="*.yaml" --include="*.md" \
  --exclude-dir=".git" --exclude-dir="venv" \
  | grep -v "0.0.0.0\|127.0.0.1\|example\|192.0.2\|10.1.2.3"

# Search for email addresses that might be personal
grep -r -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" \
  --include="*.py" --include="*.yaml" --include="*.md" \
  --exclude-dir=".git" --exclude-dir="venv" \
  | grep -v "example.com\|company.com\|noreply"
```

### Step 2: Check Git History for Secrets

```bash
# Install gitleaks (if not already installed)
# brew install gitleaks  # macOS
# or download from https://github.com/zricethezav/gitleaks

# Scan git history for secrets
gitleaks detect --source . --verbose

# If you don't have gitleaks, manually check:
git log -p | grep -i -E "(api[_-]?key|password|secret|token)" | head -50
```

### Step 3: Review Configuration Files

Manually review these files for any sensitive data:
- [ ] `services/collection/config/config.example.yaml`
- [ ] `services/collection/.env.example`
- [ ] `docker-compose.example.yml`
- [ ] All `k8s/*.yaml` files
- [ ] All `secrets/*.yaml.template` files

### Step 4: Check for Commented-Out Credentials

```bash
# Search for commented credentials
grep -r "# .*api.*key\|# .*password\|# .*secret" \
  --include="*.py" --include="*.yaml" \
  --exclude-dir=".git" --exclude-dir="venv"
```

---

## ⚠️ Critical: Rotate Exposed API Keys

If the `.env` file with real API keys was ever committed to git, **you must rotate those keys immediately**:

### AlienVault OTX
1. Log in to https://otx.alienvault.com/
2. Go to Settings → API Key
3. Generate a new API key
4. Update your local `.env` file (not committed)

### Abuse.ch
1. Contact Abuse.ch support
2. Request new authentication key
3. Update your local `.env` file (not committed)

### MISP
1. Log in to your MISP instance
2. Go to Event Actions → Automation
3. Generate new authentication key
4. Update your local `.env` file (not committed)

### Trino
1. Contact Trino administrator
2. Change your password
3. Update your local `.env` file (not committed)

---

## 📋 .gitignore Verification

Ensure `.gitignore` includes these patterns:

```gitignore
# Environment variables
.env
.env.local
.env.*.local

# GCP Credentials
*.json.key
service-account*.json
credentials.json

# Secrets
secrets/
*.pem
*.key
*.crt
*.p12
*.pfx

# Terraform sensitive files
*.tfstate
*.tfstate.*
*.tfvars
!*.tfvars.example
```

---

## 🧹 Clean Git History (If Needed)

If secrets were ever committed to git history:

### Option 1: Using BFG Repo-Cleaner (Recommended)

```bash
# Install BFG
brew install bfg  # macOS

# Create a fresh clone
git clone --mirror git@github.com:username/ladon.git

# Remove .env files from history
bfg --delete-files .env ladon.git

# Clean up
cd ladon.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push (DESTRUCTIVE)
git push --force
```

### Option 2: Using git filter-branch

```bash
# Remove .env from all commits
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch services/collection/.env" \
  --prune-empty --tag-name-filter cat -- --all

# Force push (DESTRUCTIVE)
git push origin --force --all
```

**⚠️ WARNING**: This rewrites git history. Notify all collaborators.

---

## 📄 Files Safe for Public Release

These files are safe and contain only examples/placeholders:

### Configuration Examples
- [x] `services/collection/config/config.example.yaml`
- [x] `services/collection/.env.example`
- [x] `services/collection/docker-compose.example.yml`

### Template Files
- [x] `services/collection/k8s/secret.yaml.template`
- [x] All `*.example` files

### Documentation
- [x] All `*.md` files
- [x] All `README.md` files
- [x] `CLAUDE.md`
- [x] Architecture diagrams

---

## 🚀 Final Steps Before Public Release

1. [ ] Run all verification commands above
2. [ ] Manually review flagged files
3. [ ] Rotate any exposed API keys
4. [ ] Clean git history if secrets were committed
5. [ ] Test that the repo works without sensitive data:
   ```bash
   git clone YOUR_REPO /tmp/test-repo
   cd /tmp/test-repo
   # Try to run tests, build containers, etc.
   ```
6. [ ] Update README with:
   - [ ] Setup instructions (how to get API keys)
   - [ ] `.env` file instructions (copy from .env.example)
   - [ ] License information
   - [ ] Contributing guidelines
7. [ ] Add LICENSE file (MIT, Apache 2.0, etc.)
8. [ ] Add CONTRIBUTING.md
9. [ ] Add CODE_OF_CONDUCT.md (optional)
10. [ ] Make repository public on GitHub/GitLab

---

## 📝 Recommended README Additions

Add these sections to your main README:

### Setup Instructions
```markdown
## Setup

### Prerequisites
- Python 3.11+
- Docker and Docker Compose
- Google Cloud SDK
- Kubernetes cluster (GKE)

### Getting API Keys

**AlienVault OTX:**
1. Sign up at https://otx.alienvault.com/
2. Go to Settings → API Key
3. Copy your API key

**Abuse.ch:**
Follow instructions at https://abuse.ch/

**MISP:**
Contact your MISP administrator for an API key.

### Configuration

1. Copy environment template:
   ```bash
   cp services/collection/.env.example services/collection/.env
   ```

2. Update `.env` with your API keys

3. Never commit `.env` files to git
```

---

## ✅ Post-Publication Checklist

After making the repo public:

1. [ ] Monitor GitHub security alerts
2. [ ] Enable Dependabot for dependency updates
3. [ ] Set up branch protection rules
4. [ ] Enable "Secret scanning" in GitHub settings
5. [ ] Add security policy: `SECURITY.md`
6. [ ] Set up automated security scanning (e.g., Snyk, GitGuardian)

---

## 🔐 Security Policy Template

Create `SECURITY.md`:

```markdown
# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please email security@yourdomain.com.

Do NOT open a public issue for security vulnerabilities.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Security Best Practices

- Never commit API keys or credentials
- Use Secret Manager for production secrets
- Rotate API keys regularly
- Use Workload Identity in GKE (no service account keys)
```

---

## 📞 Questions?

If you're unsure about any file, **don't publish it**. When in doubt:
1. Review the file manually
2. Ask team members
3. Use `gitleaks` or similar tools
4. Check with security team

**Better safe than sorry!** 🔒
