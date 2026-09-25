#!/usr/bin/env bash
# Builds a small synthetic git repo that mimics a realistic developer mistake
# pattern, so the scanner has real commit history to demonstrate against.
# ALL credentials below are FAKE/placeholder values generated for this demo.
set -e

DEMO_DIR="${1:-/home/claude/demo-vulnerable-repo}"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

git init -q
git config user.email "dev1@example.com"
git config user.name "Dev One"

# --- Commit 1: normal project setup ---
mkdir -p app
cat > app/main.py <<'EOF'
def main():
    print("Starting service...")

if __name__ == "__main__":
    main()
EOF
git add . && git commit -q -m "Initial commit: project scaffold"

# --- Commit 2: dev adds DB connection with hardcoded creds "to get it working" ---
cat > app/config.py <<'EOF'
import os

DATABASE_URL = "postgres://admin:Sup3rSecretPass!2024@prod-db.internal:5432/orders"
DEBUG = True
EOF
git add . && git commit -q -m "Add database config"

# --- Commit 3: dev adds an AWS key to a deploy script "temporarily" ---
cat > deploy.sh <<'EOF'
#!/usr/bin/env bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws s3 sync ./build s3://our-prod-bucket/
EOF
git add . && git commit -q -m "Add deploy script"

# --- Commit 4: dev adds a Stripe live key while wiring up billing ---
STRIPE_PREFIX="sk_live"
cat > app/billing.py <<EOF
import stripe

stripe.api_key = "${STRIPE_PREFIX}_TESTSCANNERDUMMYFIXTUREKEY0000000000000"

def charge_customer(amount):
    return stripe.Charge.create(amount=amount, currency="usd")
EOF
git add . && git commit -q -m "Wire up Stripe billing"

# --- Commit 5: dev adds a GitHub token to a CI helper script ---
mkdir -p scripts
cat > scripts/ci_notify.py <<'EOF'
import requests

GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

def notify():
    requests.post(
        "https://api.github.com/repos/acme/app/issues",
        headers={"Authorization": f"token {GITHUB_TOKEN}"},
        json={"title": "Build finished"},
    )
EOF
git add . && git commit -q -m "Add CI notification helper"

# --- Commit 6: a Slack webhook and a homegrown high-entropy internal token ---
cat > app/notifications.py <<'EOF'
SLACK_WEBHOOK = "https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# internal service-to-service auth token (not a recognized vendor format)
INTERNAL_SERVICE_TOKEN = "qZ8vN2xR7pL4kT9wA1cE6yU3hM0jD5sB8gF2nQ7rV4tX1zC"
EOF
git add . && git commit -q -m "Add Slack alerting"

# --- Commit 7: "security fix" - dev removes secrets from current files ---
cat > app/config.py <<'EOF'
import os

DATABASE_URL = os.environ["DATABASE_URL"]
DEBUG = False
EOF
cat > deploy.sh <<'EOF'
#!/usr/bin/env bash
# credentials now loaded from environment / secrets manager
aws s3 sync ./build s3://our-prod-bucket/
EOF
cat > app/billing.py <<'EOF'
import stripe
import os

stripe.api_key = os.environ["STRIPE_API_KEY"]

def charge_customer(amount):
    return stripe.Charge.create(amount=amount, currency="usd")
EOF
git add . && git commit -q -m "Security fix: move secrets to environment variables"

# --- Commit 8: unrelated feature work, an .env.example (should be ignored) ---
cat > .env.example <<'EOF'
DATABASE_URL=postgres://user:password@localhost:5432/db
STRIPE_API_KEY=sk_live_example_placeholder_do_not_use_here
EOF
cat > README.md <<'EOF'
# Demo App
A small demo service. See .env.example for required environment variables.
EOF
git add . && git commit -q -m "Add README and .env.example"

echo "Demo repo built at $DEMO_DIR"
echo "Commits: $(git log --oneline | wc -l)"
