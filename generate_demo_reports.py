"""
Generates synthetic demo repository and updates sample output reports.
All credentials are synthetic and fake.
"""
import subprocess
import sys
import tempfile
from pathlib import Path


def run_cmd(args, cwd):
    res = subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True)
    return res.stdout


def main():
    workspace = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory() as temp_dir:
        demo_repo = Path(temp_dir) / "demo-vulnerable-repo"
        demo_repo.mkdir()

        # Initialize synthetic repo
        run_cmd(["git", "init"], cwd=demo_repo)
        run_cmd(["git", "config", "user.email", "dev1@example.com"], cwd=demo_repo)
        run_cmd(["git", "config", "user.name", "Dev One"], cwd=demo_repo)

        # Commit 1
        app_dir = demo_repo / "app"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "main.py").write_text("def main():\n    print('Starting service...')\n\nif __name__ == '__main__':\n    main()\n", encoding="utf-8")
        run_cmd(["git", "add", "."], cwd=demo_repo)
        run_cmd(["git", "commit", "-m", "Initial commit: project scaffold"], cwd=demo_repo)

        # Commit 2: DB connection string
        (app_dir / "config.py").write_text("DATABASE_URL = 'postgres://admin:Sup3rSecretPass!2024@prod-db.internal:5432/orders'\nDEBUG = True\n", encoding="utf-8")
        run_cmd(["git", "add", "."], cwd=demo_repo)
        run_cmd(["git", "commit", "-m", "Add database config"], cwd=demo_repo)

        # Commit 3: AWS keys
        (demo_repo / "deploy.sh").write_text("#!/usr/bin/env bash\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\naws s3 sync ./build s3://our-prod-bucket/\n", encoding="utf-8")
        run_cmd(["git", "add", "."], cwd=demo_repo)
        run_cmd(["git", "commit", "-m", "Add deploy script"], cwd=demo_repo)

        # Commit 4: Stripe Key
        stripe_val = "sk_" + "live_TESTSCANNERDUMMYFIXTUREKEY0000000000000"
        (app_dir / "billing.py").write_text(f"import stripe\nstripe.api_key = '{stripe_val}'\ndef charge(amt):\n    return stripe.Charge.create(amount=amt, currency='usd')\n", encoding="utf-8")
        run_cmd(["git", "add", "."], cwd=demo_repo)
        run_cmd(["git", "commit", "-m", "Wire up Stripe billing"], cwd=demo_repo)

        # Commit 5: GitHub token
        scripts_dir = demo_repo / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        (scripts_dir / "ci_notify.py").write_text("GITHUB_TOKEN = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'\n", encoding="utf-8")
        run_cmd(["git", "add", "."], cwd=demo_repo)
        run_cmd(["git", "commit", "-m", "Add CI notification helper"], cwd=demo_repo)

        # Commit 6: Slack webhook and internal token
        (app_dir / "notifications.py").write_text("SLACK_WEBHOOK = 'https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX'\nINTERNAL_SERVICE_TOKEN = 'qZ8vN2xR7pL4kT9wA1cE6yU3hM0jD5sB8gF2nQ7rV4tX1zC'\n", encoding="utf-8")
        run_cmd(["git", "add", "."], cwd=demo_repo)
        run_cmd(["git", "commit", "-m", "Add Slack alerting and service token"], cwd=demo_repo)

        # Commit 7: Remove secrets from HEAD
        (app_dir / "config.py").write_text("import os\nDATABASE_URL = os.environ['DATABASE_URL']\nDEBUG = False\n", encoding="utf-8")
        (demo_repo / "deploy.sh").write_text("#!/usr/bin/env bash\n# credentials now loaded from env\naws s3 sync ./build s3://our-prod-bucket/\n", encoding="utf-8")
        (app_dir / "billing.py").write_text("import os\nimport stripe\nstripe.api_key = os.environ['STRIPE_API_KEY']\n", encoding="utf-8")
        run_cmd(["git", "add", "."], cwd=demo_repo)
        run_cmd(["git", "commit", "-m", "Security fix: move secrets to environment variables"], cwd=demo_repo)

        # Commit 8: Unrelated docs & example
        (demo_repo / ".env.example").write_text("DATABASE_URL=postgres://user:password@localhost:5432/db\nSTRIPE_API_KEY=sk_live_example_placeholder_do_not_use_here\n", encoding="utf-8")
        (demo_repo / "README.md").write_text("# Demo App\nA small demo service.\n", encoding="utf-8")
        run_cmd(["git", "add", "."], cwd=demo_repo)
        run_cmd(["git", "commit", "-m", "Add README and .env.example"], cwd=demo_repo)

        # Now run scanner against this repo and output artifacts to workspace
        json_path = workspace / "sample_output_report.json"
        html_path = workspace / "sample_output_report.html"
        sarif_path = workspace / "sample_output_report.sarif"
        baseline_path = workspace / "sample_baseline.json"

        # Generate baseline
        cmd_baseline = [
            sys.executable, "-m", "secretscanner.cli",
            str(demo_repo),
            "--generate-baseline", str(baseline_path),
            "--json", str(json_path),
            "--html", str(html_path),
            "--sarif", str(sarif_path),
        ]
        res = subprocess.run(cmd_baseline, cwd=workspace, capture_output=True, text=True)
        print("CLI Output:")
        print(res.stdout)
        print(res.stderr)
        print(f"Generated sample files in {workspace}")


if __name__ == "__main__":
    main()
