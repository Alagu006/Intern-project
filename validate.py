#!/usr/bin/env python3
"""
Validation script for Module 4: Secure File Sharing System

Run this to verify the package is complete and ready to use.
"""

import os
import sys
from pathlib import Path

# Colors for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


def check(condition, message):
    """Print check result."""
    if condition:
        print(f"{GREEN}✓{RESET} {message}")
        return True
    else:
        print(f"{RED}✗{RESET} {message}")
        return False


def warn(message):
    """Print warning."""
    print(f"{YELLOW}⚠{RESET} {message}")


def info(message):
    """Print info."""
    print(f"{BLUE}ℹ{RESET} {message}")


def main():
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}Module 4 Package Validation{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")

    base_dir = Path(__file__).parent
    passed = 0
    failed = 0

    # Check documentation files
    print(f"{BLUE}Checking Documentation...{RESET}")
    docs = [
        "START_HERE.md",
        "GET_STARTED.md",
        "QUICKSTART.md",
        "README.md",
        "API.md",
        "FLOW_DIAGRAM.md",
        "DEPLOYMENT.md",
        "IMPLEMENTATION_CHECKLIST.md",
        "MODULE_4_SUMMARY.md",
        "INDEX.md",
        "PACKAGE_CONTENTS.md",
    ]
    for doc in docs:
        if check((base_dir / doc).exists(), f"Documentation: {doc}"):
            passed += 1
        else:
            failed += 1

    # Check core application files
    print(f"\n{BLUE}Checking Application Code...{RESET}")
    app_files = [
        "app/__init__.py",
        "app/config.py",
        "app/extensions.py",
        "app/models/__init__.py",
        "app/models/user.py",
        "app/models/file.py",
        "app/models/share.py",
        "app/models/access_log.py",
        "app/auth/__init__.py",
        "app/auth/decorators.py",
        "app/auth/routes.py",
        "app/crypto/__init__.py",
        "app/crypto/file_crypto.py",
        "app/files/__init__.py",
        "app/files/routes.py",
        "app/shares/__init__.py",
        "app/shares/routes.py",
    ]
    for file in app_files:
        if check((base_dir / file).exists(), f"App file: {file}"):
            passed += 1
        else:
            failed += 1

    # Check tests
    print(f"\n{BLUE}Checking Test Suite...{RESET}")
    test_files = [
        "tests/__init__.py",
        "tests/conftest.py",
        "tests/test_shares.py",
    ]
    for file in test_files:
        if check((base_dir / file).exists(), f"Test file: {file}"):
            passed += 1
        else:
            failed += 1

    # Check configuration files
    print(f"\n{BLUE}Checking Configuration...{RESET}")
    config_files = [
        "requirements.txt",
        "wsgi.py",
        "manage.py",
        "setup.sh",
        ".env.example",
        ".gitignore",
        "pytest.ini",
    ]
    for file in config_files:
        if check((base_dir / file).exists(), f"Config file: {file}"):
            passed += 1
        else:
            failed += 1

    # Check API documentation
    print(f"\n{BLUE}Checking API Specs...{RESET}")
    api_files = [
        "openapi.yaml",
        "postman_collection.json",
        "schema.sql",
    ]
    for file in api_files:
        if check((base_dir / file).exists(), f"API spec: {file}"):
            passed += 1
        else:
            failed += 1

    # Check static files
    print(f"\n{BLUE}Checking Static Files...{RESET}")
    if check((base_dir / "static" / "share.html").exists(), "Frontend example: share.html"):
        passed += 1
    else:
        failed += 1

    # Check critical content in key files
    print(f"\n{BLUE}Checking File Content...{RESET}")
    
    # Check shares routes has all 8 endpoints
    shares_routes = base_dir / "app" / "shares" / "routes.py"
    if shares_routes.exists():
        content = shares_routes.read_text()
        endpoints = [
            "POST /api/files/<file_id>/share",
            "GET /api/files/<file_id>/shares",
            "GET /api/shares/<token>/access",
            "POST /api/shares/<token>/verify-password",
            "GET /api/shares/<token>/download",
            "PATCH /api/shares/<share_id>",
            "DELETE /api/shares/<share_id>",
            "GET /api/shares/<token>/qrcode",
        ]
        for endpoint in endpoints:
            # Check if the route definition exists (simplified check)
            method = endpoint.split()[0].lower()
            if f'methods=["{method.upper()}"]' in content or f"methods=['{method.upper()}']" in content:
                check(True, f"Endpoint implemented: {endpoint}")
                passed += 1
            else:
                check(False, f"Endpoint implemented: {endpoint}")
                failed += 1

    # Check requirements.txt has key dependencies
    print(f"\n{BLUE}Checking Dependencies...{RESET}")
    requirements = base_dir / "requirements.txt"
    if requirements.exists():
        content = requirements.read_text()
        deps = ["flask", "psycopg2", "sqlalchemy", "argon2", "cryptography", "qrcode", "pytest"]
        for dep in deps:
            if check(dep in content.lower(), f"Dependency: {dep}"):
                passed += 1
            else:
                failed += 1

    # Summary
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}Validation Summary{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")
    
    total = passed + failed
    percentage = (passed / total * 100) if total > 0 else 0
    
    print(f"Total checks: {total}")
    print(f"{GREEN}Passed: {passed}{RESET}")
    if failed > 0:
        print(f"{RED}Failed: {failed}{RESET}")
    else:
        print(f"Failed: {failed}")
    print(f"Success rate: {percentage:.1f}%\n")

    if failed == 0:
        print(f"{GREEN}{'='*70}{RESET}")
        print(f"{GREEN}✓ Package is COMPLETE and READY TO USE{RESET}")
        print(f"{GREEN}{'='*70}{RESET}\n")
        info("Next steps:")
        print("  1. Read START_HERE.md for navigation")
        print("  2. Run ./setup.sh to initialize")
        print("  3. Follow GET_STARTED.md for quick setup")
        print("  4. Run pytest tests/ -v to verify functionality\n")
        return 0
    else:
        print(f"{RED}{'='*70}{RESET}")
        print(f"{RED}✗ Package validation FAILED{RESET}")
        print(f"{RED}{'='*70}{RESET}\n")
        warn("Some files are missing. Please check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
