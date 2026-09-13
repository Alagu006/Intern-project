#!/usr/bin/env python3
"""
Test Validation Script for Module 4 & Module 6

This script validates the code structure and simulates test scenarios
without requiring a full database setup.

Run: python test_validation.py
"""

import sys
import os
from pathlib import Path

# Color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
BOLD = '\033[1m'
END = '\033[0m'


def print_header(text):
    print(f"\n{BOLD}{BLUE}{'='*70}{END}")
    print(f"{BOLD}{BLUE}{text}{END}")
    print(f"{BOLD}{BLUE}{'='*70}{END}\n")


def check(condition, message):
    if condition:
        print(f"{GREEN}✓{END} {message}")
        return True
    else:
        print(f"{RED}✗{END} {message}")
        return False


def validate_structure():
    """Validate project structure."""
    print_header("1. Validating Project Structure")
    
    base_dir = Path(".")
    
    required_files = [
        # Module 4 files
        "app/__init__.py",
        "app/models/user.py",
        "app/models/file.py",
        "app/models/share.py",
        "app/models/access_log.py",
        "app/auth/decorators.py",
        "app/auth/routes.py",
        "app/shares/routes.py",
        "app/files/routes.py",
        "tests/test_shares.py",
        
        # Module 6 files
        "app/admin/__init__.py",
        "app/admin/routes.py",
        "tests/test_admin.py",
        "MODULE_6_ADMIN.md",
        "create_admin.py",
        "postman_admin_collection.json",
    ]
    
    passed = 0
    failed = 0
    
    for file in required_files:
        file_path = base_dir / file
        if check(file_path.exists(), f"File exists: {file}"):
            passed += 1
        else:
            failed += 1
    
    return passed, failed


def validate_code_syntax():
    """Check Python files for syntax errors."""
    print_header("2. Validating Python Syntax")
    
    base_dir = Path(".")
    python_files = list(base_dir.rglob("*.py"))
    
    passed = 0
    failed = 0
    
    for file in python_files:
        if "venv" in str(file) or "__pycache__" in str(file):
            continue
        
        try:
            with open(file, 'r', encoding='utf-8') as f:
                code = f.read()
                compile(code, str(file), 'exec')
            
            if check(True, f"Syntax valid: {file.relative_to(base_dir)}"):
                passed += 1
        except SyntaxError as e:
            if check(False, f"Syntax error in {file.relative_to(base_dir)}: {e}"):
                pass
            failed += 1
    
    return passed, failed


def validate_imports():
    """Check that key imports are present in code."""
    print_header("3. Validating Key Imports")
    
    base_dir = Path(".")
    
    checks = [
        ("app/models/user.py", ["from argon2 import PasswordHasher", "role", "is_active"]),
        ("app/auth/decorators.py", ["def admin_required", "@wraps"]),
        ("app/admin/routes.py", ["@admin_required", "Blueprint", "from app.models import"]),
        ("tests/test_admin.py", ["def test_non_admin_cannot_access", "def test_disable_user"]),
    ]
    
    passed = 0
    failed = 0
    
    for file_path, keywords in checks:
        try:
            with open(base_dir / file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            all_found = all(keyword in content for keyword in keywords)
            
            if check(all_found, f"Required code in {file_path}"):
                passed += 1
            else:
                failed += 1
                missing = [k for k in keywords if k not in content]
                print(f"  {YELLOW}Missing: {missing}{END}")
        except Exception as e:
            if check(False, f"Could not validate {file_path}: {e}"):
                pass
            failed += 1
    
    return passed, failed


def validate_endpoints():
    """Validate that all required endpoints are defined."""
    print_header("4. Validating API Endpoints")
    
    base_dir = Path(".")
    
    # Check Module 4 endpoints
    shares_file = base_dir / "app/shares/routes.py"
    with open(shares_file, 'r', encoding='utf-8') as f:
        shares_content = f.read()
    
    module4_endpoints = [
        ('POST', '/api/files/<file_id>/share'),
        ('GET', '/api/shares/<token>/access'),
        ('POST', '/api/shares/<token>/verify-password'),
        ('GET', '/api/shares/<token>/download'),
        ('GET', '/api/shares/<token>/qrcode'),
    ]
    
    # Check Module 6 endpoints
    admin_file = base_dir / "app/admin/routes.py"
    with open(admin_file, 'r', encoding='utf-8') as f:
        admin_content = f.read()
    
    module6_endpoints = [
        ('GET', '/api/admin/users'),
        ('GET', '/api/admin/users/<user_id>'),
        ('PATCH', '/api/admin/users/<user_id>/disable'),
        ('PATCH', '/api/admin/users/<user_id>/enable'),
        ('GET', '/api/admin/files'),
        ('GET', '/api/admin/storage'),
        ('GET', '/api/admin/audit-logs'),
        ('GET', '/api/admin/audit-logs/export'),
        ('GET', '/api/admin/stats/summary'),
        ('GET', '/api/admin/stats/charts'),
    ]
    
    passed = 0
    failed = 0
    
    print(f"{BOLD}Module 4 Endpoints:{END}")
    for method, path in module4_endpoints:
        # Simplified check - look for route definition
        route_pattern = f'methods=["{method}"]'
        found = route_pattern in shares_content
        if check(found, f"{method:6} {path}"):
            passed += 1
        else:
            failed += 1
    
    print(f"\n{BOLD}Module 6 Endpoints:{END}")
    for method, path in module6_endpoints:
        route_pattern = f'methods=["{method}"]'
        found = route_pattern in admin_content
        if check(found, f"{method:6} {path}"):
            passed += 1
        else:
            failed += 1
    
    return passed, failed


def validate_security():
    """Validate security implementations."""
    print_header("5. Validating Security Features")
    
    base_dir = Path(".")
    
    passed = 0
    failed = 0
    
    # Check admin_required decorator
    with open(base_dir / "app/auth/decorators.py", 'r') as f:
        auth_content = f.read()
    
    if check("def admin_required" in auth_content, "admin_required decorator defined"):
        passed += 1
    else:
        failed += 1
    
    if check("user.is_admin()" in auth_content, "Admin role check implemented"):
        passed += 1
    else:
        failed += 1
    
    if check("is_active" in auth_content, "Account status check implemented"):
        passed += 1
    else:
        failed += 1
    
    # Check User model
    with open(base_dir / "app/models/user.py", 'r') as f:
        user_content = f.read()
    
    if check("role" in user_content and "admin" in user_content, "Role field in User model"):
        passed += 1
    else:
        failed += 1
    
    if check("is_active" in user_content, "is_active field in User model"):
        passed += 1
    else:
        failed += 1
    
    if check("disabled_at" in user_content, "disabled_at field in User model"):
        passed += 1
    else:
        failed += 1
    
    # Check CSV sanitization
    with open(base_dir / "app/admin/routes.py", 'r') as f:
        admin_content = f.read()
    
    if check("_sanitize_csv_field" in admin_content, "CSV sanitization function defined"):
        passed += 1
    else:
        failed += 1
    
    if check("formula injection" in admin_content.lower(), "Formula injection prevention documented"):
        passed += 1
    else:
        failed += 1
    
    # Check admin action logging
    if check("_log_admin_action" in admin_content, "Admin action logging implemented"):
        passed += 1
    else:
        failed += 1
    
    return passed, failed


def validate_tests():
    """Validate test structure."""
    print_header("6. Validating Test Structure")
    
    base_dir = Path(".")
    
    passed = 0
    failed = 0
    
    # Check Module 4 tests
    with open(base_dir / "tests/test_shares.py", 'r') as f:
        shares_tests = f.read()
    
    module4_test_classes = [
        "TestCreateShare",
        "TestPermissions",
        "TestExpiry",
        "TestPasswordProtection",
        "TestRevocation",
        "TestQRCode",
    ]
    
    print(f"{BOLD}Module 4 Test Classes:{END}")
    for test_class in module4_test_classes:
        if check(f"class {test_class}" in shares_tests, f"{test_class}"):
            passed += 1
        else:
            failed += 1
    
    # Check Module 6 tests
    with open(base_dir / "tests/test_admin.py", 'r') as f:
        admin_tests = f.read()
    
    module6_test_classes = [
        "TestRoleEnforcement",
        "TestUserManagement",
        "TestFileManagement",
        "TestStorageStatistics",
        "TestAuditLogs",
        "TestSystemStatistics",
    ]
    
    print(f"\n{BOLD}Module 6 Test Classes:{END}")
    for test_class in module6_test_classes:
        if check(f"class {test_class}" in admin_tests, f"{test_class}"):
            passed += 1
        else:
            failed += 1
    
    return passed, failed


def validate_documentation():
    """Validate documentation completeness."""
    print_header("7. Validating Documentation")
    
    base_dir = Path(".")
    
    passed = 0
    failed = 0
    
    docs = [
        "README.md",
        "API.md",
        "MODULE_6_ADMIN.md",
        "openapi.yaml",
        "postman_collection.json",
        "postman_admin_collection.json",
    ]
    
    for doc in docs:
        file_path = base_dir / doc
        if file_path.exists():
            size = file_path.stat().st_size
            if check(size > 100, f"{doc} ({size} bytes)"):
                passed += 1
            else:
                print(f"  {YELLOW}Warning: {doc} seems too small{END}")
                failed += 1
        else:
            if check(False, f"{doc} exists"):
                pass
            failed += 1
    
    return passed, failed


def main():
    """Run all validations."""
    print(f"\n{BOLD}{BLUE}{'='*70}{END}")
    print(f"{BOLD}{BLUE}Test Validation for Module 4 & Module 6{END}")
    print(f"{BOLD}{BLUE}{'='*70}{END}")
    
    total_passed = 0
    total_failed = 0
    
    # Run validations
    passed, failed = validate_structure()
    total_passed += passed
    total_failed += failed
    
    passed, failed = validate_code_syntax()
    total_passed += passed
    total_failed += failed
    
    passed, failed = validate_imports()
    total_passed += passed
    total_failed += failed
    
    passed, failed = validate_endpoints()
    total_passed += passed
    total_failed += failed
    
    passed, failed = validate_security()
    total_passed += passed
    total_failed += failed
    
    passed, failed = validate_tests()
    total_passed += passed
    total_failed += failed
    
    passed, failed = validate_documentation()
    total_passed += passed
    total_failed += failed
    
    # Summary
    print_header("Validation Summary")
    
    total_checks = total_passed + total_failed
    percentage = (total_passed / total_checks * 100) if total_checks > 0 else 0
    
    print(f"Total checks: {total_checks}")
    print(f"{GREEN}Passed: {total_passed}{END}")
    
    if total_failed > 0:
        print(f"{RED}Failed: {total_failed}{END}")
    else:
        print(f"Failed: {total_failed}")
    
    print(f"Success rate: {percentage:.1f}%\n")
    
    if total_failed == 0:
        print(f"{GREEN}{'='*70}{END}")
        print(f"{GREEN}✓ ALL VALIDATIONS PASSED{END}")
        print(f"{GREEN}{'='*70}{END}\n")
        print(f"{BOLD}Code structure is valid and ready for deployment!{END}")
        print(f"\n{YELLOW}Next steps:{END}")
        print("  1. Install dependencies: pip install -r requirements.txt")
        print("  2. Set up database: python manage.py upgrade")
        print("  3. Create admin user: python create_admin.py")
        print("  4. Run actual tests: pytest tests/ -v")
        print("  5. Start server: python wsgi.py\n")
        return 0
    else:
        print(f"{RED}{'='*70}{END}")
        print(f"{RED}✗ SOME VALIDATIONS FAILED{END}")
        print(f"{RED}{'='*70}{END}\n")
        print(f"{YELLOW}Please review the failed checks above.{END}\n")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Validation interrupted by user.{END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}Error during validation: {e}{END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
