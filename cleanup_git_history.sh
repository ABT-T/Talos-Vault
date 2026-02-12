#!/bin/bash
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================================"
echo -e "   Talos-Vault — Git History Security Cleanup"
echo -e "======================================================${NC}"
echo ""

if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    echo -e "${RED}ERROR: این اسکریپت باید داخل root ریپازیتوری اجرا بشه.${NC}"
    exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

echo -e "${YELLOW}⚠️  هشدار: این عملیات تاریخچه‌ی git را بازنویسی می‌کند.${NC}"
echo ""
read -p "آیا می‌خواهید ادامه دهید؟ (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "عملیات لغو شد."
    exit 0
fi

SENSITIVE_FILES=(
    "certs/ca-key.pem"
    "certs/server-key.pem"
    "certs/client-key.pem"
    "talos.db"
    "certs/server.csr"
    "certs/client.csr"
    "certs/ca-cert.srl"
)

echo -e "${BLUE}📋 فایل‌های زیر از تمام تاریخچه حذف خواهند شد:${NC}"
for f in "${SENSITIVE_FILES[@]}"; do
    echo "   - $f"
done
echo ""

echo -e "${BLUE}🔧 در حال پاکسازی تاریخچه...${NC}"

git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch certs/ca-key.pem certs/server-key.pem certs/client-key.pem talos.db certs/server.csr certs/client.csr certs/ca-cert.srl' \
  --prune-empty --tag-name-filter cat -- --all

echo -e "${BLUE}🧹 پاکسازی refs و garbage collection...${NC}"
git for-each-ref --format='%(refname)' refs/original/ | xargs -r git update-ref -d
git reflog expire --expire=now --all
git gc --prune=now --aggressive

echo -e "${GREEN}✅ تمام فایل‌های حساس از تاریخچه حذف شدند.${NC}"
echo ""
echo -e "${YELLOW}📌 مراحل بعدی:${NC}"
echo "  1. ./tools/gen_certs_secure.sh"
echo "  2. git push origin --force --all"
echo "  3. git push origin --force --tags"
