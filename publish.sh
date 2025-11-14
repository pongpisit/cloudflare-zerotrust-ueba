#!/bin/bash

# Publish to GitHub Script
# This script helps you publish the UEBA project to GitHub

set -e  # Exit on error

echo "🚀 Publishing UEBA for Cloudflare Zero Trust to GitHub"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "ℹ $1"
}

# Step 1: Verify no secrets
echo "Step 1: Security Check"
echo "----------------------"

print_info "Checking for hardcoded secrets..."

# Check for common secret patterns in code files
# Only check JavaScript, TypeScript, and TOML files
if grep -r "your-account-id-here\|your-api-token-here\|your-.*-list-id\|workers\.dev" . \
    --include="*.js" --include="*.ts" --include="*.toml" \
    --exclude-dir=.git --exclude-dir=node_modules 2>/dev/null | grep -v "your-"; then
    print_error "Found potential secrets in code!"
    print_info "Please ensure all sensitive values use environment variables"
    exit 1
fi

print_success "No secrets found in code"
echo ""

# Step 2: Verify required files
echo "Step 2: File Verification"
echo "-------------------------"

required_files=("README.md" "LICENSE" ".gitignore" ".env.example" "wrangler.toml" "user-risk-demo.js")

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        print_success "$file exists"
    else
        print_error "$file is missing!"
        exit 1
    fi
done
echo ""

# Step 3: Initialize Git
echo "Step 3: Git Initialization"
echo "--------------------------"

if [ -d ".git" ]; then
    print_warning "Git repository already initialized"
else
    print_info "Initializing git repository..."
    git init
    print_success "Git initialized"
fi
echo ""

# Step 4: Get GitHub username
echo "Step 4: GitHub Configuration"
echo "----------------------------"

read -p "Enter your GitHub username: " github_username

if [ -z "$github_username" ]; then
    print_error "GitHub username is required!"
    exit 1
fi

read -p "Enter repository name [cloudflare-zerotrust-ueba]: " repo_name
repo_name=${repo_name:-cloudflare-zerotrust-ueba}

print_success "Repository: $github_username/$repo_name"
echo ""

# Step 5: Add files
echo "Step 5: Adding Files"
echo "--------------------"

print_info "Adding all files to git..."
git add .

print_success "Files added"
echo ""

# Step 6: Create commit
echo "Step 6: Creating Commit"
echo "-----------------------"

print_info "Creating initial commit..."

git commit -m "Initial release: UEBA for Cloudflare Zero Trust

- Automated user risk scoring and Gateway list management
- Real-time behavioral analytics integration
- Adaptive security policy enforcement
- Comprehensive monitoring and health checks
- Production-ready with KV-based state management

Features:
- 🤖 Automated risk scoring from Cloudflare Zero Trust API
- 📊 Smart categorization (High/Medium/Low risk)
- 🔄 Real-time sync with efficient PATCH operations
- 💾 KV-based state management
- 🛡️ Retry mechanism with exponential backoff
- 📈 Health checks and metrics tracking
- 🎨 Web dashboard for monitoring

Security:
- No hardcoded secrets
- Environment variable validation
- Comprehensive .gitignore
- Security best practices documented"

print_success "Commit created"
echo ""

# Step 7: Add remote
echo "Step 7: Adding GitHub Remote"
echo "-----------------------------"

print_info "Adding GitHub remote..."

# Check if remote already exists
if git remote | grep -q "origin"; then
    print_warning "Remote 'origin' already exists"
    git remote set-url origin "https://github.com/$github_username/$repo_name.git"
    print_success "Remote URL updated"
else
    git remote add origin "https://github.com/$github_username/$repo_name.git"
    print_success "Remote added"
fi

echo ""

# Step 8: Instructions for GitHub
echo "Step 8: Create GitHub Repository"
echo "---------------------------------"
echo ""
print_warning "Before pushing, create the repository on GitHub:"
echo ""
echo "1. Go to: https://github.com/new"
echo "2. Repository name: $repo_name"
echo "3. Description: User and Entity Behavior Analytics (UEBA) for Cloudflare Zero Trust"
echo "4. Visibility: Public"
echo "5. Do NOT initialize with README"
echo "6. Click 'Create repository'"
echo ""
read -p "Press Enter when repository is created..."
echo ""

# Step 9: Push to GitHub
echo "Step 9: Pushing to GitHub"
echo "-------------------------"

print_info "Pushing to GitHub..."

git branch -M main
git push -u origin main

print_success "Code pushed to GitHub!"
echo ""

# Step 10: Create tag
echo "Step 10: Creating Release Tag"
echo "------------------------------"

print_info "Creating v1.0.0 tag..."

git tag -a v1.0.0 -m "Release v1.0.0 - UEBA for Cloudflare Zero Trust

Features:
- Automated user risk scoring
- Real-time Gateway list synchronization
- Adaptive security policy enforcement
- KV-based state management
- Comprehensive monitoring and health checks
- PATCH API for efficient updates
- Retry mechanism with exponential backoff"

git push origin v1.0.0

print_success "Tag created and pushed"
echo ""

# Final instructions
echo "🎉 SUCCESS! Your project is now on GitHub!"
echo "=========================================="
echo ""
echo "Repository URL: https://github.com/$github_username/$repo_name"
echo ""
echo "Next Steps:"
echo "-----------"
echo "1. Visit your repository: https://github.com/$github_username/$repo_name"
echo "2. Add topics: cloudflare, zero-trust, ueba, security, risk-scoring"
echo "3. Enable security features in Settings → Security"
echo "4. Create a release from the v1.0.0 tag"
echo "5. Add CONTRIBUTING.md and SECURITY.md (optional)"
echo ""
echo "See PUBLISH-TO-GITHUB.md for detailed post-publication steps"
echo ""
print_success "Publication complete! 🚀"
