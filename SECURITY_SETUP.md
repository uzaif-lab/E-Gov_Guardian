# 🔒 E-Gov Guardian Security Setup Guide

## ⚠️ CRITICAL: API Key Security

**NEVER commit API keys or sensitive credentials to GitHub!** This guide shows you how to keep your secrets safe.

## 🛡️ Quick Security Checklist

Before pushing to GitHub, ensure:

- [ ] ✅ `.gitignore` exists and excludes `config.yaml`
- [ ] ✅ `config.yaml` contains no real API keys
- [ ] ✅ API keys are stored in environment variables or separate `.env` file
- [ ] ✅ `.env` file is excluded in `.gitignore`
- [ ] ✅ Repository is set to **Private** (recommended)

## 🔧 Secure Setup Methods

### Method 1: Environment Variables (Recommended)

1. **Set Environment Variable:**

   ```bash
   # Windows
   set OPENAI_API_KEY=your_actual_api_key_here

   # Linux/Mac
   export OPENAI_API_KEY=your_actual_api_key_here
   ```

2. **Update your config.yaml:**

   ```yaml
   ai_analysis:
     openai_api_key: "YOUR_OPENAI_API_KEY_HERE" # This will be ignored
   ```

3. **The scanner will automatically use the environment variable!**

### Method 2: .env File

1. **Copy the template:**

   ```bash
   cp env.template .env
   ```

2. **Edit .env with your real API key:**

   ```bash
   OPENAI_API_KEY=sk-proj-your_actual_api_key_here
   ```

3. **Install python-dotenv (if not already installed):**

   ```bash
   pip install python-dotenv
   ```

4. **The .env file is automatically excluded from Git!**

## 🚨 Security Verification

Run this to check your security setup:

```bash
# Check what files would be committed
git status

# Verify sensitive files are ignored
git check-ignore config.yaml .env
```

**If `config.yaml` or `.env` appear in `git status`, they are NOT secure!**

## 🔐 Additional Security Measures

### 1. Repository Visibility

- Set your GitHub repository to **Private**
- Only add trusted collaborators
- Use GitHub's secret management for CI/CD

### 2. API Key Rotation

- Regularly rotate your OpenAI API keys
- Monitor usage on OpenAI dashboard
- Set spending limits

### 3. Production Deployment

For production servers:

```bash
# Use environment variables
export OPENAI_API_KEY="your_key"
export FLASK_ENV="production"
export FLASK_DEBUG="False"

# Never use config files with real secrets in production
```

## 📋 Files Created for Security

| File                   | Purpose                        | Safe for GitHub? |
| ---------------------- | ------------------------------ | ---------------- |
| `.gitignore`           | Excludes sensitive files       | ✅ YES           |
| `config.template.yaml` | Template without secrets       | ✅ YES           |
| `env.template`         | Environment variables template | ✅ YES           |
| `SECURITY_SETUP.md`    | This guide                     | ✅ YES           |
| `config.yaml`          | Contains real API keys         | ❌ NO - EXCLUDED |
| `.env`                 | Contains real API keys         | ❌ NO - EXCLUDED |

## 🎯 What to Commit to GitHub

**SAFE to commit:**

- All source code files (`.py`)
- Templates (`config.template.yaml`, `env.template`)
- Documentation (`.md` files)
- Requirements (`requirements.txt`)
- `.gitignore`

**NEVER commit:**

- `config.yaml` (contains real API keys)
- `.env` (contains real API keys)
- Any file with actual secrets

## 🚀 Deployment Workflow

1. **Development:**

   - Use `config.yaml` with real API keys locally
   - Never commit this file

2. **GitHub:**

   - Commit only templates and code
   - Use repository secrets for CI/CD

3. **Production:**
   - Use environment variables
   - Never store secrets in files

## 🆘 Emergency: API Key Exposed

If you accidentally commit an API key:

1. **Immediately revoke the key:** https://platform.openai.com/api-keys
2. **Generate a new API key**
3. **Update your local configuration**
4. **Remove the key from Git history:**
   ```bash
   git filter-branch --force --index-filter \
   'git rm --cached --ignore-unmatch config.yaml' \
   --prune-empty --tag-name-filter cat -- --all
   ```

## 🎉 You're Secure!

With this setup:

- ✅ Your API keys are protected
- ✅ Your code can be safely shared on GitHub
- ✅ The scanner will work for other users with their own API keys
- ✅ No sensitive data will be exposed

**Happy secure coding! 🛡️**
