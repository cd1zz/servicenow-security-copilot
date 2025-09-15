# GitHub Actions Workflows

## Secret Scanning (`secret-scan.yml`)

This workflow runs multiple secret scanning tools to prevent accidental credential commits:

- **TruffleHog**: Deep scanning with verification
- **Gitleaks**: Fast regex-based detection  
- **GitHub CodeQL**: Advanced security analysis (if enabled)
- **detect-secrets**: Python-specific secret detection

### Triggers
- Push to main/develop branches
- Pull requests to main
- Weekly scheduled scan (Mondays 9am UTC)

## Function App Build (`build-function-app.yml`)

Automatically builds and packages the function app when changes are made.

### Features
- Creates `function-app-deploy.zip` using your exact build command
- Runs tests if available
- Uploads zip as workflow artifact (30-day retention)
- Creates GitHub Release with zip file (main branch only)
- Comments on PRs with download link

### Triggers
- Push to main branch (with changes in `function-app/` folder)
- Pull requests with function-app changes
- Manual workflow dispatch

### Package Creation
The workflow creates the zip with:
```bash
zip -r ../function-app-deploy.zip . -x "*.git*" "*.venv*" "*.vscode*" "*__pycache__*"
```

### Downloading the Package

#### From GitHub Releases (Main branch builds)
1. Go to Releases page
2. Download `function-app-deploy.zip` from the latest release

#### From Workflow Artifacts (All builds)
1. Go to Actions tab
2. Click on the workflow run
3. Download artifact from the bottom of the page

## Local Testing

Test the zip creation locally:
```bash
cd function-app/
zip -r ../function-app-deploy.zip . -x "*.git*" "*.venv*" "*.vscode*" "*__pycache__*"
```

## Workflow Status Badges

Add these to your main README.md:

```markdown
[![Secret Scanning](https://github.com/YOUR_USERNAME/servicenow-security-copilot/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/YOUR_USERNAME/servicenow-security-copilot/actions/workflows/secret-scan.yml)
[![Build Function App](https://github.com/YOUR_USERNAME/servicenow-security-copilot/actions/workflows/build-function-app.yml/badge.svg)](https://github.com/YOUR_USERNAME/servicenow-security-copilot/actions/workflows/build-function-app.yml)
```

## Notes

- No Azure credentials needed - just builds the package
- Zip files are automatically attached to GitHub Releases
- Each release is tagged as `function-app-{build-number}`
- Artifacts are kept for 30 days