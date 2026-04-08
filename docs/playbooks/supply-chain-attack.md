# Playbook: Supply Chain Attack

## Detection
- Package filter blocks known malicious packages (80+ known, typosquat detection)
- SCA scanner (npm audit) finds critical vulnerability in dependency
- Pre-deploy gate blocks deployment with critical SCA finding
- AlertManager fires on new critical vulnerability

## Triage
1. Identify the blocked/vulnerable package
2. Check if it's a typosquat (Levenshtein distance < 2 from popular package)
3. Check npm registry for package age and download count
4. Review dependency tree for transitive vulnerabilities

## Response
1. **Automated**: Package filter blocks installation immediately
2. **Automated**: Pre-deploy gate prevents deployment with vuln deps
3. **Manual**: Review if package was already installed before filter
4. **Manual**: Check SBOM for affected components
5. **Manual**: Update to patched version if available

## Commands
```bash
# Test package filter
curl -X POST http://localhost:4100/api/security/test-package \
  -H "Content-Type: application/json" \
  -d '{"command": "npm install crossenv"}'

# Run SCA scan on workspace
curl -X POST http://localhost:4100/api/security/scan/<projectId> \
  -H "Content-Type: application/json" \
  -d '{"sca": true}'

# Generate SBOM
curl http://localhost:4100/api/security/sbom/<projectId> | jq '.components | length'

# Check specific package on npm
npm view <package-name> time dist-tags
```

## Recovery
- Remove malicious package: `npm uninstall <package>`
- Audit remaining dependencies: `npm audit fix`
- Regenerate SBOM after cleanup
- Add package to blocklist if not already covered
