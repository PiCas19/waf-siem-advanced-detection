# Archive Directory

This directory contains legacy/obsolete files that are no longer used in the current WAF implementation.

## Legacy Configuration Files (legacy-configs/)

The YAML configuration files in `legacy-configs/` directory were used in an older version of the WAF system.

**These files are now OBSOLETE and not used.**

### Old System (Deprecated)
- Configuration via YAML files (rules.yaml, owasp-crs-rules.yaml, etc.)
- Static rule definitions
- No real-time updates
- Located in: `waf/configs/`

### Current System (Active)

The current WAF implementation uses a **Dual-Layer Architecture**:

#### Layer 1: Coraza WAF (OWASP ModSecurity Core Rule Set)
- Configuration: `/etc/caddy/waf/coraza.conf`
- 200+ OWASP CRS v4.0 rules
- Custom protection rules for Finance, Industrial, Dashboard
- File location: `waf/coraza.conf`

#### Layer 2: Custom WAF (Business Logic & IP Intelligence)
- Dynamic rules loaded from database via API
- Custom rules managed via Dashboard
- Blocklist/Whitelist IP management
- IP Intelligence (Tailscale, DMZ, HMAC validation)
- API endpoints:
  - `http://localhost:8081/api/waf/custom-rules`
  - `http://localhost:8081/api/waf/blocklist`
  - `http://localhost:8081/api/waf/whitelist`

### Migration Notes

If you need to migrate from the old YAML system:
1. Create custom rules via Dashboard UI
2. Configure Coraza rules in `coraza.conf`
3. Use API endpoints for dynamic rule management

### Deployment

See deployment instructions:
- Quick start: `waf/DUAL-WAF-QUICKSTART.md`
- Full guide: `waf/CORAZA-DEPLOYMENT.md`
- Build script: `waf/build-caddy-coraza.sh`
- Deploy script: `waf/deploy-coraza.sh`

---

**Note:** These legacy files are kept for reference only. Do not use them in production.
