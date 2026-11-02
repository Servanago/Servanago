-- Web application firewall (Coraza + OWASP CRS), per site: the site form's security area.
--   waf            = '' (off) | 'crs' (preset ruleset) | 'custom' (preset plus the admin's own directives)
--   waf_directives = the per-site SecLang tail for 'custom'; '' = none. Validated by the apply path,
--                    never executed from here: this is desired state like snippets, not a rule store.
ALTER TABLE sites ADD COLUMN waf            TEXT NOT NULL DEFAULT '' CHECK (waf IN ('', 'crs', 'custom'));
ALTER TABLE sites ADD COLUMN waf_directives TEXT NOT NULL DEFAULT '';