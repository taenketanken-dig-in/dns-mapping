import pydig
import pandas as pd
import re

def main():
    domains_df = pd.read_csv("domains.csv")
    # Create a mapping from domain to rigsmyndighed (can be NaN or empty)
    rigsmyndighed_map = domains_df.set_index("domain")["rigsmyndighed"].to_dict()
    domains_to_check = domains_df["domain"].tolist()
    results = []

    for domain in domains_to_check:
        try:
            rigsmyndighed = rigsmyndighed_map.get(domain, None)
            mx_records_raw = pydig.query(domain, 'MX')
            mx_tuples = []
            for mx in mx_records_raw:
                parts = mx.strip().split()
                if len(parts) == 2 and parts[0].isdigit():
                    priority = int(parts[0])
                    host = parts[1]
                    mx_tuples.append((priority, host))
            mx_tuples.sort(key=lambda x: x[0])
            mx_records = mx_tuples[0][1] if mx_tuples else ""
            txt_records = pydig.query(domain, 'TXT')
            spf_records = []
            ip4_records = []
            include_records = []
            for record in txt_records:
                clean = record.strip('"')
                if clean.lower().startswith("v=spf1"):
                    spf_parts = clean.split()
                    for part in spf_parts:
                        if part.startswith("ip4:"):
                            ip4_records.append(part.replace("ip4:", "").strip())
                        elif part.startswith("include:"):
                            include_records.append(part.replace("include:", "").strip())
            spf_records = {
                "ip4": ip4_records,
                "include": include_records
            }
            autodiscover_cname = pydig.query(f"autodiscover.{domain}", 'CNAME')
            autodiscover_records = autodiscover_cname[0].rstrip('.') if autodiscover_cname else ""

            # DKIM patterns for major providers
            dkim_patterns = [
                # Microsoft / Office 365, Yahoo / AOL / Verizon, Other / generic
                "selector1._domainkey.{domain}",  # TXT/CNAME record (default selector 1) - used by multiple providers
                # Microsoft / Office 365
                "selector2._domainkey.{domain}",  # TXT/CNAME record (default selector 2)

                # Google Workspace
                "google._domainkey.{domain}",  # TXT record

                # Zoho Mail / Zoho Campaigns
                "zoho._domainkey.{domain}",  # TXT record
                "custom._domainkey.{domain}",  # CNAME for campaigns
                "zmail._domainkey.{domain}",  # Optional TXT for DKIM

                # Mailgun, Mailchimp / Mandrill
                "k1._domainkey.{domain}",  # TXT/CNAME record - used by Mailgun and Mandrill
                "email._domainkey.{domain}",  # Optional CNAME for tracking

                # SendGrid
                "s1._domainkey.{domain}",  # TXT record
                "a1._domainkey.{domain}",  # Optional CNAME for custom selector
                "a12._domainkey.{domain}",  # Optional CNAME for custom selector
            ]
            dkim_selectors = {}
            for pattern in dkim_patterns:
                selector = pattern.format(domain=domain)
                cname_records = pydig.query(selector, 'CNAME')
                # Only add the selector if CNAME has at least one record
                if cname_records:
                    key = pattern.split('.')[0]  # e.g., "selector1" from "selector1._domainkey.{domain}"
                    dkim_selectors[key] = cname_records

            results.append({
                "domain": domain,
                "rigsmyndighed": rigsmyndighed,
                "MX": mx_records,
                "autodiscover": autodiscover_records,
                "SPF": spf_records,
                "DKIM": dkim_selectors
            })

            print(f"Processed domain: {domain}")
        except Exception as e:
            rigsmyndighed = rigsmyndighed_map.get(domain, None)
            results.append({
                "domain": domain,
                "rigsmyndighed": rigsmyndighed,
                "MX": None,
                "SPF": None,
                "autodiscover": None,
                "DKIM": None,
                "error": str(e)
            })

    print("\nDNS Lookup Results")

    print("-" * 40)
    for result in results:
        domain_str = f"--- | Domain: {result['domain']} |"
        dash_count = 40 - len(domain_str) - 1
        print(domain_str, "-" * dash_count)
        print(result)
        print("-" * 40)

    results_df = pd.DataFrame(results)

    # unfold spf ip4 and include into a column per entry. (ip4_1, ip4_2, ..., include_1, include_2, ...)
    spf_expanded = results_df["SPF"].apply(pd.Series)
    spf_ip4 = spf_expanded["ip4"].apply(pd.Series).add_prefix("spf_ip4_")
    spf_include = spf_expanded["include"].apply(pd.Series).add_prefix("spf_include_")
    results_df = pd.concat([results_df.drop(columns=["SPF"]), spf_ip4, spf_include], axis=1)

    # unfold dkim selectors into a column per selector (dkim_selector1, dkim_selector2, ...) while removing the domain name part

    dkim_expanded = results_df["DKIM"].apply(pd.Series)
    # Use stack().map().unstack() to apply elementwise function (replacement for deprecated applymap)
    dkim_expanded_cleaned = dkim_expanded.stack().map(lambda x: x if pd.isna(x) else [record.rstrip('.') for record in x]).unstack()

    # Clean column names to remove the domain part, e.g., "selector1._domainkey.airgreenland.gl" -> "selector1._domainkey"
    def clean_dkim_col(col):
        return re.sub(r'\._domainkey\..*$', '._domainkey', col)

    dkim_expanded_cleaned.columns = [clean_dkim_col(col) for col in dkim_expanded_cleaned.columns]
    # Convert single-item lists to string, keep None/NaN as is
    def flatten_dkim(val):
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val
    dkim_flattened = dkim_expanded_cleaned.stack().map(flatten_dkim).unstack()
    dkim_columns = dkim_flattened.add_prefix("dkim_")
    results_df = pd.concat([results_df.drop(columns=["DKIM"]), dkim_columns], axis=1)
    
    results_df.to_csv("domain_dns_results.csv", index=False)

    # analyse results. create index (1 per sign) for a mailservice being on microsoft.
    # If MX contains "mail.protection.outlook.com" -> 1 else 0
    results_df["is_microsoft_365"] = results_df["MX"].apply(lambda x: 1 if x and "mail.protection.outlook.com" in x else 0)
    # If autodiscover contains "autodiscover.outlook.com" -> 1 else 0
    results_df["is_microsoft_autodiscover"] = results_df["autodiscover"].apply(lambda x: 1 if x and "autodiscover.outlook.com" in x else 0)
    # if spf domains include spf.protection.outlook.com -> 1 else 0
    results_df["is_microsoft_spf"] = results_df[[col for col in results_df.columns if col.startswith("spf_include_")]].apply(
        lambda row: 1 if any("spf.protection.outlook.com" in str(val) for val in row if pd.notna(val)) else 0, axis=1
    )
    # if dkim includes onmicrosoft.com -> 1 else 0
    results_df["is_microsoft_dkim"] = results_df[[col for col in results_df.columns if col.startswith("dkim_")]].apply(
        lambda row: 1 if any("onmicrosoft.com" in str(val) for val in row if pd.notna(val)) else 0, axis=1
    )

    results_df["microsoft_signs"] = results_df[["is_microsoft_365", "is_microsoft_autodiscover", "is_microsoft_spf", "is_microsoft_dkim"]].sum(axis=1)
    # Print summary results by rigsmyndighed (binary value)
    for rigsmyndighed_value in [0, 1]:
        subset = results_df[results_df["rigsmyndighed"].fillna("") == rigsmyndighed_value]
        print(f"\nMicrosoft Detection Summary for rigsmyndighed = '{rigsmyndighed_value}'")
        print("-" * 40)
        print(f"Total domains checked: {len(subset)}")
        print(f"Domains with Microsoft signs: {subset[subset['microsoft_signs'] > 0].shape[0]}")
        print(f"Domains with 1 Microsoft sign: {subset[subset['microsoft_signs'] == 1].shape[0]}")
        print(f"Domains with 2 Microsoft signs: {subset[subset['microsoft_signs'] == 2].shape[0]}")
        print(f"Domains with 3 Microsoft signs: {subset[subset['microsoft_signs'] == 3].shape[0]}")
        print(f"Domains with all 4 Microsoft signs: {subset[subset['microsoft_signs'] == 4].shape[0]}")
        print("-" * 40)
    results_df.to_csv("analysis_results.csv", index=False)


if __name__ == "__main__":
    main()
