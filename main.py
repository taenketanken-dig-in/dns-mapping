import pydig
import pandas as pd
import re
from ipwhois import IPWhois

def main():
    # Load domains and create lookup map for rigsmyndighed field
    domains_df = pd.read_csv("domains.csv")
    rigsmyndighed_map = domains_df.set_index("domain")["rigsmyndighed"].to_dict()
    domains_to_check = domains_df["domain"].tolist()
    results = []

    for domain in domains_to_check:
        try:
            rigsmyndighed = rigsmyndighed_map.get(domain, None)
            
            # Parse MX records and extract the highest priority mail server
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
            # Extract SPF records from TXT records
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
            # Lookup country codes for domain's A records using IP geolocation
            a_records = pydig.query(domain, 'A')
            domain_countries = []
            for ip in a_records:
                country_code = None
                try:
                    ipwhois_client = IPWhois(ip, timeout=10)
                    rdap_data = ipwhois_client.lookup_rdap(asn_methods=["whois", "http"])
                    country_code = rdap_data.get("asn_country_code")
                except Exception:
                    country_code = None
                domain_countries.append(country_code)
            
            # Check for autodiscover CNAME record (used by Exchange/Outlook)
            autodiscover_cname = pydig.query(f"autodiscover.{domain}", 'CNAME')
            autodiscover_records = autodiscover_cname[0].rstrip('.') if autodiscover_cname else ""

            # Check for DKIM selectors used by major email providers
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
            # Query each DKIM selector and store results
            dkim_selectors = {}
            for pattern in dkim_patterns:
                selector = pattern.format(domain=domain)
                cname_records = pydig.query(selector, 'CNAME')
                if cname_records:
                    key = pattern.split('.')[0]  # Extract selector name (e.g., "selector1")
                    dkim_selectors[key] = cname_records

            results.append({
                "domain": domain,
                "rigsmyndighed": rigsmyndighed,
                "MX": mx_records,
                "autodiscover": autodiscover_records,
                "SPF": spf_records,
                "domain_countries": domain_countries,
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


    results_df = pd.DataFrame(results)

    # Normalize country codes: single country -> string, multiple -> comma-separated, empty -> None
    if "domain_countries" in results_df.columns:
        def normalize_countries(val):
            if isinstance(val, list):
                vals = [v for v in val if v]
                if len(vals) == 1:
                    return vals[0]
                if len(vals) > 1:
                    return ",".join(sorted(set(vals)))
                return None
            return val
        results_df["domain_countries"] = results_df["domain_countries"].map(normalize_countries)

    # Expand SPF records into separate columns for each IP and include directive
    spf_expanded = results_df["SPF"].apply(pd.Series)
    spf_ip4 = spf_expanded["ip4"].apply(pd.Series).add_prefix("spf_ip4_")
    spf_include = spf_expanded["include"].apply(pd.Series).add_prefix("spf_include_")
    results_df = pd.concat([results_df.drop(columns=["SPF"]), spf_ip4, spf_include], axis=1)

    # Expand DKIM selectors into separate columns, cleaning domain suffixes
    dkim_expanded = results_df["DKIM"].apply(pd.Series)
    # Normalize trailing dots in FQDNs
    dkim_expanded_cleaned = dkim_expanded.stack().map(lambda x: x if pd.isna(x) else [record.rstrip('.') for record in x]).unstack()

    # Clean column names to remove domain-specific parts
    def clean_dkim_col(col):
        return re.sub(r'\._domainkey\..*$', '._domainkey', col)

    dkim_expanded_cleaned.columns = [clean_dkim_col(col) for col in dkim_expanded_cleaned.columns]
    
    # Convert single-item lists to strings for cleaner output
    def flatten_dkim(val):
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val
    dkim_flattened = dkim_expanded_cleaned.stack().map(flatten_dkim).unstack()
    dkim_columns = dkim_flattened.add_prefix("dkim_")
    results_df = pd.concat([results_df.drop(columns=["DKIM"]), dkim_columns], axis=1)
    
    results_df.to_csv("domain_dns_results.csv", index=False)

    # Detect Microsoft 365 usage via MX, autodiscover, SPF, and DKIM signals
    results_df["is_microsoft_365"] = results_df["MX"].apply(lambda x: 1 if x and "mail.protection.outlook.com" in x else 0)
    results_df["is_microsoft_autodiscover"] = results_df["autodiscover"].apply(lambda x: 1 if x and "autodiscover.outlook.com" in x else 0)
    results_df["is_microsoft_spf"] = results_df[[col for col in results_df.columns if col.startswith("spf_include_")]].apply(
        lambda row: 1 if any("spf.protection.outlook.com" in str(val) for val in row if pd.notna(val)) else 0, axis=1
    )
    results_df["is_microsoft_dkim"] = results_df[[col for col in results_df.columns if col.startswith("dkim_")]].apply(
        lambda row: 1 if any(
            ("onmicrosoft.com" in str(val) or "dkim.protection.outlook.com" in str(val))
            for val in row if pd.notna(val)
        ) else 0, axis=1
    )

    # Count total Microsoft indicators per domain
    results_df["microsoft_signs"] = results_df[["is_microsoft_365", "is_microsoft_autodiscover", "is_microsoft_spf", "is_microsoft_dkim"]].sum(axis=1)
    
    # Generate analysis reports comparing rigsmyndighed groups
    def print_two_tables_side_by_side(left_df, right_df, left_title, right_title, padding=4):
        """Helper function to display two dataframes side by side for comparison"""
        left_str = left_df.to_string(index=False)
        right_str = right_df.to_string(index=False)
        left_lines = left_str.splitlines() if left_str else []
        right_lines = right_str.splitlines() if right_str else []
        left_width = max((len(line) for line in left_lines), default=0)
        right_width = max((len(line) for line in right_lines), default=0)
        title_line = left_title.ljust(left_width) + (" " * padding) + right_title
        print(title_line)
        print(("-" * left_width) + (" " * padding) + ("-" * right_width))
        max_lines = max(len(left_lines), len(right_lines))
        for i in range(max_lines):
            left_line = left_lines[i] if i < len(left_lines) else ""
            right_line = right_lines[i] if i < len(right_lines) else ""
            print(left_line.ljust(left_width) + (" " * padding) + right_line)

    # Normalize rigsmyndighed for filtering as strings "0"/"1"
    rigs_col = results_df["rigsmyndighed"].astype(str).str.strip().fillna("")

    # Display Microsoft detection summary comparing rigsmyndighed groups
    print("\nMicrosoft detection summary (comparison)")
    print("=" * 80)
    def build_summary(subset_df):
        """Build summary statistics for Microsoft detection indicators"""
        total = len(subset_df)
        signs_gt_0 = subset_df[subset_df["microsoft_signs"] > 0].shape[0]
        signs_1 = subset_df[subset_df["microsoft_signs"] == 1].shape[0]
        signs_2 = subset_df[subset_df["microsoft_signs"] == 2].shape[0]
        signs_3 = subset_df[subset_df["microsoft_signs"] == 3].shape[0]
        signs_4 = subset_df[subset_df["microsoft_signs"] == 4].shape[0]
        return pd.DataFrame([
            {"metric": "total_domains", "value": total},
            {"metric": ">0_signs", "value": signs_gt_0},
            {"metric": "exactly_1", "value": signs_1},
            {"metric": "exactly_2", "value": signs_2},
            {"metric": "exactly_3", "value": signs_3},
            {"metric": "exactly_4", "value": signs_4},
        ])[ ["metric", "value"] ]
    summary_left = build_summary(results_df[rigs_col == "0"]).copy()
    summary_right = build_summary(results_df[rigs_col == "1"]).copy()
    print_two_tables_side_by_side(summary_left, summary_right, "rigsmyndighed = 0", "rigsmyndighed = 1")
    
    # Display country distribution comparison
    print("\nCountry distribution (top 10) comparison")
    print("=" * 80)
    def build_country_table(subset_df):
        """Build country distribution table for domains with geolocation data"""
        domains_with_countries = subset_df[subset_df["domain_countries"].notna() & (subset_df["domain_countries"] != "")]
        if len(domains_with_countries) == 0:
            return pd.DataFrame([{"country": "-", "count": 0, "percent": 0.0}])[ ["country", "count", "percent"] ]
        country_counts = {}
        for countries in domains_with_countries["domain_countries"]:
            if countries:
                for country in [c.strip() for c in str(countries).split(',')]:
                    if country:
                        country_counts[country] = country_counts.get(country, 0) + 1
        sorted_items = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        total_with_countries = len(domains_with_countries)
        table = pd.DataFrame([
            {"country": c, "count": n, "percent": round((n / total_with_countries) * 100, 1)}
            for c, n in sorted_items
        ])[ ["country", "count", "percent"] ]
        return table

    country_left = build_country_table(results_df[rigs_col == "0"]).copy()
    country_right = build_country_table(results_df[rigs_col == "1"]).copy()
    print_two_tables_side_by_side(country_left, country_right, "rigsmyndighed = 0", "rigsmyndighed = 1")
    
    # Save final analysis results
    results_df.to_csv("analysis_results.csv", index=False)


if __name__ == "__main__":
    main()

