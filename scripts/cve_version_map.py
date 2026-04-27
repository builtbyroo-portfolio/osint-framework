#!/usr/bin/env python3
"""Phase 2 helper: Map technology+version pairs to CPE identifiers for NVD lookup."""
import argparse
import json
import re
from pathlib import Path

# Technology name → CPE vendor:product mapping
# Format: CPE 2.3 = cpe:2.3:a:VENDOR:PRODUCT:VERSION
CPE_MAP = {
    # Web servers
    'Apache HTTP Server': 'apache:http_server',
    'Apache': 'apache:http_server',
    'nginx': 'nginx:nginx',
    'Microsoft IIS': 'microsoft:internet_information_services',
    'Microsoft-IIS': 'microsoft:internet_information_services',
    'Apache Tomcat': 'apache:tomcat',
    'Tomcat': 'apache:tomcat',
    'LiteSpeed': 'litespeedtech:litespeed_web_server',
    'Caddy': 'caddyserver:caddy',

    # Languages/Runtimes
    'PHP': 'php:php',
    'OpenSSL': 'openssl:openssl',
    'Node.js': 'nodejs:node.js',
    'Python': 'python:python',
    'Ruby': 'ruby-lang:ruby',

    # CMS
    'WordPress': 'wordpress:wordpress',
    'Drupal': 'drupal:drupal',
    'Joomla': 'joomla:joomla\\!',
    'Joomla!': 'joomla:joomla\\!',
    'Magento': 'magento:magento',
    'Ghost': 'ghost:ghost',

    # Frameworks
    'ASP.NET': 'microsoft:asp.net',
    'ASP.NET MVC': 'microsoft:asp.net_mvc',
    'Spring Framework': 'vmware:spring_framework',
    'Spring Boot': 'vmware:spring_boot',
    'Django': 'djangoproject:django',
    'Laravel': 'laravel:laravel',
    'Ruby on Rails': 'rubyonrails:rails',
    'Express.js': 'expressjs:express',
    'Next.js': 'vercel:next.js',
    'Angular': 'angular:angular',
    'Vue.js': 'vuejs:vue.js',
    'Flask': 'palletsprojects:flask',

    # DevOps / CI
    'Jenkins': 'jenkins:jenkins',
    'GitLab': 'gitlab:gitlab',
    'Gitea': 'gitea:gitea',
    'Bamboo': 'atlassian:bamboo',
    'TeamCity': 'jetbrains:teamcity',

    # Atlassian
    'Atlassian Jira': 'atlassian:jira',
    'Jira': 'atlassian:jira',
    'Atlassian Confluence': 'atlassian:confluence',
    'Confluence': 'atlassian:confluence',
    'Bitbucket': 'atlassian:bitbucket',

    # Network / Infrastructure
    'Citrix ADC/NetScaler': 'citrix:application_delivery_controller',
    'Citrix Gateway': 'citrix:gateway',
    'Citrix ADC': 'citrix:application_delivery_controller',
    'F5 BIG-IP': 'f5:big-ip',
    'Fortinet FortiOS': 'fortinet:fortios',
    'FortiGate': 'fortinet:fortios',
    'Palo Alto PAN-OS': 'paloaltonetworks:pan-os',
    'SonicWall': 'sonicwall:sma',
    'Ivanti Connect Secure': 'ivanti:connect_secure',
    'Pulse Secure': 'pulsesecure:pulse_connect_secure',

    # Monitoring
    'Grafana': 'grafana:grafana',
    'Kibana': 'elastic:kibana',
    'Elasticsearch': 'elastic:elasticsearch',
    'Prometheus': 'prometheus:prometheus',
    'Nagios': 'nagios:nagios',
    'Zabbix': 'zabbix:zabbix',
    'Splunk': 'splunk:splunk',

    # Databases
    'Redis': 'redis:redis',
    'MongoDB': 'mongodb:mongodb',
    'MySQL': 'oracle:mysql',
    'PostgreSQL': 'postgresql:postgresql',
    'MariaDB': 'mariadb:mariadb',
    'CouchDB': 'apache:couchdb',
    'Cassandra': 'apache:cassandra',

    # Message Queues
    'RabbitMQ': 'vmware:rabbitmq',
    'Apache Kafka': 'apache:kafka',

    # Other
    'Varnish Cache': 'varnish-cache:varnish',
    'HAProxy': 'haproxy:haproxy',
    'Envoy': 'envoyproxy:envoy',
    'MinIO': 'minio:minio',
    'HashiCorp Vault': 'hashicorp:vault',
    'HashiCorp Consul': 'hashicorp:consul',
    'SonarQube': 'sonarsource:sonarqube',
    'Metabase': 'metabase:metabase',
    'Apache Airflow': 'apache:airflow',
    'Apache Struts': 'apache:struts',
    'Telerik UI': 'telerik:ui_for_asp.net_ajax',
    'ServiceNow': 'servicenow:servicenow',
    'n8n': 'n8n:n8n',
    'Webmin': 'webmin:webmin',
}


def normalize_version(version_str):
    """Clean version string for CPE matching."""
    if not version_str:
        return None
    # Remove common prefixes
    v = re.sub(r'^[vV]', '', version_str.strip())
    # Keep only version-like characters
    m = re.match(r'([\d]+(?:\.[\d]+)*(?:[-._]\w+)?)', v)
    return m.group(1) if m else None


def build_cpe(vendor_product, version):
    """Build CPE 2.3 string."""
    return f"cpe:2.3:a:{vendor_product}:{version}:*:*:*:*:*:*:*"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tech-inventory', required=True, help='Tech inventory JSON from Phase 1')
    parser.add_argument('--httpx', help='httpx JSON (for additional header parsing)')
    parser.add_argument('--nmap', help='Nmap XML (for additional version data)')
    parser.add_argument('--output', required=True, help='Output version map JSON')
    args = parser.parse_args()

    tech_path = Path(args.tech_inventory)
    if not tech_path.exists():
        print("Tech inventory not found, creating empty version map")
        with open(args.output, 'w') as f:
            json.dump([], f)
        return

    with open(tech_path) as f:
        tech_inventory = json.load(f)

    version_map = []
    seen = set()

    for entry in tech_inventory:
        tech_name = entry['technology']
        versions = entry.get('versions', [])
        hosts = entry.get('hosts', [])

        # Find CPE mapping
        cpe_vp = CPE_MAP.get(tech_name)
        if not cpe_vp:
            # Try fuzzy match
            for known_name, vp in CPE_MAP.items():
                if known_name.lower() in tech_name.lower() or tech_name.lower() in known_name.lower():
                    cpe_vp = vp
                    break

        if not cpe_vp:
            # Unknown tech — still record it for manual review
            version_map.append({
                'technology': tech_name,
                'versions': versions,
                'hosts': hosts[:10],
                'cpe': None,
                'cpe_queries': [],
                'mapped': False,
            })
            continue

        # Build CPE queries for each version
        cpe_queries = []
        for v in versions:
            norm_v = normalize_version(v)
            if norm_v:
                key = f"{cpe_vp}:{norm_v}"
                if key not in seen:
                    seen.add(key)
                    cpe_queries.append({
                        'version': norm_v,
                        'cpe': build_cpe(cpe_vp, norm_v),
                        'keyword': f"{cpe_vp.replace(':', ' ')} {norm_v}",
                    })

        # Also add versionless query (catches all CVEs for the product)
        versionless_key = f"{cpe_vp}:*"
        if versionless_key not in seen and not cpe_queries:
            seen.add(versionless_key)
            cpe_queries.append({
                'version': '*',
                'cpe': build_cpe(cpe_vp, '*'),
                'keyword': cpe_vp.replace(':', ' '),
            })

        version_map.append({
            'technology': tech_name,
            'versions': versions,
            'hosts': hosts[:10],
            'cpe_vendor_product': cpe_vp,
            'cpe_queries': cpe_queries,
            'mapped': True,
            'priority': entry.get('priority', 'normal'),
        })

    # Sort: mapped + high priority first
    version_map.sort(key=lambda x: (
        0 if x.get('mapped') and x.get('priority') == 'high' else
        1 if x.get('mapped') else 2
    ))

    with open(args.output, 'w') as f:
        json.dump(version_map, f, indent=2)

    mapped = sum(1 for v in version_map if v.get('mapped'))
    with_version = sum(1 for v in version_map if v.get('cpe_queries'))
    print(f"Version map: {len(version_map)} technologies, {mapped} CPE-mapped, {with_version} with version queries")


if __name__ == '__main__':
    main()
