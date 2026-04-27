#!/usr/bin/env python3
"""Phase 1 helper: Extract and normalize technology stack from fingerprinting tools."""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict


# Known tech → version regex patterns for header/body extraction
TECH_PATTERNS = {
    'apache': [
        (r'Apache[/ ]([\d.]+)', 'Apache HTTP Server'),
    ],
    'nginx': [
        (r'nginx[/ ]([\d.]+)', 'nginx'),
    ],
    'iis': [
        (r'Microsoft-IIS[/ ]([\d.]+)', 'Microsoft IIS'),
    ],
    'php': [
        (r'PHP[/ ]([\d.]+)', 'PHP'),
        (r'X-Powered-By: PHP/([\d.]+)', 'PHP'),
    ],
    'openssl': [
        (r'OpenSSL[/ ]([\d.]+\w*)', 'OpenSSL'),
    ],
    'tomcat': [
        (r'Apache[- ]Tomcat[/ ]([\d.]+)', 'Apache Tomcat'),
    ],
    'wordpress': [
        (r'WordPress[/ ]([\d.]+)', 'WordPress'),
        (r'wp-includes.*\?ver=([\d.]+)', 'WordPress'),
    ],
    'drupal': [
        (r'Drupal ([\d.]+)', 'Drupal'),
        (r'X-Generator: Drupal (\d+)', 'Drupal'),
    ],
    'joomla': [
        (r'Joomla[! ]*([\d.]+)', 'Joomla'),
    ],
    'jquery': [
        (r'jquery[.-]([\d.]+(?:\.min)?)', 'jQuery'),
    ],
    'react': [
        (r'react(?:\.production)?[.-]v?([\d.]+)', 'React'),
    ],
    'aspnet': [
        (r'X-AspNet-Version: ([\d.]+)', 'ASP.NET'),
        (r'X-AspNetMvc-Version: ([\d.]+)', 'ASP.NET MVC'),
    ],
    'spring': [
        (r'X-Application-Context', 'Spring Framework'),
    ],
    'express': [
        (r'X-Powered-By: Express', 'Express.js'),
    ],
    'laravel': [
        (r'laravel_session', 'Laravel'),
    ],
    'rails': [
        (r'X-Runtime: [\d.]+', 'Ruby on Rails'),
        (r'_rails_session', 'Ruby on Rails'),
    ],
    'jenkins': [
        (r'X-Jenkins: ([\d.]+)', 'Jenkins'),
        (r'Jenkins-Version: ([\d.]+)', 'Jenkins'),
    ],
    'gitlab': [
        (r'GitLab ([\d.]+)', 'GitLab'),
    ],
    'jira': [
        (r'Jira.*?v?([\d.]+)', 'Atlassian Jira'),
        (r'ajs-version-number.*?content="([\d.]+)"', 'Atlassian Jira'),
    ],
    'confluence': [
        (r'Confluence[/ ]([\d.]+)', 'Atlassian Confluence'),
        (r'ajs-version-number.*?content="([\d.]+)"', 'Atlassian Confluence'),
    ],
    'citrix': [
        (r'Citrix.*?NetScaler', 'Citrix ADC/NetScaler'),
        (r'Citrix Gateway', 'Citrix Gateway'),
    ],
    'f5': [
        (r'BIGipServer', 'F5 BIG-IP'),
        (r'F5[/ ]([\d.]+)', 'F5 BIG-IP'),
    ],
    'grafana': [
        (r'Grafana v([\d.]+)', 'Grafana'),
        (r'"version":"([\d.]+)".*?grafana', 'Grafana'),
    ],
    'kibana': [
        (r'kbn-version: ([\d.]+)', 'Kibana'),
    ],
    'elasticsearch': [
        (r'"version".*?"number"\s*:\s*"([\d.]+)"', 'Elasticsearch'),
    ],
    'rabbitmq': [
        (r'RabbitMQ Management ([\d.]+)', 'RabbitMQ'),
    ],
    'redis': [
        (r'redis_version:([\d.]+)', 'Redis'),
    ],
    'mongodb': [
        (r'MongoDB ([\d.]+)', 'MongoDB'),
    ],
    'nextjs': [
        (r'__NEXT_DATA__', 'Next.js'),
        (r'_next/static', 'Next.js'),
    ],
    'varnish': [
        (r'Varnish', 'Varnish Cache'),
        (r'X-Varnish', 'Varnish Cache'),
    ],
    'cloudflare': [
        (r'cloudflare', 'Cloudflare'),
    ],
    'akamai': [
        (r'AkamaiGHost', 'Akamai'),
    ],
}

# Priority CVE-heavy technologies (scan these more carefully)
HIGH_PRIORITY_TECH = {
    'Apache HTTP Server', 'nginx', 'Microsoft IIS', 'PHP', 'OpenSSL',
    'Apache Tomcat', 'WordPress', 'Drupal', 'Joomla', 'Jenkins',
    'GitLab', 'Atlassian Jira', 'Atlassian Confluence', 'Citrix ADC/NetScaler',
    'Citrix Gateway', 'F5 BIG-IP', 'Grafana', 'Kibana', 'Elasticsearch',
    'RabbitMQ', 'Redis', 'MongoDB', 'Spring Framework', 'Apache Struts',
}


def parse_httpx(filepath):
    """Parse httpx JSON output for tech + versions."""
    results = defaultdict(lambda: {'hosts': set(), 'versions': set(), 'raw': []})
    if not filepath or not Path(filepath).exists():
        return results

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = entry.get('url', '')
            server = entry.get('webserver', '') or ''
            techs = entry.get('tech', []) or []
            title = entry.get('title', '') or ''
            headers_raw = json.dumps(entry)

            # httpx tech detection
            for tech in techs:
                # Try to split "Name vX.Y.Z"
                m = re.match(r'^(.+?)\s+v?([\d.]+.*)$', tech)
                if m:
                    name, ver = m.group(1).strip(), m.group(2).strip()
                    results[name]['versions'].add(ver)
                else:
                    results[tech]['versions'] = results[tech].get('versions', set())
                results[tech]['hosts'].add(url)

            # Server header parsing
            for tech_key, patterns in TECH_PATTERNS.items():
                for pattern, tech_name in patterns:
                    m = re.search(pattern, headers_raw, re.IGNORECASE)
                    if m:
                        results[tech_name]['hosts'].add(url)
                        if m.lastindex and m.lastindex >= 1:
                            results[tech_name]['versions'].add(m.group(1))

    return results


def parse_whatweb(filepath):
    """Parse WhatWeb JSON output."""
    results = defaultdict(lambda: {'hosts': set(), 'versions': set(), 'raw': []})
    if not filepath or not Path(filepath).exists():
        return results

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries = json.loads(line) if line.startswith('[') else [json.loads(line)]
            except json.JSONDecodeError:
                continue

            for entry in entries:
                url = entry.get('target', '')
                plugins = entry.get('plugins', {})
                for plugin_name, plugin_data in plugins.items():
                    if plugin_name in ('IP', 'Country', 'HTTPServer'):
                        continue
                    results[plugin_name]['hosts'].add(url)
                    versions = plugin_data.get('version', [])
                    if isinstance(versions, list):
                        for v in versions:
                            if v:
                                results[plugin_name]['versions'].add(str(v))
                    elif versions:
                        results[plugin_name]['versions'].add(str(versions))

    return results


def parse_nmap(filepath):
    """Parse nmap XML output for service versions."""
    results = defaultdict(lambda: {'hosts': set(), 'versions': set(), 'raw': []})
    if not filepath or not Path(filepath).exists():
        return results

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError):
        return results

    for host in root.findall('.//host'):
        addr_elem = host.find('address')
        if addr_elem is None:
            continue
        ip = addr_elem.get('addr', '')

        for port in host.findall('.//port'):
            service = port.find('service')
            if service is None:
                continue

            product = service.get('product', '')
            version = service.get('version', '')
            extra = service.get('extrainfo', '')
            port_id = port.get('portid', '')

            if product:
                host_str = f"{ip}:{port_id}"
                results[product]['hosts'].add(host_str)
                if version:
                    results[product]['versions'].add(version)
                if extra:
                    results[product]['raw'].append(extra)

    return results


def merge_results(*result_dicts):
    """Merge multiple tech inventories."""
    merged = defaultdict(lambda: {'hosts': set(), 'versions': set(), 'raw': []})
    for rd in result_dicts:
        for tech, data in rd.items():
            merged[tech]['hosts'].update(data.get('hosts', set()))
            merged[tech]['versions'].update(data.get('versions', set()))
            merged[tech]['raw'].extend(data.get('raw', []))
    return merged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--httpx', help='httpx JSON output file')
    parser.add_argument('--whatweb', help='WhatWeb JSON output file')
    parser.add_argument('--nmap', help='Nmap XML output file')
    parser.add_argument('--output', required=True, help='Output JSON file')
    args = parser.parse_args()

    httpx_data = parse_httpx(args.httpx)
    whatweb_data = parse_whatweb(args.whatweb)
    nmap_data = parse_nmap(args.nmap)

    merged = merge_results(httpx_data, whatweb_data, nmap_data)

    # Convert sets to lists for JSON serialization
    output = []
    for tech, data in sorted(merged.items()):
        versions = sorted(data['versions']) if data['versions'] else []
        hosts = sorted(data['hosts']) if data['hosts'] else []
        priority = 'high' if tech in HIGH_PRIORITY_TECH else 'normal'

        output.append({
            'technology': tech,
            'versions': versions,
            'hosts': hosts,
            'host_count': len(hosts),
            'priority': priority,
        })

    # Sort: high priority first, then by host count
    output.sort(key=lambda x: (0 if x['priority'] == 'high' else 1, -x['host_count']))

    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Extracted {len(output)} technologies ({sum(1 for t in output if t['priority'] == 'high')} high-priority)")


if __name__ == '__main__':
    main()
