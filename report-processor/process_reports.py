#!/usr/bin/env python3
"""
Process and merge ScoutSuite and Prowler reports into a unified format
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
import pandas as pd
import psycopg2
from psycopg2.extras import Json
import yaml
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ReportProcessor:
    def __init__(self):
        self.db_config = {
            'host': os.environ.get('DB_HOST', 'postgres'),
            'database': os.environ.get('DB_NAME', 'cloudaudit'),
            'user': os.environ.get('DB_USER', 'audituser'),
            'password': os.environ.get('DB_PASSWORD', 'secretpassword')
        }
        self.reports_dir = Path('/reports')
        self.processed_dir = Path('/processed')
        self.processed_dir.mkdir(exist_ok=True)
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            return psycopg2.connect(**self.db_config)
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return None
    
    def process_scoutsuite_report(self, report_path):
        """Process ScoutSuite JSON report"""
        logger.info(f"Processing ScoutSuite report: {report_path}")
        
        findings = []
        try:
            with open(report_path, 'r') as f:
                data = json.load(f)
            
            # Extract metadata
            metadata = {
                'tool': 'scoutsuite',
                'cloud_provider': data.get('provider', 'unknown'),
                'scan_date': datetime.now().isoformat(),
                'account_id': data.get('account_id', 'unknown')
            }
            
            # Extract findings
            for service, service_data in data.get('services', {}).items():
                for finding_type, finding_data in service_data.get('findings', {}).items():
                    if isinstance(finding_data, dict) and finding_data.get('items'):
                        for item in finding_data['items']:
                            finding = {
                                'service': service,
                                'type': finding_type,
                                'severity': finding_data.get('level', 'unknown'),
                                'resource_id': item.get('id', 'unknown'),
                                'region': item.get('region', 'global'),
                                'description': finding_data.get('description', ''),
                                'remediation': finding_data.get('remediation', ''),
                                'compliance': finding_data.get('compliance', [])
                            }
                            findings.append(finding)
            
            logger.info(f"Extracted {len(findings)} findings from ScoutSuite")
            return metadata, findings
            
        except Exception as e:
            logger.error(f"Error processing ScoutSuite report: {e}")
            return None, []
    
    def process_prowler_report(self, report_path):
        """Process Prowler JSON report"""
        logger.info(f"Processing Prowler report: {report_path}")
        
        findings = []
        try:
            with open(report_path, 'r') as f:
                # Prowler outputs newline-delimited JSON
                for line in f:
                    if line.strip():
                        finding_data = json.loads(line)
                        
                        finding = {
                            'check_id': finding_data.get('CheckID', ''),
                            'check_title': finding_data.get('CheckTitle', ''),
                            'severity': finding_data.get('Severity', 'unknown'),
                            'status': finding_data.get('Status', ''),
                            'region': finding_data.get('Region', 'global'),
                            'resource_id': finding_data.get('ResourceId', ''),
                            'resource_type': finding_data.get('ResourceType', ''),
                            'description': finding_data.get('StatusExtended', ''),
                            'remediation': finding_data.get('Remediation', {}).get('Recommendation', ''),
                            'compliance': finding_data.get('Compliance', [])
                        }
                        findings.append(finding)
            
            metadata = {
                'tool': 'prowler',
                'cloud_provider': 'aws',
                'scan_date': datetime.now().isoformat()
            }
            
            logger.info(f"Extracted {len(findings)} findings from Prowler")
            return metadata, findings
            
        except Exception as e:
            logger.error(f"Error processing Prowler report: {e}")
            return None, []

    def process_kube_linter_report(self, report_path):
        """Process kube-linter JSON report"""
        logger.info(f"Processing kube-linter report: {report_path}")

        findings = []
        try:
            with open(report_path, 'r') as f:
                data = json.load(f)

            metadata = {
                'tool': 'kube-linter',
                'cloud_provider': 'kubernetes',
                'scan_date': datetime.now().isoformat()
            }

            # kube-linter reports array of findings under Reports
            for item in data.get('Reports', []):
                k8s_obj = item.get('Object', {}).get('K8sObject', {})
                for violation in item.get('Violations', []):
                    # Map kube-linter severity levels
                    severity_map = {
                        'error': 'high',
                        'warning': 'medium',
                        'info': 'low'
                    }

                    finding = {
                        'check_id': violation.get('Check', ''),
                        'check_title': violation.get('Check', ''),
                        'severity': severity_map.get(
                            violation.get('Severity', 'warning').lower(),
                            'medium'
                        ),
                        'status': 'FAIL',
                        'resource_type': k8s_obj.get('GroupVersionKind', {}).get('Kind', ''),
                        'resource_id': f"{k8s_obj.get('Namespace', 'default')}/{k8s_obj.get('Name', '')}",
                        'resource_name': k8s_obj.get('Name', ''),
                        'description': violation.get('Message', ''),
                        'remediation': violation.get('Remediation', ''),
                        'compliance': []
                    }
                    findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from kube-linter")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing kube-linter report: {e}")
            return None, []

    def process_polaris_report(self, report_path):
        """Process Polaris JSON report"""
        logger.info(f"Processing Polaris report: {report_path}")

        findings = []
        try:
            with open(report_path, 'r') as f:
                data = json.load(f)

            metadata = {
                'tool': 'polaris',
                'cloud_provider': 'kubernetes',
                'scan_date': datetime.now().isoformat(),
                'cluster_info': data.get('ClusterInfo', {})
            }

            # Map Polaris severity to standard severity levels
            severity_map = {
                'danger': 'critical',
                'warning': 'medium',
                'passing': 'info'
            }

            # Process audit results from Results structure
            for namespace_name, namespace_data in data.get('Results', {}).items():
                if not isinstance(namespace_data, dict):
                    continue
                for controller_name, controller_data in namespace_data.items():
                    if not isinstance(controller_data, dict):
                        continue

                    kind = controller_data.get('Kind', 'Unknown')

                    for container_name, container_results in controller_data.get('Results', {}).items():
                        if not isinstance(container_results, dict):
                            continue

                        for check_category, checks in container_results.items():
                            if not isinstance(checks, dict):
                                continue

                            for check_name, check_result in checks.items():
                                if not isinstance(check_result, dict):
                                    continue

                                # Only report failures
                                if check_result.get('Success', True):
                                    continue

                                severity_level = check_result.get('Severity', 'warning')

                                finding = {
                                    'check_id': f"polaris-{check_category}-{check_name}",
                                    'check_title': check_name.replace('_', ' ').title(),
                                    'severity': severity_map.get(severity_level, 'medium'),
                                    'status': 'FAIL',
                                    'resource_type': kind,
                                    'resource_id': f"{namespace_name}/{controller_name}",
                                    'resource_name': controller_name,
                                    'category': check_category,
                                    'container': container_name,
                                    'description': check_result.get('Message', ''),
                                    'remediation': f"Review and fix {check_name} for {kind} {controller_name}",
                                    'compliance': []
                                }
                                findings.append(finding)

            # Also process PodResults if available (for cluster audits)
            for pod_result in data.get('PodResults', []):
                namespace = pod_result.get('Namespace', 'default')
                pod_name = pod_result.get('Name', '')
                kind = pod_result.get('Kind', 'Pod')

                for container_result in pod_result.get('ContainerResults', []):
                    container_name = container_result.get('Name', '')

                    for check_name, check_result in container_result.get('Results', {}).items():
                        if not isinstance(check_result, dict):
                            continue
                        if check_result.get('Success', True):
                            continue

                        severity_level = check_result.get('Severity', 'warning')

                        finding = {
                            'check_id': f"polaris-{check_name}",
                            'check_title': check_name.replace('_', ' ').title(),
                            'severity': severity_map.get(severity_level, 'medium'),
                            'status': 'FAIL',
                            'resource_type': kind,
                            'resource_id': f"{namespace}/{pod_name}",
                            'resource_name': pod_name,
                            'container': container_name,
                            'description': check_result.get('Message', ''),
                            'remediation': f"Review and fix {check_name} for container {container_name}",
                            'compliance': []
                        }
                        findings.append(finding)

            logger.info(f"Extracted {len(findings)} findings from Polaris")
            return metadata, findings

        except Exception as e:
            logger.error(f"Error processing Polaris report: {e}")
            return None, []

    def save_to_database(self, metadata, findings, scan_id):
        """Save processed findings to database"""
        conn = self.connect_db()
        if not conn:
            return False
        
        try:
            cur = conn.cursor()
            
            # Insert scan metadata
            cur.execute("""
                INSERT INTO scan_metadata (scan_id, tool, cloud_provider, scan_date, status)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (scan_id) DO UPDATE
                SET scan_date = EXCLUDED.scan_date, status = EXCLUDED.status
            """, (
                scan_id,
                metadata['tool'],
                metadata['cloud_provider'],
                metadata['scan_date'],
                'completed'
            ))
            
            # Insert findings
            for finding in findings:
                cur.execute("""
                    INSERT INTO findings (
                        scan_id, finding_id, severity, category, 
                        resource_type, resource_id, region, title, 
                        description, remediation, compliance_frameworks, raw_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id, finding_id) DO UPDATE
                    SET severity = EXCLUDED.severity,
                        description = EXCLUDED.description,
                        remediation = EXCLUDED.remediation
                """, (
                    scan_id,
                    finding.get('check_id', finding.get('type', '')),
                    finding.get('severity', 'unknown'),
                    finding.get('service', finding.get('category', '')),
                    finding.get('resource_type', ''),
                    finding.get('resource_id', ''),
                    finding.get('region', 'global'),
                    finding.get('check_title', finding.get('type', '')),
                    finding.get('description', ''),
                    finding.get('remediation', ''),
                    Json(finding.get('compliance', [])),
                    Json(finding)
                ))
            
            conn.commit()
            logger.info(f"Saved {len(findings)} findings to database")
            return True
            
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def generate_unified_report(self):
        """Generate unified HTML report from all findings"""
        conn = self.connect_db()
        if not conn:
            return
        
        try:
            # Query all recent findings
            query = """
                SELECT f.*, s.tool, s.cloud_provider
                FROM findings f
                JOIN scan_metadata s ON f.scan_id = s.scan_id
                WHERE s.scan_date > NOW() - INTERVAL '7 days'
                ORDER BY f.severity DESC, f.finding_id
            """
            
            df = pd.read_sql(query, conn)
            
            # Generate summary statistics
            summary = {
                'total_findings': len(df),
                'critical': len(df[df['severity'] == 'CRITICAL']),
                'high': len(df[df['severity'] == 'HIGH']),
                'medium': len(df[df['severity'] == 'MEDIUM']),
                'low': len(df[df['severity'] == 'LOW']),
                'by_region': df.groupby('region').size().to_dict(),
                'by_tool': df.groupby('tool').size().to_dict()
            }
            
            # Save summary
            summary_path = self.processed_dir / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=2)
            
            logger.info(f"Generated unified report with {summary['total_findings']} findings")
            
        except Exception as e:
            logger.error(f"Error generating unified report: {e}")
        finally:
            conn.close()
    
    def run(self):
        """Main processing loop"""
        logger.info("Starting report processing...")
        
        # Process ScoutSuite reports
        scoutsuite_reports = list(self.reports_dir.glob('scoutsuite/*/scoutsuite_results_*.json'))
        for report in scoutsuite_reports:
            scan_id = f"scoutsuite_{report.parent.name}"
            metadata, findings = self.process_scoutsuite_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)
        
        # Process Prowler reports
        prowler_reports = list(self.reports_dir.glob('prowler/*/prowler-output-*.json'))
        for report in prowler_reports:
            scan_id = f"prowler_{report.parent.name}"
            metadata, findings = self.process_prowler_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process kube-linter reports
        kube_linter_reports = list(self.reports_dir.glob('kube-linter/*.json'))
        for report in kube_linter_reports:
            scan_id = f"kube_linter_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            metadata, findings = self.process_kube_linter_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Process Polaris reports
        polaris_reports = list(self.reports_dir.glob('polaris/*.json'))
        for report in polaris_reports:
            scan_id = f"polaris_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            metadata, findings = self.process_polaris_report(report)
            if metadata and findings:
                self.save_to_database(metadata, findings, scan_id)

        # Generate unified report
        self.generate_unified_report()
        
        logger.info("Report processing completed")

if __name__ == "__main__":
    processor = ReportProcessor()
    processor.run()
