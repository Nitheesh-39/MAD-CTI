"""
Multi-Agent Framework for Cyber Threat Intelligence Analysis
Agents: Parser, NLP Analyst, Enricher, Graph Builder, Scorer, Classifier
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Any, Tuple
import numpy as np


class BaseAgent:
    """Base class for all agents"""
    
    def __init__(self, name: str):
        self.name = name
        self.results = {}
    
    def process(self, data: Any) -> Any:
        """Process data - to be implemented by subclasses"""
        raise NotImplementedError
    
    def log(self, message: str):
        """Log agent activity"""
        print(f"[{self.name}] {message}")


class ParserAgent(BaseAgent):
    """Agent for parsing and extracting IOCs from text"""
    
    def __init__(self):
        super().__init__("Parser")
        
        # Regex patterns for IOC extraction
        self.patterns = {
            'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'url': r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'cve': r'CVE-\d{4}-\d{4,7}',
            'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        }
    
    def process(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text"""
        self.log(f"Parsing text of length {len(text)}")
        
        iocs = {}
        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                iocs[ioc_type] = list(set(matches))  # Remove duplicates
        
        self.results = iocs
        self.log(f"Extracted {sum(len(v) for v in iocs.values())} IOCs")
        return iocs


class NLPAnalystAgent(BaseAgent):
    """Agent for NLP analysis - entity extraction, keyword extraction, sentiment"""
    
    def __init__(self):
        super().__init__("NLP Analyst")
        
        # Threat-related keywords for different categories
        self.threat_keywords = {
            'hack': [
                'hack', 'hacking', 'hacked', 'breach', 'breached', 'compromised',
                'exploit', 'exploited', 'phishing', 'ddos', 'sql injection',
                'password crack', 'brute force', 'credential', 'unauthorized access',
                'backdoor', 'rootkit', 'privilege escalation', 'zero-day'
            ],
            'malware': [
                'malware', 'virus', 'trojan', 'ransomware', 'spyware', 'adware',
                'worm', 'keylogger', 'botnet', 'payload', 'infection', 'infected',
                'cryptolocker', 'wannacry', 'petya', 'emotet', 'trickbot',
                'rat', 'remote access trojan', 'dropper', 'loader'
            ],
            'vulnerability': [
                'vulnerability', 'vulnerable', 'cve', 'exploit', 'bug', 'flaw',
                'weakness', 'security hole', 'patch', 'unpatched', 'disclosure',
                'rce', 'remote code execution', 'buffer overflow', 'xss',
                'cross-site scripting', 'csrf', 'injection', 'deserialization'
            ]
        }
        
        # Entity patterns
        self.entity_patterns = {
            'ORGANIZATION': r'\b(?:Microsoft|Google|Apple|Amazon|Facebook|Twitter|GitHub|Cisco|Oracle|IBM|Intel)\b',
            'MALWARE_NAME': r'\b(?:WannaCry|Petya|Emotet|TrickBot|Ryuk|Maze|REvil|DarkSide|BlackMatter)\b',
            'TOOL': r'\b(?:Metasploit|Cobalt Strike|Mimikatz|PowerShell|Empire|BloodHound)\b',
            'THREAT_ACTOR': r'\b(?:APT\d+|Lazarus|Fancy Bear|Cozy Bear|Sandworm)\b',
        }
    
    def process(self, text: str) -> Dict[str, Any]:
        """Perform NLP analysis on text"""
        self.log(f"Analyzing text of length {len(text)}")
        
        # Extract entities
        entities = self._extract_entities(text)
        
        # Extract keywords
        keywords = self._extract_keywords(text)
        
        # Calculate sentiment (simplified)
        sentiment = self._calculate_sentiment(text)
        
        # Determine threat category
        threat_category = self._categorize_threat(text)
        
        results = {
            'entities': entities,
            'keywords': keywords,
            'sentiment': sentiment,
            'threat_category': threat_category,
            'text_length': len(text),
            'word_count': len(text.split())
        }
        
        self.results = results
        self.log(f"Analysis complete: {len(entities)} entities, {len(keywords)} keywords")
        return results
    
    def _extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract named entities from text"""
        entities = {}
        for entity_type, pattern in self.entity_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                entities[entity_type] = list(set(matches))
        return entities
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract threat-related keywords"""
        text_lower = text.lower()
        keywords = []
        
        for category, keyword_list in self.threat_keywords.items():
            for keyword in keyword_list:
                if keyword in text_lower:
                    keywords.append(keyword)
        
        return list(set(keywords))
    
    def _calculate_sentiment(self, text: str) -> float:
        """Calculate sentiment score (simplified: -1 to 1)"""
        # Negative words indicate threats
        negative_words = ['attack', 'threat', 'malicious', 'dangerous', 'critical', 'severe']
        positive_words = ['secure', 'safe', 'protected', 'patched', 'fixed']
        
        text_lower = text.lower()
        neg_count = sum(1 for word in negative_words if word in text_lower)
        pos_count = sum(1 for word in positive_words if word in text_lower)
        
        total = neg_count + pos_count
        if total == 0:
            return 0.0
        
        return (pos_count - neg_count) / total
    
    def _categorize_threat(self, text: str) -> Dict[str, float]:
        """Categorize threat type with confidence scores"""
        text_lower = text.lower()
        scores = {}
        
        for category, keywords in self.threat_keywords.items():
            matches = sum(1 for keyword in keywords if keyword in text_lower)
            scores[category] = matches
        
        # Normalize scores
        total = sum(scores.values())
        if total > 0:
            scores = {k: v/total for k, v in scores.items()}
        
        return scores


class EnricherAgent(BaseAgent):
    """Agent for enriching IOCs with additional context"""
    
    def __init__(self):
        super().__init__("Enricher")
        
        # Simulated threat intelligence database
        self.threat_db = {
            'known_malicious_ips': ['192.168.1.100', '10.0.0.50'],
            'known_malicious_domains': ['evil.com', 'malware.net'],
            'known_malware_hashes': []
        }
    
    def process(self, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
        """Enrich IOCs with threat intelligence"""
        self.log(f"Enriching {sum(len(v) for v in iocs.values())} IOCs")
        
        enriched = {
            'malicious_indicators': [],
            'suspicious_indicators': [],
            'clean_indicators': [],
            'severity_score': 0.0
        }
        
        # Check IPs
        if 'ipv4' in iocs:
            for ip in iocs['ipv4']:
                if ip in self.threat_db['known_malicious_ips']:
                    enriched['malicious_indicators'].append({'type': 'ip', 'value': ip})
                    enriched['severity_score'] += 0.3
                elif self._is_private_ip(ip):
                    enriched['suspicious_indicators'].append({'type': 'ip', 'value': ip})
                    enriched['severity_score'] += 0.1
        
        # Check domains
        if 'domain' in iocs:
            for domain in iocs['domain']:
                if domain in self.threat_db['known_malicious_domains']:
                    enriched['malicious_indicators'].append({'type': 'domain', 'value': domain})
                    enriched['severity_score'] += 0.3
        
        # Check for CVEs
        if 'cve' in iocs:
            for cve in iocs['cve']:
                enriched['malicious_indicators'].append({'type': 'cve', 'value': cve})
                enriched['severity_score'] += 0.4
        
        # Cap severity score at 1.0
        enriched['severity_score'] = min(enriched['severity_score'], 1.0)
        
        self.results = enriched
        self.log(f"Enrichment complete: {len(enriched['malicious_indicators'])} malicious indicators")
        return enriched
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
        except ValueError:
            return False
        
        return False


class GraphBuilderAgent(BaseAgent):
    """Agent for building knowledge graphs from threat data"""
    
    def __init__(self):
        super().__init__("Graph Builder")
        self.nodes = []
        self.edges = []
    
    def process(self, record_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build graph representation of threat data"""
        self.log("Building knowledge graph")
        
        graph = {
            'nodes': [],
            'edges': [],
            'metrics': {}
        }
        
        # Create central node for the record
        record_id = record_data.get('id', 'unknown')
        graph['nodes'].append({
            'id': f"record_{record_id}",
            'type': 'threat_record',
            'label': f"Record {record_id}"
        })
        
        # Add IOC nodes
        iocs = record_data.get('iocs', {})
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                node_id = f"{ioc_type}_{ioc}"
                graph['nodes'].append({
                    'id': node_id,
                    'type': ioc_type,
                    'label': ioc
                })
                graph['edges'].append({
                    'source': f"record_{record_id}",
                    'target': node_id,
                    'type': 'contains'
                })
        
        # Add entity nodes
        entities = record_data.get('entities', {})
        for entity_type, entity_list in entities.items():
            for entity in entity_list:
                node_id = f"{entity_type}_{entity}"
                graph['nodes'].append({
                    'id': node_id,
                    'type': entity_type,
                    'label': entity
                })
                graph['edges'].append({
                    'source': f"record_{record_id}",
                    'target': node_id,
                    'type': 'mentions'
                })
        
        # Calculate graph metrics
        graph['metrics'] = {
            'node_count': len(graph['nodes']),
            'edge_count': len(graph['edges']),
            'density': self._calculate_density(len(graph['nodes']), len(graph['edges']))
        }
        
        self.results = graph
        self.log(f"Graph built: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
        return graph
    
    def _calculate_density(self, nodes: int, edges: int) -> float:
        """Calculate graph density"""
        if nodes <= 1:
            return 0.0
        max_edges = nodes * (nodes - 1) / 2
        return edges / max_edges if max_edges > 0 else 0.0


class ScorerAgent(BaseAgent):
    """Agent for scoring threat severity"""
    
    def __init__(self):
        super().__init__("Scorer")
        
        # Scoring weights
        self.weights = {
            'ioc_count': 0.2,
            'malicious_indicators': 0.3,
            'cve_presence': 0.25,
            'threat_keywords': 0.15,
            'sentiment': 0.1
        }
    
    def process(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive threat score"""
        self.log("Calculating threat scores")
        
        # Extract relevant metrics
        ioc_count = len(analysis_data.get('iocs', {}).get('ipv4', [])) + \
                   len(analysis_data.get('iocs', {}).get('domain', []))
        
        malicious_count = len(analysis_data.get('enrichment', {}).get('malicious_indicators', []))
        
        has_cve = len(analysis_data.get('iocs', {}).get('cve', [])) > 0
        
        keyword_count = len(analysis_data.get('nlp', {}).get('keywords', []))
        
        sentiment = analysis_data.get('nlp', {}).get('sentiment', 0.0)
        
        # Calculate component scores (0-1 scale)
        ioc_score = min(ioc_count / 10, 1.0)
        malicious_score = min(malicious_count / 5, 1.0)
        cve_score = 1.0 if has_cve else 0.0
        keyword_score = min(keyword_count / 10, 1.0)
        sentiment_score = abs(sentiment)  # More extreme sentiment = higher score
        
        # Calculate weighted total
        total_score = (
            ioc_score * self.weights['ioc_count'] +
            malicious_score * self.weights['malicious_indicators'] +
            cve_score * self.weights['cve_presence'] +
            keyword_score * self.weights['threat_keywords'] +
            sentiment_score * self.weights['sentiment']
        )
        
        # Determine severity level
        if total_score >= 0.75:
            severity = 'critical'
        elif total_score >= 0.5:
            severity = 'high'
        elif total_score >= 0.25:
            severity = 'medium'
        else:
            severity = 'low'
        
        results = {
            'total_score': round(total_score, 3),
            'severity_level': severity,
            'component_scores': {
                'ioc_score': round(ioc_score, 3),
                'malicious_score': round(malicious_score, 3),
                'cve_score': round(cve_score, 3),
                'keyword_score': round(keyword_score, 3),
                'sentiment_score': round(sentiment_score, 3)
            }
        }
        
        self.results = results
        self.log(f"Scoring complete: {severity} severity ({total_score:.3f})")
        return results


class ClassifierAgent(BaseAgent):
    """Agent for classifying threats into categories: Hack, Malware, Vulnerability"""
    
    def __init__(self):
        super().__init__("Classifier")
        
        # Feature keywords for each category
        self.category_features = {
            'hack': {
                'keywords': ['breach', 'hack', 'phishing', 'ddos', 'sql injection', 
                           'brute force', 'credential', 'unauthorized', 'backdoor'],
                'weight': 1.0
            },
            'malware': {
                'keywords': ['malware', 'virus', 'trojan', 'ransomware', 'spyware',
                           'worm', 'keylogger', 'botnet', 'infection', 'payload'],
                'weight': 1.0
            },
            'vulnerability': {
                'keywords': ['vulnerability', 'cve', 'exploit', 'bug', 'flaw',
                           'patch', 'rce', 'buffer overflow', 'xss', 'injection'],
                'weight': 1.0
            }
        }
    
    def process(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify threat into categories"""
        self.log("Classifying threat type")
        
        # Get NLP analysis
        nlp_data = analysis_data.get('nlp', {})
        keywords = nlp_data.get('keywords', [])
        threat_categories = nlp_data.get('threat_category', {})
        
        # Get IOCs
        iocs = analysis_data.get('iocs', {})
        has_cve = len(iocs.get('cve', [])) > 0
        
        # Calculate scores for each category
        scores = {}
        for category, features in self.category_features.items():
            score = 0.0
            
            # Keyword matching
            category_keywords = features['keywords']
            matches = sum(1 for kw in keywords if kw in category_keywords)
            score += matches * 0.3
            
            # NLP category score
            if category in threat_categories:
                score += threat_categories[category] * 0.5
            
            # Special case: CVE presence strongly indicates vulnerability
            if category == 'vulnerability' and has_cve:
                score += 0.5
            
            scores[category] = score
        
        # Normalize scores
        total = sum(scores.values())
        if total > 0:
            confidence_scores = {k: round(v/total, 3) for k, v in scores.items()}
        else:
            confidence_scores = {k: 0.333 for k in scores.keys()}
        
        # Determine primary classification
        primary_category = max(confidence_scores, key=confidence_scores.get)
        primary_confidence = confidence_scores[primary_category]
        
        results = {
            'primary_category': primary_category,
            'primary_confidence': primary_confidence,
            'all_scores': confidence_scores,
            'is_multi_category': len([s for s in confidence_scores.values() if s > 0.3]) > 1
        }
        
        self.results = results
        self.log(f"Classification: {primary_category} ({primary_confidence:.3f} confidence)")
        return results


class MultiAgentOrchestrator:
    """Orchestrator for coordinating all agents"""
    
    def __init__(self):
        self.parser = ParserAgent()
        self.nlp_analyst = NLPAnalystAgent()
        self.enricher = EnricherAgent()
        self.graph_builder = GraphBuilderAgent()
        self.scorer = ScorerAgent()
        self.classifier = ClassifierAgent()
    
    def process_record(self, text: str, record_id: int = None) -> Dict[str, Any]:
        """Process a single threat record through all agents"""
        print(f"\n{'='*60}")
        print(f"Processing Record {record_id if record_id else 'Unknown'}")
        print(f"{'='*60}\n")
        
        # Step 1: Parse IOCs
        iocs = self.parser.process(text)
        
        # Step 2: NLP Analysis
        nlp_results = self.nlp_analyst.process(text)
        
        # Step 3: Enrich IOCs
        enrichment = self.enricher.process(iocs)
        
        # Combine data for subsequent agents
        combined_data = {
            'id': record_id,
            'text': text,
            'iocs': iocs,
            'nlp': nlp_results,
            'enrichment': enrichment,
            'entities': nlp_results.get('entities', {})
        }
        
        # Step 4: Build graph
        graph = self.graph_builder.process(combined_data)
        
        # Step 5: Score threat
        scores = self.scorer.process(combined_data)
        
        # Step 6: Classify threat
        classification = self.classifier.process(combined_data)
        
        # Compile final results
        final_results = {
            'record_id': record_id,
            'iocs': iocs,
            'nlp_analysis': nlp_results,
            'enrichment': enrichment,
            'graph': graph,
            'scores': scores,
            'classification': classification,
            'processed_at': datetime.utcnow().isoformat()
        }
        
        print(f"\n{'='*60}")
        print(f"Processing Complete")
        print(f"Category: {classification['primary_category'].upper()}")
        print(f"Severity: {scores['severity_level'].upper()}")
        print(f"Score: {scores['total_score']:.3f}")
        print(f"{'='*60}\n")
        
        return final_results
    
    def process_batch(self, records: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Process multiple records"""
        results = []
        for i, record in enumerate(records):
            text = record.get('text', '')
            record_id = record.get('id', i)
            result = self.process_record(text, record_id)
            results.append(result)
        return results
