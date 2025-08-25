#!/usr/bin/env python3
"""
GitHub Repository Moderation Evaluator

This script evaluates the moderation stance of a GitHub repository by analyzing:
1. Hidden comments (spam, abuse, off-topic)
2. AI-generated "slop" content
3. Poor sentiment/harmful content
4. Issue/PR management responsiveness

Usage: python github_moderation_eval.py <repo_url>
"""

import os
import sys
import json
import time
import re
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ollama
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

@dataclass
class ModerationMetrics:
    """Data class to store moderation metrics"""
    hidden_comments_count: int = 0
    hidden_comments_reasons: Optional[Dict[str, int]] = None
    ai_slop_issues: int = 0
    ai_slop_comments: int = 0
    ai_slop_prs: int = 0
    ai_slop_reasons: Optional[List[str]] = None  # New field to track reasons
    harmful_content_count: int = 0
    harmful_content_categories: Optional[Dict[str, int]] = None
    harmful_content_details: Optional[List[Dict[str, str]]] = None  # Store details for each flagged item
    harmful_by_employees: int = 0
    slow_response_issues: int = 0
    no_response_issues: int = 0
    total_issues_analyzed: int = 0
    total_prs_analyzed: int = 0
    total_comments_analyzed: int = 0
    
    def __post_init__(self):
        if self.ai_slop_reasons is None:
            self.ai_slop_reasons = []
        if self.hidden_comments_reasons is None:
            self.hidden_comments_reasons = {}
        if self.harmful_content_categories is None:
            self.harmful_content_categories = {}
        if self.harmful_content_details is None:
            self.harmful_content_details = []
            self.hidden_comments_reasons = {}
        if self.harmful_content_categories is None:
            self.harmful_content_categories = {}
        if self.harmful_content_details is None:
            self.harmful_content_details = []

class GitHubClient:
    """GitHub API client with rate limiting and GraphQL support"""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GitHub token required. Set GITHUB_TOKEN environment variable or pass token parameter.")
        
        self.session = requests.Session()
        # Setup retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        })
    
    def graphql_query(self, query: str, variables: Optional[Dict] = None) -> Dict:
        """Execute GraphQL query"""
        response = self.session.post(
            'https://api.github.com/graphql',
            json={'query': query, 'variables': variables or {}}
        )
        response.raise_for_status()
        return response.json()
    
    def rest_api_get(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make REST API GET request"""
        url = f"https://api.github.com{endpoint}"
        response = self.session.get(url, params=params or {})
        
        # Handle rate limiting
        if response.status_code == 403 and 'rate limit' in response.text.lower():
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            sleep_time = max(reset_time - int(time.time()) + 5, 60)
            print(f"Rate limited. Sleeping for {sleep_time} seconds...")
            time.sleep(sleep_time)
            response = self.session.get(url, params=params or {})
        
        response.raise_for_status()
        return response.json()

class ContentAnalyzer:
    """Analyzes content using local LLM (Ollama)"""
    
    def __init__(self, model_name: str = "llama3.2"):
        self.model_name = model_name
        self.client = ollama.Client()
        
        # Verify model is available
        try:
            self.client.chat(model=model_name, messages=[{"role": "user", "content": "test"}])
        except Exception as e:
            print(f"Warning: Could not connect to Ollama model '{model_name}'. Error: {e}")
            print("Make sure Ollama is running and the model is installed.")
    
    def is_ai_slop(self, content: str, content_type: str = "comment") -> Tuple[bool, List[str]]:
        """
        Determine if content appears to be AI-generated "slop"
        
        Returns: (is_slop, reasons_list)
        
        Checks for:
        - Generic and vague language
        - Repetitiveness and redundancy
        - Lack of specificity or contextual understanding
        - Overly formal or polished tone
        - Filler text and unnecessary information
        - Perfect formatting without substance
        - Patterns from known AI slop examples
        """
        if not content or len(content.strip()) == 0:
            return False, []
        
        reasons = []
        
        # First, check for common AI slop patterns from real examples
        ai_slop_indicators = {
            # Generic vulnerability report patterns from curl slop examples
            "Generic Security Vulnerability Pattern": [
                r"buffer overflow vulnerability in.*leading to remote code execution",
                r"critical.*vulnerability.*disclosed on the internet",
                r"exploitable format string vulnerability in .* function",
                r"use of a broken or risky cryptographic algorithm.*cwe-\d+",
                r"memory leak.*via.*handling.*leading to",
                r"stack-based buffer overflow.*option handling.*remote",
                r"use-after-free.*callback via.*ssl_get",
                r"exposure of hard-coded private keys.*credentials",
                r"vulnerability report:.*local file disclosure via",
                r"http/\d.*flood vulnerability.*continuation",
                r"stream dependency cycle exploit.*http/3",
                r"proxy bypass via.*curlopt_customrequest.*verb tunneling",
                r"request smuggling vulnerability analysis.*curl security",
                r"disk space exhaustion leading to.*denial of service.*dos",
                r"public exposure of security audit file.*cwe-321",
            ],
            
            "Generic Security Terminology": [
                r"cwe-\d+.*in.*via.*leading to.*remote code execution",
                r"vulnerability.*analysis.*security report.*comprehensive.*examination",
                r"exploitation.*via.*malicious.*input.*buffer overflow",
            ],
            
            "Generic Technical Phrases": [
                r"comprehensive analysis of.*security implications.*detailed examination",
                r"thorough investigation reveals.*critical issues.*extensive research",
                r"in-depth study of.*exploitation techniques.*comprehensive.*analysis",
            ],
            
            "AI-like Formal Language": [
                r"it is important to note that.*furthermore.*it should be mentioned",
                r"additionally.*one must consider.*consequently.*this results in",
                r"in conclusion.*the aforementioned.*as previously discussed",
                r"moreover.*it is worth mentioning.*therefore.*one can conclude",
            ],
            
            "Formulaic Structure": [
                r"step 1:.*step 2:.*step 3:.*step 4:",
                r"method 1.*method 2.*method 3.*comprehensive",
                r"approach 1:.*approach 2:.*approach 3:.*analysis",
            ],
        }
        
        # Check for direct pattern matches - be more restrictive
        content_lower = content.lower()
        pattern_matches = 0
        
        for category, patterns in ai_slop_indicators.items():
            category_matches = 0
            for pattern in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE | re.DOTALL):
                    category_matches += 1
                    pattern_matches += 1
            
            if category_matches > 0:
                reasons.append(f"{category} ({category_matches} matches)")
        
        # Only flag as AI slop if we have strong pattern matches
        if pattern_matches >= 3:  # Increased threshold from 2 to 3
            return True, reasons
        
        # Only use LLM for longer content that has some suspicious patterns
        if len(content) < 200 or pattern_matches == 0:
            return False, reasons
        
        prompt = f"""
        Analyze the following {content_type} and determine if it appears to be AI-generated "slop" content.
        
        IMPORTANT: Be very conservative. Only flag content as AI slop if it shows MULTIPLE clear indicators.
        
        Real human content often includes:
        - Personal opinions and experiences
        - Informal language and contractions
        - Context-specific references
        - Natural typos or informal grammar
        - Specific technical details
        - References to actual tools, versions, or specific scenarios
        
        Only flag as AI slop if the content shows MULTIPLE of these indicators:
        1. Extremely generic and vague language without ANY specific details
        2. Multiple repetitive phrases or redundant information
        3. Complete lack of specific contextual understanding
        4. Unnaturally formal tone throughout (not just professional)
        5. Excessive filler text with no substance
        6. Perfect formatting but completely lacking substantial content
        7. Multiple template-like structures
        8. Generic vulnerability reports that match EXACTLY these patterns:
           - "Buffer overflow vulnerability in [generic] leading to remote code execution"
           - "Critical [generic] vulnerability disclosed on the internet"
           - Multiple formulaic security report titles without specific technical context
        
        Content length: {len(content)} characters
        
        Content to analyze:
        \"\"\"
        {content[:1500]}  # Increased from 1000 to allow more context
        \"\"\"
        
        Respond with only "YES" if this shows MULTIPLE clear indicators of AI-generated slop, or "NO" if it appears to be genuine human content or you're uncertain.
        """
        
        try:
            response = self.client.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}]
            )
            result = response['message']['content'].strip().upper()
            llm_detected = result.startswith("YES")
            
            # Only add LLM reason if it detected AND we also have pattern matches
            if llm_detected and pattern_matches > 0:
                reasons.append("LLM Analysis: Multiple AI slop indicators detected")
                return True, reasons
            elif llm_detected:
                # LLM detected but no patterns - be more cautious
                reasons.append("LLM Analysis: Potential AI content (low confidence)")
                return False, reasons  # Don't flag without pattern confirmation
            
            return False, reasons
            
        except Exception as e:
            print(f"Error analyzing AI slop: {e}")
            # Fall back to pattern-based detection only for strong matches
            if pattern_matches >= 3:
                reasons.append("Pattern-based detection (LLM unavailable)")
                return True, reasons
            return False, reasons
    
    def analyze_sentiment_and_harm(self, content: str, author: str = "") -> Tuple[bool, bool, str]:
        """
        Analyze content for negative sentiment and potential harm to marginalized groups
        
        Returns: (is_harmful, is_by_employee, harm_category)
        """
        if not content or len(content.strip()) < 10:
            return False, False, ""
        
        prompt = f"""
        Analyze the following content for harmful sentiment, spam, or content that could cause harm to marginalized people or groups.
        
        Look for:
        1. Discriminatory language against marginalized groups (race, gender, sexuality, disability, religion, etc.)
        2. Harassment, bullying, or threatening language
        3. Content that promotes hate or violence
        4. Exclusionary or dismissive language toward underrepresented groups
        5. Microaggressions or subtle bias
        6. SPAM - ONLY flag as spam if content is clearly trying to SELL something or promote commercial services/products. DO NOT flag legitimate technical discussions, feature requests, bug reports, or open source contributions as spam.
        
        IMPORTANT FOR SPAM DETECTION:
        - Technical discussions about code, branches, versions, updates = NOT SPAM
        - Feature requests or bug reports = NOT SPAM  
        - Open source contributions or suggestions = NOT SPAM
        - Only flag if explicitly selling products, services, or promoting commercial offerings
        - Look for words like "buy", "purchase", "our services", "contact us", commercial URLs, prices, etc.
        
        Content to analyze:
        \"\"\"
        {content[:1000]}
        \"\"\"
        
        If harmful or spam, respond with ONLY ONE WORD from these categories:
        DISCRIMINATION
        HARASSMENT  
        HATE_SPEECH
        EXCLUSIONARY
        MICROAGGRESSION
        SPAM
        OTHER
        
        If not harmful and not spam, respond with only: SAFE
        """
        
        try:
            response = self.client.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}]
            )
            result = response['message']['content'].strip().upper()
            
            # Check if result is one of our harmful categories
            harmful_categories = ['DISCRIMINATION', 'HARASSMENT', 'HATE_SPEECH', 'EXCLUSIONARY', 'MICROAGGRESSION', 'SPAM', 'OTHER']
            
            if result in harmful_categories:
                is_harmful = True
                category = result
            elif result == 'SAFE':
                is_harmful = False
                category = ""
            else:
                # If LLM returns something unexpected, try to parse it
                for cat in harmful_categories:
                    if cat in result:
                        is_harmful = True
                        category = cat
                        break
                else:
                    is_harmful = False
                    category = ""
            
            # Simple heuristic to detect if author might be an employee
            # This would need to be enhanced with actual org member checking
            is_employee = bool(re.search(r'(admin|maintainer|owner|member)', author.lower()))
            
            return is_harmful, is_employee, category
        except Exception as e:
            print(f"Error analyzing sentiment: {e}")
            return False, False, ""

class ModerationEvaluator:
    """Main class to evaluate repository moderation"""
    
    def __init__(self, github_client: GitHubClient, content_analyzer: ContentAnalyzer, enable_sentiment_analysis: bool = True):
        self.github = github_client
        self.analyzer = content_analyzer
        self.metrics = ModerationMetrics()
        self.enable_sentiment_analysis = enable_sentiment_analysis
    
    def parse_repo_url(self, repo_url: str) -> Tuple[str, str]:
        """Parse repository URL to extract owner and repo name"""
        if repo_url.startswith('https://github.com/'):
            parts = repo_url.replace('https://github.com/', '').strip('/').split('/')
        else:
            parts = repo_url.strip('/').split('/')
        
        if len(parts) >= 2:
            return parts[0], parts[1]
        else:
            raise ValueError(f"Invalid repository URL: {repo_url}")
    
    def get_hidden_comments(self, owner: str, repo: str) -> Tuple[int, Dict[str, int]]:
        """
        Count hidden comments in issues and PRs for spam, abuse, and off-topic reasons
        Uses GraphQL API to attempt to access minimized comments
        
        Returns: (total_count, reasons_dict)
        """
        print("Analyzing hidden/minimized comments using GraphQL...")
        
        # GraphQL query to get issues and PRs with comments, including minimized state
        query = """
        query($owner: String!, $name: String!, $cursor: String) {
          repository(owner: $owner, name: $name) {
            issues(first: 50, after: $cursor, states: [OPEN, CLOSED]) {
              pageInfo {
                hasNextPage
                endCursor
              }
              nodes {
                number
                title
                comments(first: 100) {
                  nodes {
                    isMinimized
                    minimizedReason
                    body
                    author {
                      login
                    }
                  }
                }
              }
            }
            pullRequests(first: 50, after: $cursor, states: [OPEN, CLOSED, MERGED]) {
              pageInfo {
                hasNextPage
                endCursor
              }
              nodes {
                number
                title
                comments(first: 100) {
                  nodes {
                    isMinimized
                    minimizedReason
                    body
                    author {
                      login
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        hidden_count = 0
        hidden_reasons = {}
        
        try:
            # Analyze Issues
            cursor = None
            while True:
                variables = {
                    "owner": owner,
                    "name": repo,
                    "cursor": cursor
                }
                
                result = self.github.graphql_query(query, variables)
                
                if 'errors' in result:
                    print(f"GraphQL errors: {result['errors']}")
                    break
                
                issues = result.get('data', {}).get('repository', {}).get('issues', {})
                if not issues or not issues.get('nodes'):
                    break
                
                for issue in issues['nodes']:
                    for comment in issue.get('comments', {}).get('nodes', []):
                        if comment.get('isMinimized'):
                            hidden_count += 1
                            reason = comment.get('minimizedReason', 'UNKNOWN')
                            hidden_reasons[reason] = hidden_reasons.get(reason, 0) + 1
                
                if not issues['pageInfo']['hasNextPage']:
                    break
                cursor = issues['pageInfo']['endCursor']
            
            # Analyze Pull Requests  
            cursor = None
            while True:
                variables = {
                    "owner": owner,
                    "name": repo,
                    "cursor": cursor
                }
                
                result = self.github.graphql_query(query, variables)
                
                if 'errors' in result:
                    print(f"GraphQL errors: {result['errors']}")
                    break
                
                prs = result.get('data', {}).get('repository', {}).get('pullRequests', {})
                if not prs or not prs.get('nodes'):
                    break
                
                for pr in prs['nodes']:
                    for comment in pr.get('comments', {}).get('nodes', []):
                        if comment.get('isMinimized'):
                            hidden_count += 1
                            reason = comment.get('minimizedReason', 'UNKNOWN')
                            hidden_reasons[reason] = hidden_reasons.get(reason, 0) + 1
                
                if not prs['pageInfo']['hasNextPage']:
                    break
                cursor = prs['pageInfo']['endCursor']
                
        except Exception as e:
            print(f"Error accessing hidden comments via GraphQL: {e}")
            print("Note: Hidden comments analysis may require additional permissions or may not be available")
            return 0, {}
        
        if hidden_count > 0:
            print(f"Found {hidden_count} minimized/hidden comments:")
            for reason, count in hidden_reasons.items():
                print(f"  - {reason}: {count}")
        else:
            print("No minimized/hidden comments found")
            
        return hidden_count, hidden_reasons
    
    def analyze_issues_and_prs(self, owner: str, repo: str, days_back: Optional[int] = None):
        """Analyze all issues and PRs for AI slop and response times"""
        
        # Analyze Issues
        page = 1
        while True:
            try:
                params = {
                    'state': 'all',
                    'per_page': 100,
                    'page': page
                }
                
                # Only add since filter if days_back is specified
                if days_back is not None:
                    since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
                    params['since'] = since_date
                
                issues = self.github.rest_api_get(
                    f'/repos/{owner}/{repo}/issues',
                    params=params
                )
                
                if not issues:
                    break
                
                for issue in issues:
                    if 'pull_request' in issue:  # Skip PRs in issues endpoint
                        continue
                    
                    self.metrics.total_issues_analyzed += 1
                    
                    # Check if issue is AI slop
                    issue_content = f"{issue.get('title', '')} {issue.get('body', '')}"
                    is_slop, slop_reasons = self.analyzer.is_ai_slop(issue_content, "issue")
                    if is_slop:
                        self.metrics.ai_slop_issues += 1
                        for reason in slop_reasons:
                            if self.metrics.ai_slop_reasons is not None and reason not in self.metrics.ai_slop_reasons:
                                self.metrics.ai_slop_reasons.append(reason)
                    
                    # Check sentiment (if enabled)
                    if self.enable_sentiment_analysis:
                        is_harmful, is_by_employee, harm_category = self.analyzer.analyze_sentiment_and_harm(
                            issue_content, issue.get('user', {}).get('login', '')
                        )
                        if is_harmful:
                            self.metrics.harmful_content_count += 1
                            if harm_category and self.metrics.harmful_content_categories is not None:
                                self.metrics.harmful_content_categories[harm_category] = self.metrics.harmful_content_categories.get(harm_category, 0) + 1
                            
                            # Store details for reporting
                            if self.metrics.harmful_content_details is not None:
                                content_preview = (issue_content[:100] + "..." if len(issue_content) > 100 else issue_content)
                                self.metrics.harmful_content_details.append({
                                    'type': 'Issue',
                                    'number': str(issue.get('number', 'Unknown')),
                                    'category': harm_category.replace('_', ' ').title() if harm_category else 'Other',
                                    'preview': content_preview.replace('\n', ' ').replace('\r', ' ')
                                })
                            
                            if is_by_employee:
                                self.metrics.harmful_by_employees += 1
                    
                    # Check response time
                    created_at = datetime.fromisoformat(issue['created_at'].replace('Z', '+00:00'))
                    
                    # Get comments to check response time
                    if issue.get('comments', 0) > 0:
                        comments = self.github.rest_api_get(f"/repos/{owner}/{repo}/issues/{issue['number']}/comments")
                        if comments:
                            first_response = datetime.fromisoformat(comments[0]['created_at'].replace('Z', '+00:00'))
                            response_time = (first_response - created_at).days
                            if response_time > 7:  # Slow response threshold
                                self.metrics.slow_response_issues += 1
                            
                            # Analyze comment sentiment
                            for comment in comments[:10]:  # Limit to first 10 comments
                                self.metrics.total_comments_analyzed += 1
                                comment_content = comment.get('body', '')
                                
                                is_slop, slop_reasons = self.analyzer.is_ai_slop(comment_content, "comment")
                                if is_slop:
                                    self.metrics.ai_slop_comments += 1
                                    for reason in slop_reasons:
                                        if self.metrics.ai_slop_reasons is not None and reason not in self.metrics.ai_slop_reasons:
                                            self.metrics.ai_slop_reasons.append(reason)
                                
                                if self.enable_sentiment_analysis:
                                    is_harmful, is_by_employee, harm_category = self.analyzer.analyze_sentiment_and_harm(
                                        comment_content, comment.get('user', {}).get('login', '')
                                    )
                                    if is_harmful:
                                        self.metrics.harmful_content_count += 1
                                        if harm_category and self.metrics.harmful_content_categories is not None:
                                            self.metrics.harmful_content_categories[harm_category] = self.metrics.harmful_content_categories.get(harm_category, 0) + 1
                                        
                                        # Store details for reporting
                                        if self.metrics.harmful_content_details is not None:
                                            content_preview = (comment_content[:100] + "..." if len(comment_content) > 100 else comment_content)
                                            self.metrics.harmful_content_details.append({
                                                'type': 'Comment',
                                                'number': f"Issue #{issue['number']} Comment",
                                                'category': harm_category.replace('_', ' ').title() if harm_category else 'Other',
                                                'preview': content_preview.replace('\n', ' ').replace('\r', ' ')
                                            })
                                        
                                        if is_by_employee:
                                            self.metrics.harmful_by_employees += 1
                    else:
                        # No response
                        if (datetime.now() - created_at.replace(tzinfo=None)).days > 14:
                            self.metrics.no_response_issues += 1
                
                page += 1
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                print(f"Error analyzing issues page {page}: {e}")
                break
        
        # Analyze Pull Requests
        page = 1
        while True:
            try:
                prs = self.github.rest_api_get(
                    f'/repos/{owner}/{repo}/pulls',
                    params={
                        'state': 'all',
                        'per_page': 100,
                        'page': page
                    }
                )
                
                if not prs:
                    break
                
                for pr in prs:
                    self.metrics.total_prs_analyzed += 1
                    
                    # Check if PR is AI slop
                    pr_content = f"{pr.get('title', '')} {pr.get('body', '')}"
                    is_slop, slop_reasons = self.analyzer.is_ai_slop(pr_content, "pull request")
                    if is_slop:
                        self.metrics.ai_slop_prs += 1
                        for reason in slop_reasons:
                            if self.metrics.ai_slop_reasons is not None and reason not in self.metrics.ai_slop_reasons:
                                self.metrics.ai_slop_reasons.append(reason)
                    
                    # Check sentiment (if enabled)
                    if self.enable_sentiment_analysis:
                        is_harmful, is_by_employee, harm_category = self.analyzer.analyze_sentiment_and_harm(
                            pr_content, pr.get('user', {}).get('login', '')
                        )
                        if is_harmful:
                            self.metrics.harmful_content_count += 1
                            if harm_category and self.metrics.harmful_content_categories is not None:
                                self.metrics.harmful_content_categories[harm_category] = self.metrics.harmful_content_categories.get(harm_category, 0) + 1
                            
                            # Store details for reporting
                            if self.metrics.harmful_content_details is not None:
                                content_preview = (pr_content[:100] + "..." if len(pr_content) > 100 else pr_content)
                                self.metrics.harmful_content_details.append({
                                    'type': 'PR',
                                    'number': f"#{pr.get('number', 'Unknown')}",
                                    'category': harm_category.replace('_', ' ').title() if harm_category else 'Other',
                                    'preview': content_preview.replace('\n', ' ').replace('\r', ' ')
                                })
                            
                            if is_by_employee:
                                self.metrics.harmful_by_employees += 1
                
                page += 1
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                print(f"Error analyzing PRs page {page}: {e}")
                break
    
    def calculate_moderation_score(self) -> Tuple[int, str]:
        """Calculate overall moderation score and recommendation"""
        issues_count = 0
        
        # Check each category
        if self.metrics.hidden_comments_count > 0:
            issues_count += 1
        
        if (self.metrics.ai_slop_issues + self.metrics.ai_slop_comments + self.metrics.ai_slop_prs) > 0:
            issues_count += 1
        
        if self.enable_sentiment_analysis and self.metrics.harmful_content_count > 0:
            issues_count += 1
        
        if (self.metrics.slow_response_issues + self.metrics.no_response_issues) > 0:
            issues_count += 1
        
        # Adjust max score if sentiment analysis is disabled
        max_score = 4 if self.enable_sentiment_analysis else 3
        
        # Determine recommendation based on user specifications
        recommendations = {
            4: "Critical need for moderation review",
            3: "Immediate need for moderation review", 
            2: "Important need for moderation review",
            1: "Moderate need for moderation review",
            0: "Great - no moderation issues detected"
        }
        
        return issues_count, recommendations[issues_count]
    
    def generate_report(self, owner: str, repo: str) -> str:
        """Generate moderation report"""
        score, recommendation = self.calculate_moderation_score()
        max_score = 4 if self.enable_sentiment_analysis else 3
        
        report = f"""
# GitHub Repository Moderation Report

**Repository:** {owner}/{repo}  
**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Overall Score:** {score}/{max_score} issue categories detected  
**Assessment:** {recommendation}  
**Sentiment Analysis:** {'Enabled' if self.enable_sentiment_analysis else 'Disabled'}

## Detailed Metrics

### 1. Hidden Comments (Spam/Abuse/Off-topic)
- Hidden comments found: {self.metrics.hidden_comments_count}
- Status: {'⚠️ Hidden comments detected' if self.metrics.hidden_comments_count > 0 else '✅ No hidden comments detected'}"""
        
        if self.metrics.hidden_comments_reasons:
            report += "\n- Breakdown by reason:"
            for reason, count in self.metrics.hidden_comments_reasons.items():
                report += f"\n  - {reason}: {count}"
        
        report += f"""

### 2. AI-Generated Content ("Slop")
- AI slop issues found: {self.metrics.ai_slop_issues}
- AI slop comments found: {self.metrics.ai_slop_comments}  
- AI slop PRs found: {self.metrics.ai_slop_prs}
- Total AI slop items found: {self.metrics.ai_slop_issues + self.metrics.ai_slop_comments + self.metrics.ai_slop_prs}
- Status: {'⚠️ AI-generated content detected' if (self.metrics.ai_slop_issues + self.metrics.ai_slop_comments + self.metrics.ai_slop_prs) > 0 else '✅ No AI-generated content detected'}"""
        
        if self.metrics.ai_slop_reasons:
            report += f"""
- Detection reasons: {', '.join(self.metrics.ai_slop_reasons)}"""
        
        report += """

### 3. Harmful Content & Sentiment
"""
        
        if self.enable_sentiment_analysis:
            report += f"""- Harmful content found: {self.metrics.harmful_content_count}
- Harmful content by employees: {self.metrics.harmful_by_employees}
- Status: {'⚠️ Harmful content detected' if self.metrics.harmful_content_count > 0 else '✅ No harmful content detected'}"""
            
            if self.metrics.harmful_content_categories:
                report += "\n\n**Harmful Content by Category:**"
                for category, count in self.metrics.harmful_content_categories.items():
                    category_display = category.replace('_', ' ').title()
                    report += f"\n- {category_display}: {count}"
            
            if self.metrics.harmful_content_details:
                report += "\n\n**Detailed Breakdown:**"
                report += "\n| Type | Location | Category | Preview |"
                report += "\n|------|----------|----------|---------|"
                for detail in self.metrics.harmful_content_details:
                    preview = detail['preview'][:50] + "..." if len(detail['preview']) > 50 else detail['preview']
                    report += f"\n| {detail['type']} | {detail['number']} | {detail['category']} | {preview} |"
        else:
            report += "- Status: ⏭️ Skipped (sentiment analysis disabled)"
        
        report += f"""

### 4. Issue/PR Management
- Slow response issues found (>7 days): {self.metrics.slow_response_issues}
- No response issues found (>14 days): {self.metrics.no_response_issues}
- Total management issues found: {self.metrics.slow_response_issues + self.metrics.no_response_issues}
- Status: {'⚠️ Response time issues detected' if (self.metrics.slow_response_issues + self.metrics.no_response_issues) > 0 else '✅ No response time issues detected'}

## Analysis Summary
- Total issues analyzed: {self.metrics.total_issues_analyzed}
- Total PRs analyzed: {self.metrics.total_prs_analyzed}
- Total comments analyzed: {self.metrics.total_comments_analyzed}

## Final Assessment

Based on the analysis, this repository has **{score}** out of {max_score} potential moderation issue categories detected.

**Assessment Level:** {recommendation}
"""
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Evaluate GitHub repository moderation stance')
    parser.add_argument('repo_url', help='GitHub repository URL or owner/repo format')
    parser.add_argument('--token', help='GitHub token (or set GITHUB_TOKEN env var)')
    parser.add_argument('--model', default='llama3.2', help='Ollama model name to use')
    parser.add_argument('--days', type=int, help='Days back to analyze (optional - if not specified, analyzes all issues/PRs)')
    parser.add_argument('--output', help='Output file for report (default: stdout)')
    parser.add_argument('--no-sentiment', action='store_true', 
                       help='Disable sentiment analysis for faster processing')
    
    args = parser.parse_args()
    
    try:
        # Initialize components
        print("Initializing GitHub client...")
        github_client = GitHubClient(args.token)
        
        print(f"Initializing content analyzer with model: {args.model}")
        content_analyzer = ContentAnalyzer(args.model)
        
        enable_sentiment = not args.no_sentiment
        evaluator = ModerationEvaluator(github_client, content_analyzer, enable_sentiment)
        
        if not enable_sentiment:
            print("Note: Sentiment analysis disabled - this will be faster but less comprehensive")
        
        # Parse repository
        owner, repo = evaluator.parse_repo_url(args.repo_url)
        print(f"Analyzing repository: {owner}/{repo}")
        
        # Run analysis
        print("Analyzing hidden comments...")
        evaluator.metrics.hidden_comments_count, evaluator.metrics.hidden_comments_reasons = evaluator.get_hidden_comments(owner, repo)
        
        if args.days:
            print(f"Analyzing issues and PRs from the last {args.days} days...")
        else:
            print("Analyzing all issues and PRs...")
        evaluator.analyze_issues_and_prs(owner, repo, args.days)
        
        # Generate report
        print("Generating report...")
        report = evaluator.generate_report(owner, repo)
        
        # Output report
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Report saved to: {args.output}")
        else:
            print(report)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
