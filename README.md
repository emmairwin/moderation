# GitHub Repository Moderation Evaluator

A comprehensive tool to analyze the moderation stance of GitHub repositories by detecting hidden comments, AI-generated content, harmful sentiment, and response time issues.

> **⚠️ Important Notice:**  
> This tool was created with assistance from AI and is intended for **testing and educational purposes only**. Results should not be used as the sole basis for moderation decisions. Always apply human judgment and consider context when evaluating repository content.

## Overview

This tool evaluates four key moderation areas:
1. **Hidden Comments** - Detects spam, abuse, and off-topic comments that have been minimized
2. **AI-Generated Content** - Identifies "AI slop" in issues, PRs, and comments using pattern matching and LLM analysis
3. **Harmful Content & Sentiment** - Flags discriminatory language, harassment, hate speech, and spam
4. **Issue/PR Management** - Analyzes response times to identify management issues

## Prerequisites

### Required Software
- **Python 3.8+**
- **Ollama** with a language model (default: `llama3.2`)
- **Git** (for cloning)

### Install Ollama
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the default model
ollama pull llama3.2
```

### GitHub Token
You'll need a GitHub Personal Access Token with these permissions:
- `repo` (for private repos) or `public_repo` (for public repos only)
- `read:org` (recommended for better employee detection)

[Create a token here](https://github.com/settings/tokens)

## Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd moderation
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Create environment file:**
```bash
cp .env.example .env
```

4. **Add your GitHub token to `.env`:**
```bash
GITHUB_TOKEN=your_github_token_here
```

## Usage

### Basic Usage
```bash
python index.py <repository-url>
```

### Examples
```bash
# Analyze a specific repository
python index.py https://github.com/owner/repo

# Use owner/repo format
python index.py owner/repo

# Disable sentiment analysis for faster processing
python index.py owner/repo --no-sentiment

# Analyze only recent activity (last 30 days)
python index.py owner/repo --days 30

# Use a different Ollama model
python index.py owner/repo --model llama2

# Save report to file
python index.py owner/repo --output report.md

# Provide token via command line
python index.py owner/repo --token your_token_here
```

### Command Line Options
- `--token` - GitHub token (overrides .env file)
- `--model` - Ollama model name (default: llama3.2)
- `--days` - Days back to analyze (default: all time)
- `--output` - Output file for report (default: stdout)
- `--no-sentiment` - Disable sentiment analysis for faster processing

## What to Expect

### Analysis Process
The tool will:
1. **Initialize** - Connect to GitHub API and Ollama
2. **Analyze Hidden Comments** - Use GraphQL to find minimized comments
3. **Process Issues & PRs** - Examine all issues and pull requests
4. **Generate Report** - Create a comprehensive moderation report

### Sample Output
```
Initializing GitHub client...
Initializing content analyzer with model: llama3.2
Analyzing repository: owner/repo
Analyzing hidden comments...
Found 2 minimized/hidden comments:
  - SPAM: 1
  - ABUSE: 1
Analyzing all issues and PRs...
Generating report...
```

### Report Structure
The generated report includes:

#### 1. Executive Summary
- Repository information
- Overall moderation score (0-4 categories detected)
- Assessment level and recommendations

#### 2. Detailed Analysis
- **Hidden Comments**: Count and breakdown by reason (SPAM, ABUSE, OFF_TOPIC, etc.)
- **AI-Generated Content**: Issues, comments, and PRs flagged as AI slop with detection reasons
- **Harmful Content**: Categorized breakdown with detailed table showing specific instances
- **Response Times**: Slow and non-responsive issues analysis

#### 3. Sample Report Section
```markdown
### 3. Harmful Content & Sentiment
- Harmful content found: 2
- Status: ⚠️ Harmful content detected

**Harmful Content by Category:**
- Spam: 1
- Harassment: 1

**Detailed Breakdown:**
| Type | Location | Category | Preview |
|------|----------|----------|---------|
| Comment | Issue #123 Comment | Spam | Check out our amazing services at... |
| Issue | #456 | Harassment | You are completely stupid and wrong... |
```

## AI Slop Detection Criteria

The tool identifies AI-generated content using:

### Pattern-Based Detection
- Generic security vulnerability reports
- Formulaic language structures
- AI-like formal language patterns
- Template-based content

### LLM Analysis
- Extremely generic language without specifics
- Repetitive or redundant information
- Lack of contextual understanding
- Unnaturally formal tone
- Excessive filler text

### Conservative Approach
- Requires ≥3 pattern matches for flagging
- LLM verification for longer content
- Avoids false positives on legitimate content

## Harmful Content Categories

- **DISCRIMINATION** - Language targeting marginalized groups
- **HARASSMENT** - Bullying or threatening language  
- **HATE_SPEECH** - Content promoting hate or violence
- **EXCLUSIONARY** - Dismissive language toward underrepresented groups
- **MICROAGGRESSION** - Subtle bias or microaggressions
- **SPAM** - Commercial promotion, selling products/services
- **OTHER** - Other harmful content

## Performance & Rate Limits

### Expected Runtime
- Small repos (< 100 issues): 2-5 minutes
- Medium repos (100-500 issues): 5-15 minutes  
- Large repos (500+ issues): 15+ minutes

### Rate Limiting
- The tool automatically handles GitHub API rate limits
- Uses retry strategies and sleep intervals
- GraphQL queries for efficient data retrieval

### Sentiment Analysis Impact
- With sentiment: More thorough but slower
- Without `--no-sentiment`: 2-3x faster but less comprehensive

## Troubleshooting

### Common Issues

**"Could not connect to Ollama model"**
```bash
# Make sure Ollama is running
ollama serve

# Pull the model if missing
ollama pull llama3.2
```

**"GitHub token required"**
- Check your `.env` file exists
- Verify token has correct permissions
- Try passing token via `--token` flag

**"GraphQL errors"**
- Token may need additional permissions
- Some repos may restrict access to minimized comments
- This is normal and won't affect other analysis

**Rate limiting errors**
- Tool automatically waits for rate limit reset
- Consider using `--days` to limit scope
- Ensure token has proper permissions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your license here]

## Support

For issues, questions, or feature requests, please open an issue on GitHub.
