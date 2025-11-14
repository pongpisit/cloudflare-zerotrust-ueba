# UEBA for Cloudflare Zero Trust

**User and Entity Behavior Analytics (UEBA)** system that automatically enforces adaptive security policies based on real-time user risk scores from Cloudflare Zero Trust.

## What is UEBA?

User and Entity Behavior Analytics (UEBA) is a cybersecurity process that uses machine learning and analytics to detect anomalous user behavior and potential security threats. This implementation integrates with **Cloudflare Zero Trust Risk Scoring** to provide automated, risk-based access control.

## How It Works with Cloudflare Zero Trust

### 1. **Risk Score Collection**
Cloudflare Zero Trust continuously monitors user behavior across your organization:
- Login patterns and locations
- Device posture and compliance
- Application access patterns
- Network behavior anomalies
- Authentication events
- Data access patterns

These signals are aggregated into a **risk score** for each user, categorized as:
- 🔴 **High Risk**: Suspicious behavior detected (e.g., impossible travel, unusual access patterns)
- 🟡 **Medium Risk**: Moderate anomalies detected (e.g., new device, unusual time)
- 🟢 **Low Risk**: Normal behavior patterns

### 2. **Automated Policy Enforcement**
This UEBA system automatically synchronizes user risk levels with **Cloudflare Gateway Lists**:

```
Cloudflare Zero Trust Risk Scoring
           ↓
    Risk Score Analysis
           ↓
    User Categorization
    (High/Medium/Low)
           ↓
    Gateway List Updates
           ↓
    Security Policy Enforcement
```

### 3. **Dynamic Access Control**
Gateway Lists are used in Cloudflare Zero Trust policies to:
- **Block high-risk users** from accessing sensitive applications
- **Require additional authentication** (MFA, device checks) for medium-risk users
- **Allow normal access** for low-risk users
- **Isolate suspicious sessions** using Browser Isolation
- **Apply DLP policies** based on risk level

## Real-World Use Cases

### Use Case 1: Compromised Account Detection
```
User logs in from unusual location
    ↓
Risk score increases to "High"
    ↓
User added to High Risk Gateway List
    ↓
Access to sensitive apps blocked
    ↓
Security team notified
```

### Use Case 2: Adaptive MFA
```
User shows medium-risk behavior
    ↓
Added to Medium Risk Gateway List
    ↓
Gateway policy requires additional MFA
    ↓
User must verify identity
    ↓
Access granted after verification
```

### Use Case 3: Insider Threat Prevention
```
User accesses unusual data volumes
    ↓
Risk score elevated
    ↓
DLP policies enforced
    ↓
Data exfiltration prevented
```

## Architecture

### Components

1. **Cloudflare Zero Trust Risk Scoring API**
   - Analyzes user behavior signals
   - Generates risk scores (high/medium/low)
   - Updates continuously based on new signals

2. **UEBA Worker (This Application)**
   - Fetches risk scores every minute
   - Categorizes users by risk level
   - Synchronizes Gateway Lists
   - Maintains state in KV storage

3. **Cloudflare Gateway Lists**
   - High Risk Users List
   - Medium Risk Users List
   - Low Risk Users List

4. **Zero Trust Policies**
   - Access policies using Gateway Lists
   - HTTP policies for web filtering
   - Network policies for traffic control

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                  Cloudflare Zero Trust                      │
│  (Monitors: Logins, Devices, Apps, Network, Data Access)   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Risk Scoring Engine  │
         │  (ML-based Analysis)  │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   Risk Score API      │
         │  (High/Medium/Low)    │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │    UEBA Worker        │
         │  (This Application)   │
         │  - Fetch scores       │
         │  - Categorize users   │
         │  - Update lists       │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   Gateway Lists       │
         │  - High Risk Users    │
         │  - Medium Risk Users  │
         │  - Low Risk Users     │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Security Policies    │
         │  - Block high risk    │
         │  - Require MFA        │
         │  - Apply DLP          │
         │  - Browser Isolation  │
         └───────────────────────┘
```

## Key Features

- 🤖 **Automated Risk Response**: No manual intervention required
- ⚡ **Real-time Updates**: Synchronizes every minute
- 🎯 **Precise Categorization**: Three-tier risk classification
- 🔄 **Efficient Sync**: PATCH API for minimal overhead
- 💾 **State Management**: KV storage ensures consistency
- 🛡️ **Resilient**: Retry logic handles API failures
- 📊 **Observable**: Health checks and metrics tracking
- 🎨 **User-Friendly**: Web dashboard for monitoring

## Prerequisites

1. **Cloudflare Account** with Zero Trust enabled
2. **API Token** with permissions:
   - Zero Trust: Read
   - Gateway: Edit
3. **Gateway Lists** (can be created via the worker)
4. **Wrangler CLI** installed: `npm install -g wrangler`

## Setup Instructions

### 1. Clone and Install

```bash
git clone <repository-url>
cd user-risk-zerotrust
```

### 2. Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and add your credentials:

```bash
CLOUDFLARE_ACCOUNT_ID=your-account-id-here
CLOUDFLARE_API_TOKEN=your-api-token-here
```

### 3. Create KV Namespace

```bash
# Create production KV namespace
wrangler kv:namespace create USER_RISK_KV

# Create preview KV namespace
wrangler kv:namespace create USER_RISK_KV --preview
```

Update `wrangler.toml` with the generated namespace IDs.

### 4. Create Gateway Lists (Optional)

You can create new Gateway lists via the worker API:

```bash
# Deploy the worker first
wrangler deploy

# Create new lists
curl https://your-worker.workers.dev/api/create-new-lists
```

Update `wrangler.toml` or set environment variables with the list IDs.

### 5. Set Secrets

```bash
wrangler secret put CLOUDFLARE_ACCOUNT_ID
wrangler secret put CLOUDFLARE_API_TOKEN

# Optional: Set custom list IDs
wrangler secret put HIGH_RISK_LIST_ID
wrangler secret put MEDIUM_RISK_LIST_ID
wrangler secret put LOW_RISK_LIST_ID
```

### 6. Deploy

```bash
wrangler deploy
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CLOUDFLARE_ACCOUNT_ID` | Yes | Your Cloudflare Account ID |
| `CLOUDFLARE_API_TOKEN` | Yes | API token with Zero Trust:Read and Gateway:Edit permissions |
| `HIGH_RISK_LIST_ID` | No | Gateway list ID for high risk users (auto-created if not set) |
| `MEDIUM_RISK_LIST_ID` | No | Gateway list ID for medium risk users (auto-created if not set) |
| `LOW_RISK_LIST_ID` | No | Gateway list ID for low risk users (auto-created if not set) |

### Cron Schedule

The worker runs automatically every minute (`* * * * *`) to:
1. Fetch current user risk scores
2. Categorize users by risk level
3. Update KV state (source of truth)
4. Sync Gateway lists using efficient PATCH operations

You can modify the schedule in `wrangler.toml`:

```toml
[triggers]
crons = ["0 * * * *"]  # Every hour
```

## API Endpoints

### Dashboard
- `GET /` - Web UI dashboard with risk summaries and controls

### Data Endpoints
- `GET /api/user-risk-scores` - Fetch current user risk scores
- `GET /api/gateway-lists` - View Gateway list contents
- `GET /api/health` - System health check
- `GET /api/metrics` - Execution metrics and statistics

### Management Endpoints
- `POST /api/update-risk-lists` - Manually trigger risk list sync
- `POST /api/force-cleanup` - Force complete synchronization
- `POST /api/create-new-lists` - Create new Gateway lists
- `GET /api/reconcile-lists` - Check for inconsistencies

### Testing Endpoints
- `GET /api/test-user-removal` - Test user removal functionality
- `GET /api/test-kv-sync` - Test KV-based sync system
- `GET /api/test-patch-method` - Test PATCH API method

## Integration with Zero Trust Policies

### Creating Risk-Based Access Policies

Once Gateway Lists are populated with risk-categorized users, create Zero Trust policies:

#### Example 1: Block High-Risk Users from Sensitive Apps
```
Policy Type: Access Policy
Application: Internal Dashboard
Action: Block
Condition: User Email in list "High Risk Users"
```

#### Example 2: Require Additional MFA for Medium-Risk Users
```
Policy Type: Access Policy
Application: All Applications
Action: Allow
Condition: User Email in list "Medium Risk Users"
Additional Checks: 
  - Require MFA
  - Device posture check
  - Warp client required
```

#### Example 3: Apply Browser Isolation for High-Risk Sessions
```
Policy Type: HTTP Policy
Traffic: All Web Traffic
Action: Isolate
Condition: User Email in list "High Risk Users"
Isolation Profile: High Security
```

#### Example 4: Enhanced DLP for Elevated Risk
```
Policy Type: HTTP Policy
Traffic: File Uploads/Downloads
Action: Block
Condition: User Email in list "High Risk Users" OR "Medium Risk Users"
DLP Profile: Sensitive Data Protection
```

### Policy Enforcement Flow

```
User attempts to access application
         ↓
Zero Trust evaluates user email
         ↓
Checks Gateway Lists
         ↓
┌────────────────────────────────────┐
│ High Risk List? → Block Access     │
│ Medium Risk List? → Require MFA    │
│ Low Risk List? → Allow Access      │
│ Not in any list? → Default Policy  │
└────────────────────────────────────┘
```

## How the UEBA System Works

### Automated Workflow

1. **Fetch Risk Scores**: Worker calls Cloudflare Zero Trust Risk Scoring API
2. **Categorize Users**: Users are filtered by `max_risk_level` (high/medium/low)
3. **Store in KV**: Expected state is stored in KV as source of truth
4. **Compare States**: Current Gateway list state is compared with KV state
5. **Sync Changes**: PATCH API efficiently adds/removes users as needed
6. **Verify**: Final state is verified and reconciliation flags are set if needed
7. **Policy Enforcement**: Zero Trust policies automatically apply based on list membership

### Risk Score Signals

Cloudflare Zero Trust Risk Scoring considers multiple signals:

**Authentication Signals:**
- Impossible travel (login from distant locations in short time)
- New device or browser
- Unusual login time
- Failed authentication attempts
- Password reset patterns

**Access Signals:**
- Access to unusual applications
- Access outside normal working hours
- Access from unusual locations
- Rapid access to multiple resources
- Access pattern changes

**Device Signals:**
- Device posture violations
- Missing security software
- Outdated OS or applications
- Jailbroken/rooted devices
- Unknown or unmanaged devices

**Network Signals:**
- Connection from suspicious IPs
- Use of VPN/proxy services
- Connection from high-risk countries
- Unusual network traffic patterns

**Data Signals:**
- Large data downloads
- Unusual file access patterns
- Sensitive data access
- Data exfiltration indicators

## Benefits of UEBA with Cloudflare Zero Trust

### Security Benefits

1. **Proactive Threat Detection**
   - Identify compromised accounts before damage occurs
   - Detect insider threats through behavior analysis
   - Respond to anomalies in real-time

2. **Adaptive Security Posture**
   - Security controls adjust automatically based on risk
   - No manual policy updates required
   - Continuous risk assessment and response

3. **Reduced Attack Surface**
   - High-risk users automatically restricted
   - Lateral movement prevented
   - Sensitive data protected dynamically

4. **Compliance & Audit**
   - Automated risk-based access control
   - Complete audit trail of risk changes
   - Demonstrate adaptive security controls

### Operational Benefits

1. **Zero Manual Intervention**
   - Fully automated risk response
   - No security team action required
   - Scales to thousands of users

2. **Reduced Alert Fatigue**
   - Automated response to risk changes
   - Security team focuses on high-priority incidents
   - Clear risk categorization

3. **Cost Efficiency**
   - Serverless architecture (pay per use)
   - No infrastructure to manage
   - Minimal operational overhead

4. **Fast Deployment**
   - Deploy in minutes with Wrangler
   - Integrates with existing Zero Trust
   - No agent installation required

### Business Benefits

1. **Improved User Experience**
   - Low-risk users have seamless access
   - Security friction only when needed
   - Transparent risk-based controls

2. **Risk Reduction**
   - Faster response to threats
   - Automated containment
   - Reduced breach impact

3. **Regulatory Compliance**
   - Risk-based access control
   - Continuous monitoring
   - Audit-ready logs

## Monitoring

### Health Check

```bash
curl https://your-worker.workers.dev/api/health
```

Returns:
- Cloudflare API connectivity status
- Risk Scoring API availability
- System health indicators

### Metrics

```bash
curl https://your-worker.workers.dev/api/metrics
```

Returns:
- Execution statistics
- Success/error rates
- Performance metrics
- Feature flags

## Troubleshooting

### Users Not Being Added/Removed

1. Check KV state: `GET /api/reconcile-lists`
2. Verify API permissions on your token
3. Check if lists are protected by policies
4. Use `/api/force-cleanup` to force synchronization

### Rate Limiting

The worker includes automatic retry with exponential backoff for:
- 429 (Rate Limited) responses
- 5xx (Server Error) responses
- Network errors

### API Inconsistencies

If Gateway lists don't match KV state:
1. Check `/api/reconcile-lists` for details
2. Use `/api/force-cleanup` to force sync
3. Verify no other processes are modifying the lists

## Security Best Practices

1. **Never commit secrets** to version control
2. **Use Wrangler Secrets** for sensitive data
3. **Rotate API tokens** regularly
4. **Limit API token permissions** to only what's needed
5. **Monitor execution logs** for suspicious activity
6. **Use separate lists** for testing vs production

## Development

### Local Testing

```bash
# Run locally with wrangler
wrangler dev

# Test specific endpoints
curl http://localhost:8787/api/health
```

### Testing Changes

```bash
# Test user removal
curl https://your-worker.workers.dev/api/test-user-removal

# Test KV sync
curl https://your-worker.workers.dev/api/test-kv-sync

# Test PATCH method
curl https://your-worker.workers.dev/api/test-patch-method
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues and questions:
- Open an issue on GitHub
- Check Cloudflare Workers documentation
- Review Cloudflare Zero Trust documentation

## Acknowledgments

- Built on Cloudflare Workers platform
- Uses Cloudflare Zero Trust Risk Scoring API
- Leverages Cloudflare Gateway for user list management
