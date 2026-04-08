# Data Model

The application uses PostgreSQL with Prisma ORM. The schema covers multi-tenant auth, project management, conversation history, billing, and deployments.

Source file: `prisma/schema.prisma`

## Entity Relationships

```
Organization --(1:N)--> OrgMembership --(N:1)--> User
Organization --(1:N)--> Project
Organization --(1:N)--> UsageEvent
Organization --(1:N)--> CreditLedgerEntry

User --(1:N)--> OrgMembership
User --(1:N)--> Message
User --(1:N)--> Deployment
User --(1:N)--> UsageEvent

Project --(1:N)--> Conversation --(1:N)--> Message --(1:N)--> AgentAction
Project --(1:N)--> AgentAction
Project --(1:N)--> ProjectFile
Project --(1:N)--> Deployment
Project --(1:N)--> UsageEvent
Project --(N:1)--> Template (optional)
Project --(self N:1)--> Project (forks)

Template --(1:N)--> Project
```

## Models

### Organization

Multi-tenant root entity. Each org has a plan tier, billing state, and credit balance.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| name | String | Display name |
| slug | String | Unique URL slug |
| plan | String | `free`, `pro`, `business`, `enterprise` (default: `free`) |
| stripeCustomerId | String? | Stripe integration |
| creditBalance | Decimal(10,4) | Current credit balance (default: 50) |
| createdAt | DateTime | Auto-set |
| updatedAt | DateTime | Auto-updated |

Table name: `organizations`

### User

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| email | String | Unique |
| name | String? | Display name |
| avatarUrl | String? | Profile image |
| keycloakId | String? | Unique, links to Keycloak OIDC |
| createdAt | DateTime | Auto-set |

Table name: `users`

### OrgMembership

Join table for users and organizations with role-based access.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| userId | UUID | FK to User |
| orgId | UUID | FK to Organization |
| role | String | `owner`, `admin`, `member`, `viewer` (default: `member`) |
| createdAt | DateTime | Auto-set |

Unique constraint: `(userId, orgId)`. Table name: `org_memberships`

### Project

Central entity representing a user's application workspace.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| orgId | UUID | FK to Organization |
| creatorId | UUID | User who created the project |
| name | String | Display name |
| slug | String | URL slug (unique within org) |
| description | String? | Project description |
| visibility | String | `public`, `private`, `internal` (default: `private`) |
| templateId | UUID? | FK to Template (if created from template) |
| forkedFromId | UUID? | Self-referencing FK (fork source) |
| techStack | Json? | `{framework, styling, ...}` |
| containerId | String? | Docker container ID or K8s pod name |
| containerName | String? | Human-readable container name |
| previewUrl | String? | Live preview URL |
| snapshotKey | String? | S3 key for latest snapshot |
| snapshotHash | String? | SHA-256 of snapshot content |
| status | String | `stopped`, `starting`, `running`, `error` (default: `stopped`) |
| createdAt | DateTime | Auto-set |
| updatedAt | DateTime | Auto-updated |

Unique constraint: `(orgId, slug)`. Indexes: `orgId`, `creatorId`. Table name: `projects`

### ProjectFile

Tracks files within a project for database-level persistence (separate from container filesystem).

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| projectId | UUID | FK to Project (cascade delete) |
| path | String | Relative path, e.g. `src/components/Button.tsx` |
| content | Text? | File content |
| contentHash | String? | SHA-256 of content |
| isDirectory | Boolean | Default: false |
| updatedAt | DateTime | Auto-updated |

Unique constraint: `(projectId, path)`. Table name: `project_files`

### Conversation

Groups messages within a project. A project can have multiple conversations.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| projectId | UUID | FK to Project (cascade delete) |
| createdAt | DateTime | Auto-set |

Index: `projectId`. Table name: `conversations`

### Message

Individual messages in a conversation, from users or the AI assistant.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| conversationId | UUID | FK to Conversation (cascade delete) |
| userId | UUID? | FK to User (null for assistant messages) |
| role | String | `user`, `assistant`, `system` |
| content | Text | Message body |
| toolCalls | Json? | Tool call records from the LLM |
| modelUsed | String? | Which model generated this (e.g., `claude-sonnet-4`) |
| providerUsed | String? | Which provider was used (e.g., `bedrock`) |
| tokenUsage | Json? | `{input, output, cached}` |
| creditsConsumed | Decimal(10,4)? | Billing credits used |
| durationMs | Int? | LLM response time |
| createdAt | DateTime | Auto-set |

Index: `conversationId`. Table name: `messages`

### AgentAction

Records every tool execution (file operations, shell commands) by the AI agent.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| projectId | UUID | FK to Project (cascade delete) |
| messageId | UUID? | FK to Message (which message triggered this) |
| type | String | `file_write`, `file_read`, `shell_exec`, `file_list` |
| input | Json | Tool input parameters |
| output | Text? | Tool execution result |
| status | String | `pending`, `running`, `success`, `error` (default: `pending`) |
| durationMs | Int? | Execution time |
| createdAt | DateTime | Auto-set |

Index: `projectId`. Table name: `agent_actions`

### UsageEvent

Tracks resource consumption for billing purposes.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| orgId | UUID | FK to Organization |
| userId | UUID | FK to User |
| projectId | UUID? | FK to Project (optional) |
| eventType | String | `llm_call`, `build`, `deploy`, `storage` |
| creditsUsed | Decimal(10,4) | Credits consumed |
| metadata | Json? | `{model, tokensIn, tokensOut, provider}` |
| createdAt | DateTime | Auto-set |

Indexes: `(orgId, createdAt)`, `(userId, createdAt)`. Table name: `usage_events`

### CreditLedgerEntry

Append-only ledger for credit balance changes. Supports double-entry accounting.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| orgId | UUID | FK to Organization |
| amount | Decimal(10,4) | Positive = credit, negative = debit |
| balanceAfter | Decimal(10,4) | Running balance after this entry |
| source | String | `subscription`, `top_up`, `daily_grant`, `usage`, `refund` |
| referenceId | String? | Links to UsageEvent or Stripe payment ID |
| description | String? | Human-readable note |
| createdAt | DateTime | Auto-set |

Index: `(orgId, createdAt)`. Table name: `credit_ledger`

### Template

Starter templates that projects can be initialized from.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| name | String | Template name |
| description | String? | Template description |
| category | String | `landing-page`, `dashboard`, `e-commerce`, `api`, `blog` |
| thumbnailUrl | String? | Preview image |
| techStack | Json | `{framework, styling, ...}` |
| fileSnapshot | Json | `{path: content}` for initial files |
| popularity | Int | Download/use count (default: 0) |
| isFeatured | Boolean | Show on homepage (default: false) |
| createdAt | DateTime | Auto-set |

Table name: `templates`

### Deployment

Tracks deployed instances of projects.

| Field | Type | Notes |
|-------|------|-------|
| id | UUID | Primary key |
| projectId | UUID | FK to Project (cascade delete) |
| deployedBy | UUID | FK to User |
| environment | String | `preview`, `production` (default: `preview`) |
| status | String | `building`, `deployed`, `failed`, `stopped` (default: `building`) |
| url | String? | Deployed URL |
| customDomain | String? | Custom domain if configured |
| containerId | String? | Deployment container ID |
| buildLog | Text? | Full build output |
| imageTag | String? | Docker image tag |
| createdAt | DateTime | Auto-set |
| updatedAt | DateTime | Auto-updated |

Index: `projectId`. Table name: `deployments`

## Related Documentation

- [Workspace Lifecycle](workspace-lifecycle.md) -- how `containerId`, `containerName`, `snapshotKey`, and `snapshotHash` on `Project` are managed
- [Event System](event-system.md) -- billing events correlate with `UsageEvent` and `CreditLedgerEntry`
