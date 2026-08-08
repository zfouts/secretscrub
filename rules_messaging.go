// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

import "regexp"

// messagingRules recognize chat and mail credentials, including the webhook
// URLs where possession alone is authorization.
var messagingRules = []Rule{
	{
		ID: "slack-token", Category: CategoryMessaging, Confidence: 0.97,
		Description: "Slack bot, user, app-level or legacy token",
		Contains:    "xox",
		Pattern:     regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`),
	},
	{
		ID: "slack-app-token", Category: CategoryMessaging, Confidence: 0.97,
		Description: "Slack app-level token",
		Contains:    "xapp-",
		Pattern:     regexp.MustCompile(`\bxapp-\d-[A-Za-z0-9-]{20,}\b`),
	},
	{
		ID: "slack-webhook", Category: CategoryMessaging, Confidence: 0.98,
		Description: "Slack incoming webhook; possession is authorization",
		Contains:    "hooks.slack.com",
		Pattern:     regexp.MustCompile(`(?i)https://hooks\.slack\.com/(?:services|workflows|triggers)/\S+`),
	},
	{
		ID: "discord-webhook", Category: CategoryMessaging, Confidence: 0.97,
		Description: "Discord webhook; possession is authorization",
		Contains:    "/api/webhooks/",
		Pattern:     regexp.MustCompile(`(?i)https://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\S+`),
	},
	{
		ID: "discord-bot-token", Category: CategoryMessaging, Confidence: 0.9,
		Description: "Discord bot token",
		Pattern:     regexp.MustCompile(`\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b`),
		MinLen:      59, // 24 + 1 + 6 + 1 + 27, at the low end of each range
	},
	{
		ID: "teams-webhook", Category: CategoryMessaging, Confidence: 0.96,
		Description: "Microsoft Teams incoming webhook; possession is authorization",
		Contains:    "webhook.office.com",
		Pattern:     regexp.MustCompile(`(?i)https://[a-z0-9.-]*webhook\.office\.com/\S+`),
	},
	{
		ID: "telegram-bot-token", Category: CategoryMessaging, Confidence: 0.97,
		Description: "Telegram bot token",
		Contains:    ":aa",
		Pattern:     regexp.MustCompile(`\b\d{8,10}:AA[A-Za-z0-9_-]{32,}\b`),
	},
	{
		ID: "sendgrid-api-key", Category: CategoryMessaging, Confidence: 0.98,
		Description: "SendGrid API key",
		Contains:    "sg.",
		Pattern:     regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b`),
	},
	{
		ID: "mailgun-api-key", Category: CategoryMessaging, Confidence: 0.92,
		Description: "Mailgun private API key",
		Contains:    "key-",
		Pattern:     regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`),
	},
	{
		ID: "mailchimp-api-key", Category: CategoryMessaging, Confidence: 0.96,
		Description: "Mailchimp API key",
		Contains:    "-us",
		Pattern:     regexp.MustCompile(`\b[0-9a-f]{32}-us\d{1,2}\b`),
	},
	{
		ID: "twilio-api-key", Category: CategoryMessaging, Confidence: 0.9,
		Description: "Twilio API key SID",
		Contains:    "sk",
		Pattern:     regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
	},
}
