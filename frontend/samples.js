// Sample policies for the gallery (the judge's fast path).
// These mirror the good policies in the repo's samples/ directory.
window.POLICYLENS_SAMPLES = [
  {
    name: "Clean S3 read-only role",
    blurb: "A well-scoped policy. Should produce zero findings.",
    policy: {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "ReadAppBucket",
          Effect: "Allow",
          Action: ["s3:GetObject", "s3:ListBucket"],
          Resource: [
            "arn:aws:s3:::my-app-data",
            "arn:aws:s3:::my-app-data/*",
          ],
        },
      ],
    },
  },
  {
    name: "Overprivileged deploy role",
    blurb: "s3:*, cloudformation:*, and unconstrained iam:PassRole on *.",
    policy: {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "Deploy",
          Effect: "Allow",
          Action: ["s3:*", "cloudformation:*", "iam:PassRole"],
          Resource: "*",
        },
        {
          Sid: "ReadLogs",
          Effect: "Allow",
          Action: ["logs:GetLogEvents", "logs:DescribeLogGroups"],
          Resource: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/*",
        },
      ],
    },
  },
  {
    name: "Lambda execution role with secrets access",
    blurb: "Reads every secret and decrypts with any KMS key, no conditions.",
    policy: {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "Logs",
          Effect: "Allow",
          Action: [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ],
          Resource: "arn:aws:logs:*:*:*",
        },
        {
          Sid: "ReadSecrets",
          Effect: "Allow",
          Action: "secretsmanager:GetSecretValue",
          Resource: "*",
        },
        {
          Sid: "DecryptEverything",
          Effect: "Allow",
          Action: ["kms:Decrypt", "kms:DescribeKey"],
          Resource: "*",
        },
      ],
    },
  },
  {
    name: "Nested NotAction / NotResource (gnarly)",
    blurb: "Allow + NotAction, Allow + NotResource, and self-escalation.",
    policy: {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "AllowAllExceptBilling",
          Effect: "Allow",
          NotAction: ["aws-portal:*", "budgets:*"],
          Resource: "*",
        },
        {
          Sid: "AllExceptProd",
          Effect: "Allow",
          Action: "ec2:*",
          NotResource: [
            "arn:aws:ec2:us-east-1:123456789012:instance/i-prod0000000000000",
          ],
        },
        {
          Sid: "SelfEscalate",
          Effect: "Allow",
          Action: [
            "iam:AttachUserPolicy",
            "iam:PutUserPolicy",
            "iam:CreatePolicyVersion",
          ],
          Resource: "*",
        },
      ],
    },
  },
  {
    name: "Public S3 bucket policy",
    blurb: "Principal * with no condition, plus a full-admin statement.",
    policy: {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "PublicRead",
          Effect: "Allow",
          Principal: "*",
          Action: "s3:GetObject",
          Resource: "arn:aws:s3:::public-web-assets/*",
        },
        {
          Sid: "AdminFullAccess",
          Effect: "Allow",
          Principal: { AWS: "*" },
          Action: "*",
          Resource: "*",
        },
      ],
    },
  },
];
