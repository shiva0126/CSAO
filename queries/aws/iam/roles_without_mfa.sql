select
 role_name,
 arn
from
 aws_iam_role
where
 assume_role_policy_document::text like '%sts:AssumeRole%';
