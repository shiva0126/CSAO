select
 user_name,
 arn
from
 aws_iam_user
where
 mfa_active = false;
