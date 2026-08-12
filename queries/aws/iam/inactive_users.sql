select
 user_name,
 arn
from
 aws_iam_user
where
 password_last_used is null;
