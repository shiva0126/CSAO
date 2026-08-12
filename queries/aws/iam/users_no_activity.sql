select
    user_name,
    password_last_used
from
    aws_iam_user
where
    password_last_used is null;
