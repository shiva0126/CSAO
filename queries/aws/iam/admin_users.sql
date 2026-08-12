select
 user_name,
 arn
from
 aws_iam_user
where
 attached_policy_names @> ARRAY['AdministratorAccess'];
