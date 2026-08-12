select
 user_name,
 access_key_id,
 create_date
from
 aws_iam_access_key
where
 create_date < now() - interval '90 days';
