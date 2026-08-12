select
    user_name,
    access_key_id,
    status
from
    aws_iam_access_key
where
    status='Active';
