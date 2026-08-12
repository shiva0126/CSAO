select
    name,
    mfa_delete
from
    aws_s3_bucket
where
    mfa_delete != 'Enabled';
