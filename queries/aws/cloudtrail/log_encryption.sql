select
    name,
    kms_key_id
from
    aws_cloudtrail_trail
where
    kms_key_id is null;
