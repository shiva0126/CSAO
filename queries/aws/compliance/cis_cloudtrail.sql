select
 name,
 is_logging
from
 aws_cloudtrail_trail
where
 is_logging=false;
