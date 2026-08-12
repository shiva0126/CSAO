select
 name,
 log_file_validation_enabled
from
 aws_cloudtrail_trail
where
 log_file_validation_enabled=false;
