select
 name,
 is_multi_region_trail
from
 aws_cloudtrail_trail
where
 is_multi_region_trail=false;
