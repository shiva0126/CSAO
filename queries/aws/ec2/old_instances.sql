select
 instance_id,
 launch_time,
 instance_type,
 region
from
 aws_ec2_instance
where
 launch_time < now() - interval '365 days';
