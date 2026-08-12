select
    instance_id,
    monitoring_state
from
    aws_ec2_instance
where
    monitoring_state != 'enabled';
