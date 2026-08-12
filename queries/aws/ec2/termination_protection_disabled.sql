select
    instance_id,
    instance_state,
    disable_api_termination
from
    aws_ec2_instance
where
    disable_api_termination = false;
