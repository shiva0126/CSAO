select
 instance_id,
 metadata_options ->> 'HttpTokens' as imdsv2,
 region
from
 aws_ec2_instance
where
 metadata_options ->> 'HttpTokens'
 != 'required';
