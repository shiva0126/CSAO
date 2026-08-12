select
 function_name
from
 aws_lambda_function
where
 vpc_config is null;
