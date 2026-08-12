select
 function_name,
 runtime,
 region
from
 aws_lambda_function
where
 package_type='Zip';
