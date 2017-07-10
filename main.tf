provider "aws" {
  profile = "default"
  region = "${var.region}"
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
}

// this will fetch our account_id, no need to hard code it
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "tf_gh_check_role" {
  name = "tf_gh_check_role"
  assume_role_policy = "${file("policy/lambda-role.json")}"
}

resource "aws_iam_role_policy" "tf_gh_check_iam_role_policy" {
  name = "tf_gh_check_iam_role_policy"
  role = "${aws_iam_role.tf_gh_check_role.id}"
  policy = "${file("policy/policy.json")}"
}

data "archive_file" "lambda" {
  type = "zip"
  source_dir  = "./src"
  output_path = "lambda.zip"
}

// we use this same deployment for several functions, lets upload to s3 instead of multiple uploads
resource "aws_s3_bucket" "tf_gh_check_bucket" {
  bucket = "tf-gh-check"
}

resource "aws_s3_bucket_object" "tf_gh_check_bucket_lambdazip" {
  key    = "tf_gh_check_bucket_lambda.zip"
  bucket = "${aws_s3_bucket.tf_gh_check_bucket.bucket}"
  source = "${data.archive_file.lambda.output_path}"
  etag   = "${data.archive_file.lambda.output_md5}"
}

// overall gateway
resource "aws_api_gateway_rest_api" "tf_gh_check_gateway_api" {
  name = "tf_gh_check-api"
  description = "Gateway for terraformed gh check"
}


// Primary interface; incoming lambda function

resource "aws_lambda_function" "tf_gh_check_function_incoming" {
  s3_bucket         = "${aws_s3_bucket_object.tf_gh_check_bucket_lambdazip.bucket}"
  s3_key            = "${aws_s3_bucket_object.tf_gh_check_bucket_lambdazip.key}"
  s3_object_version = "${aws_s3_bucket_object.tf_gh_check_bucket_lambdazip.version_id}"
  function_name = "tf_gh_check_function_incoming"
  role = "${aws_iam_role.tf_gh_check_role.arn}"
  handler = "main.incoming"
  runtime = "python2.7"
  source_code_hash = "${data.archive_file.lambda.output_base64sha256}"
  publish = true
  timeout = 5
}

resource "aws_lambda_permission" "allow_api_gateway" {
  function_name = "${aws_lambda_function.tf_gh_check_function_incoming.arn}"
  statement_id = "AllowExecutionFromApiGateway"
  action = "lambda:InvokeFunction"
  principal = "apigateway.amazonaws.com"
  source_arn = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}/*/${aws_api_gateway_method.tf_gh_check_gateway_method.http_method}${aws_api_gateway_resource.tf_gh_check_gateway_resource.path}"
}

resource "aws_api_gateway_resource" "tf_gh_check_gateway_resource" {
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  parent_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.root_resource_id}"
  path_part = "hook"
}

resource "aws_api_gateway_method" "tf_gh_check_gateway_method" {
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  resource_id = "${aws_api_gateway_resource.tf_gh_check_gateway_resource.id}"
  http_method = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "tf_gh_check_integration" {
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  resource_id = "${aws_api_gateway_resource.tf_gh_check_gateway_resource.id}"
  http_method = "${aws_api_gateway_method.tf_gh_check_gateway_method.http_method}"
  type = "AWS_PROXY"
  uri = "arn:aws:apigateway:${var.region}:lambda:path/2015-03-31/functions/arn:aws:lambda:${var.region}:${data.aws_caller_identity.current.account_id}:function:${aws_lambda_function.tf_gh_check_function_incoming.function_name}/invocations"
  integration_http_method = "POST"
}

resource "aws_cloudwatch_log_group" "tf_gh_check_logs" {
  name = "/aws/lambda/${aws_lambda_function.tf_gh_check_function_incoming.function_name}"
}


// Secondary function, no api gateway just direct invocation from the first

resource "aws_lambda_function" "tf_gh_check_function_secondary" {
  s3_bucket         = "${aws_s3_bucket_object.tf_gh_check_bucket_lambdazip.bucket}"
  s3_key            = "${aws_s3_bucket_object.tf_gh_check_bucket_lambdazip.key}"
  s3_object_version = "${aws_s3_bucket_object.tf_gh_check_bucket_lambdazip.version_id}"
  function_name = "tf_gh_check_function_secondary"
  role = "${aws_iam_role.tf_gh_check_role.arn}"
  handler = "main.secondary"
  runtime = "python2.7"
  source_code_hash = "${data.archive_file.lambda.output_base64sha256}"
  publish = true
  timeout = 30
}


// Log viewing function and api gateway configurations

resource "aws_lambda_function" "tf_gh_check_function_logview" {
  s3_bucket         = "${aws_s3_bucket_object.tf_gh_check_bucket_lambdazip.bucket}"
  s3_key            = "${aws_s3_bucket_object.tf_gh_check_bucket_lambdazip.key}"
  s3_object_version = "${aws_s3_bucket_object.tf_gh_check_bucket_lambdazip.version_id}"
  function_name = "tf_gh_check_function_logview"
  role = "${aws_iam_role.tf_gh_check_role.arn}"
  handler = "main.logview"
  runtime = "python2.7"
  source_code_hash = "${data.archive_file.lambda.output_base64sha256}"
  publish = true
  timeout = 10
}

resource "aws_lambda_permission" "allow_api_gateway_log" {
  function_name = "${aws_lambda_function.tf_gh_check_function_logview.arn}"
  statement_id = "AllowExecutionFromApiGateway"
  action = "lambda:InvokeFunction"
  principal = "apigateway.amazonaws.com"
  source_arn = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}/*/${aws_api_gateway_method.tf_gh_check_gateway_method_log.http_method}${aws_api_gateway_resource.tf_gh_check_gateway_resource_log.path}"
}

resource "aws_api_gateway_resource" "tf_gh_check_gateway_resource_log" {
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  parent_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.root_resource_id}"
  path_part = "log"
}

resource "aws_api_gateway_method" "tf_gh_check_gateway_method_log" {
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  resource_id = "${aws_api_gateway_resource.tf_gh_check_gateway_resource_log.id}"
  http_method = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "tf_gh_check_integration_log" {
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  resource_id = "${aws_api_gateway_resource.tf_gh_check_gateway_resource_log.id}"
  http_method = "${aws_api_gateway_method.tf_gh_check_gateway_method_log.http_method}"
  type = "AWS_PROXY"
  uri = "arn:aws:apigateway:${var.region}:lambda:path/2015-03-31/functions/arn:aws:lambda:${var.region}:${data.aws_caller_identity.current.account_id}:function:${aws_lambda_function.tf_gh_check_function_logview.function_name}/invocations"
  integration_http_method = "POST"
}

resource "aws_cloudwatch_log_group" "tf_gh_logview" {
  name = "/aws/lambda/${aws_lambda_function.tf_gh_check_function_logview.function_name}"
}





resource "aws_api_gateway_deployment" "tf_gh_check_prod" {
  depends_on = [
    "aws_api_gateway_method.tf_gh_check_gateway_method",
    "aws_api_gateway_integration.tf_gh_check_integration",
    "aws_api_gateway_method.tf_gh_check_gateway_method_log",
    "aws_api_gateway_integration.tf_gh_check_integration_log",
  ]
  rest_api_id = "${aws_api_gateway_rest_api.tf_gh_check_gateway_api.id}"
  stage_name = "prod"
}


output "webhook_url" {
  value = "https://${aws_api_gateway_deployment.tf_gh_check_prod.rest_api_id}.execute-api.${var.region}.amazonaws.com/${aws_api_gateway_deployment.tf_gh_check_prod.stage_name}${aws_api_gateway_resource.tf_gh_check_gateway_resource.path}"
}
output "log_url" {
  value = "https://${aws_api_gateway_deployment.tf_gh_check_prod.rest_api_id}.execute-api.${var.region}.amazonaws.com/${aws_api_gateway_deployment.tf_gh_check_prod.stage_name}${aws_api_gateway_resource.tf_gh_check_gateway_resource_log.path}"
}
