# Github Webhook via AWS Lamba Python

An exploration of leveraging AWS Lamba to produce "serverless" python handling for github webhooks.

## Deployment

You should be able to deploy this without editing any application code to get a basic check going.

### Things to Install

- [Terraform](https://www.terraform.io/) -- to push code and configuration to AWS
- [Python 2.7](https://www.python.org/downloads/release/python-2713/) -- to build the application

### Credentials to Acquire

1. AWS Access Key
2. AWS Secret Key
3. Github Token

Copy `variables.tf.example.txt` to `variables.tf` and fill in the AWS credentials. Then create `src/ghtoken.txt` and place the Github token in that file.

### Build

This will fetch all the requirements and place them in vendor where `main.py` will seek them out.
```bash
$ pip install -r src/vendor/requirements.txt -t src/vendor 
```

If you'd like, you can also locally test the code by running
 
```bash
$ python src/main.py 
```

### Deploy

Now that the application is "built" and all the secrets are in place, you can deploy the whole thing with:

```bash
$ terraform apply 
```

This will package your app (`src/`) into a zip file, upload it as your lamda function and setup all the function, api gateway, and logging AWS configurations to run the code "serverless"ly. At the end of the run, you'll get output that looks like this:

```
prod_url = https://xxxxxxx.execute-api.xxxxxx.amazonaws.com/prod/hook    
```

Copy this URL and add it as a `Content-type: application/json` webhook to your repository. Run the test ping event and go check your Lambda function logs to see that it went through!

## Thanks

I used these are references and starting points for this project

- [Using Terraform to setup AWS API-Gateway and Lambda](https://andydote.co.uk/2017/03/17/terraform-aws-lambda-api-gateway/) -- Credit where due, most of the terraform states came from this fellow.
- [Terraforming Amazon AWS Lambda function and related API Gateway](http://www.arvinep.com/2016/06/terraforming-amazon-aws-lambda-function.html) -- Helped with a missing cloudwatch log setup

# TODO

As I commit (weekend projects!) this doesn't actually _do_ anything in the webhook response. I want to add [secret validation](https://github.com/carlos-jenkins/python-github-webhooks/blob/870c39e2cd66405014ef66e1011ca5399413cd2a/webhooks.py#L70) first and then some instructions on setting up the webhook for pull requests to do some basic check type structure.

I'd also like to explore [triggering secondary lambda functions](https://stackoverflow.com/questions/36784925/how-to-get-return-response-from-aws-lambda-function?rq=1) in order to spread the task work out and to allow for much faster hook replies (async calls to the secondaries).

Good times!