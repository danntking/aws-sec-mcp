#!/bin/bash
# AWS Security MCP - Complete CI/CD Pipeline Deployment
# This deploys everything through CloudFormation + CodePipeline

set -e

# Configuration
PROJECT_NAME="aws-security-mcp"
ENVIRONMENT="prod"
REGION="us-east-1"
STACK_NAME="${PROJECT_NAME}-${ENVIRONMENT}-cicd"
GITHUB_OWNER="danntking"
GITHUB_REPO="aws-sec-mcp"
GITHUB_BRANCH="main"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}🚀 AWS Security MCP - CI/CD Pipeline Deployment${NC}"
echo "=================================================="
echo -e "${BLUE}Project: ${PROJECT_NAME}${NC}"
echo -e "${BLUE}Environment: ${ENVIRONMENT}${NC}"
echo -e "${BLUE}Region: ${REGION}${NC}"
echo -e "${BLUE}GitHub: ${GITHUB_OWNER}/${GITHUB_REPO}${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}🔍 Checking prerequisites...${NC}"

if ! command -v aws &> /dev/null; then
    echo -e "${RED}❌ AWS CLI not found${NC}"
    exit 1
fi

aws sts get-caller-identity > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ AWS credentials not configured${NC}"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo -e "${GREEN}✅ AWS Account ID: ${ACCOUNT_ID}${NC}"

# Check GitHub token in SSM
echo -e "${YELLOW}🔑 Checking GitHub token...${NC}"
GITHUB_TOKEN_EXISTS=$(aws ssm get-parameter --name "/github/token" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$GITHUB_TOKEN_EXISTS" == "NOT_FOUND" ]; then
    echo -e "${RED}❌ GitHub token not found in SSM Parameter Store${NC}"
    echo -e "${YELLOW}Please create a GitHub Personal Access Token and store it:${NC}"
    echo ""
    echo "1. Go to GitHub → Settings → Developer settings → Personal access tokens"
    echo "2. Create token with 'repo' permissions"
    echo "3. Store in AWS SSM:"
    echo -e "${BLUE}   aws ssm put-parameter --name '/github/token' --value 'YOUR_TOKEN' --type 'SecureString'${NC}"
    echo ""
    read -p "Press Enter after creating the token, or Ctrl+C to exit..."
    
    # Check again
    GITHUB_TOKEN_EXISTS=$(aws ssm get-parameter --name "/github/token" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo "NOT_FOUND")
    if [ "$GITHUB_TOKEN_EXISTS" == "NOT_FOUND" ]; then
        echo -e "${RED}❌ GitHub token still not found. Exiting.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✅ GitHub token found${NC}"

# Get VPC information
echo -e "${YELLOW}🌐 Discovering VPC and subnet information...${NC}"

DEFAULT_VPC=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text --region $REGION 2>/dev/null)

if [ "$DEFAULT_VPC" == "None" ] || [ -z "$DEFAULT_VPC" ]; then
    DEFAULT_VPC=$(aws ec2 describe-vpcs --query "Vpcs[0].VpcId" --output text --region $REGION)
fi

PUBLIC_SUBNETS=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$DEFAULT_VPC" "Name=map-public-ip-on-launch,Values=true" \
    --query "Subnets[].SubnetId" \
    --output text \
    --region $REGION)

if [ -z "$PUBLIC_SUBNETS" ]; then
    PUBLIC_SUBNETS=$(aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$DEFAULT_VPC" \
        --query "Subnets[].SubnetId" \
        --output text \
        --region $REGION)
fi

PUBLIC_SUBNET_LIST=$(echo $PUBLIC_SUBNETS | tr ' ' ',')
SUBNET_COUNT=$(echo $PUBLIC_SUBNETS | wc -w)

if [ $SUBNET_COUNT -lt 2 ]; then
    echo -e "${RED}❌ At least 2 subnets required. Found: ${SUBNET_COUNT}${NC}"
    exit 1
fi

echo -e "${GREEN}✅ VPC: ${DEFAULT_VPC}${NC}"
echo -e "${GREEN}✅ Subnets: ${PUBLIC_SUBNET_LIST} (${SUBNET_COUNT} subnets)${NC}"

# Deploy CloudFormation stack
echo -e "${YELLOW}☁️  Deploying CI/CD pipeline infrastructure...${NC}"
echo "This will create:"
echo "  • CodePipeline with GitHub integration"
echo "  • CodeBuild project for Docker builds"
echo "  • ECR Repository"
echo "  • ECS Cluster with Fargate"
echo "  • Application Load Balancer"
echo "  • All IAM roles and policies"
echo "  • Automatic deployment from GitHub"
echo ""

aws cloudformation deploy \
    --template-file mcp-cicd-complete.yaml \
    --stack-name $STACK_NAME \
    --parameter-overrides \
        ProjectName=$PROJECT_NAME \
        Environment=$ENVIRONMENT \
        GitHubRepoOwner=$GITHUB_OWNER \
        GitHubRepoName=$GITHUB_REPO \
        GitHubBranch=$GITHUB_BRANCH \
        VpcId=$DEFAULT_VPC \
        PublicSubnetIds=$PUBLIC_SUBNET_LIST \
        DesiredCount=1 \
        ContainerCpu=2048 \
        ContainerMemory=4096 \
    --capabilities CAPABILITY_NAMED_IAM \
    --region $REGION \
    --no-fail-on-empty-changeset

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Infrastructure deployment successful!${NC}"
else
    echo -e "${RED}❌ Infrastructure deployment failed!${NC}"
    exit 1
fi

# Get outputs
echo -e "${YELLOW}📋 Retrieving deployment information...${NC}"

LB_URL=$(aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --query "Stacks[0].Outputs[?OutputKey=='LoadBalancerURL'].OutputValue" \
    --output text \
    --region $REGION)

PIPELINE_NAME=$(aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --query "Stacks[0].Outputs[?OutputKey=='PipelineName'].OutputValue" \
    --output text \
    --region $REGION)

ECR_URI=$(aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --query "Stacks[0].Outputs[?OutputKey=='ECRRepositoryURI'].OutputValue" \
    --output text \
    --region $REGION)

# Start the pipeline
echo -e "${YELLOW}🔄 Starting CodePipeline...${NC}"
aws codepipeline start-pipeline-execution --name $PIPELINE_NAME --region $REGION > /dev/null

echo ""
echo -e "${GREEN}🎉 CI/CD Pipeline Deployment Complete!${NC}"
echo "=============================================="
echo -e "${GREEN}🌐 MCP Server URL: ${LB_URL}${NC}"
echo -e "${GREEN}🔍 Health Check: ${LB_URL}/health${NC}"
echo -e "${GREEN}📋 API Docs: ${LB_URL}/docs${NC}"
echo -e "${GREEN}🚀 Pipeline: ${PIPELINE_NAME}${NC}"
echo -e "${GREEN}📦 ECR Repository: ${ECR_URI}${NC}"
echo ""
echo -e "${YELLOW}⏳ Pipeline Status:${NC}"
echo "  • Source: Pulling from GitHub"
echo "  • Build: Building Docker image"
echo "  • Deploy: Deploying to ECS"
echo ""
echo -e "${BLUE}Monitor pipeline progress:${NC}"
echo "  AWS Console → CodePipeline → ${PIPELINE_NAME}"
echo ""
echo -e "${BLUE}View logs:${NC}"
echo "  aws logs tail /aws/codebuild/${PROJECT_NAME}-${ENVIRONMENT} --follow --region ${REGION}"
echo ""
echo -e "${YELLOW}🔄 The deployment will complete automatically in ~5-10 minutes${NC}"
echo -e "${YELLOW}💡 Any new commits to '${GITHUB_BRANCH}' branch will trigger automatic deployment${NC}"
echo ""
echo -e "${GREEN}Frontend Configuration:${NC}"
echo -e "${YELLOW}VITE_MCP_BACKEND_API_ENDPOINT=${LB_URL}${NC}"