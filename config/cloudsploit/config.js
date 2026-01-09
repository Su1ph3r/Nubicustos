// CloudSploit Configuration for AWS Scanning
// Uses environment variables for credentials

module.exports = {
    credentials: {
        aws: {
            // Use AWS credentials file mounted at /root/.config/aws/credentials
            credential_file: process.env.AWS_SHARED_CREDENTIALS_FILE || '/root/.config/aws/credentials'
        }
    }
};
