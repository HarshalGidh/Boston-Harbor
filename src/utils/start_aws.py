# -------------------------------------Start Aws---------------------
import paramiko

# Set up the SSH key file, IP, username, and passphrase
key_path = "keys/aws_key.pem"  # Path to the converted .pem file
hostname = "172.31.15.173"  # AWS EC2 public IP address
username = "pragatidhobe"  # EC2 instance username
passphrase = "12345678"  # Passphrase, if any

# Create an SSH client instance
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    # Load SSH key
    key = paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)

    # Connect to the instance
    ssh_client.connect(hostname=hostname, username=username, pkey=key)

    # Execute a command (example)
    stdin, stdout, stderr = ssh_client.exec_command("ls")
    print(stdout.read().decode())  # Print command output

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    ssh_client.close()

# -------------------------------------End Aws---------------------