pipeline {
    agent any

    stages {
        stage('Checkout Code') {
            steps {
                echo "Fetching code from GitHub..."
                checkout scm
            }
        }

        stage('Build') {
            steps {
                echo "Building application..."
            }
        }

        stage('Test') {
            steps {
                echo "Running tests..."
            }
        }
    }
}
