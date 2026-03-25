pipeline {
    agent any

    environment {
        WORKSPACE_DIR = "${WORKSPACE}"
    }

    stages {

        stage('Clone Repository') {
            steps {
                echo 'Cloning the GitHub Repository...'
                sh '''
                    rm -rf temp_repo
                    git clone --depth=1 https://github.com/Akashsonawane571/DevSecOps.git temp_repo
                '''
            }
        }

        sstage('Prepare Dependencies') {
    steps {
        echo "Installing dependencies (Node via Docker)..."
        sh '''
            if [ -f temp_repo/package.json ]; then
                echo "Node project detected"

                docker run --rm \
                  -v $(pwd)/temp_repo:/app \
                  -w /app \
                  node:18-alpine \
                  npm install --package-lock-only
            else
                echo "No package.json found, skipping"
            fi
        '''
    }
}
        stage('SBOM Generation (Syft)') {
            steps {
                echo "Generating SBOM..."
                sh '''
                    mkdir -p sca/sbom

                    docker run --rm \
                      -v $(pwd):/workspace \
                      anchore/syft:latest dir:/workspace/temp_repo \
                      -o json > sca/sbom/sbom.json
                '''
            }
        }

        stage('Vulnerability Scan (Grype)') {
            steps {
                echo "Running Grype scan..."
                sh '''
                    mkdir -p sca/reports

                    docker run --rm \
                      -v $(pwd):/workspace \
                      anchore/grype:latest sbom:/workspace/sca/sbom/sbom.json \
                      -o json > sca/reports/grype-report.json
                '''
            }
        }

        stage('Trivy Scan (CI/CD Gate)') {
            steps {
                echo "Running Trivy scan..."

                sh '''
                    docker run --rm \
                      -v $(pwd):/workspace \
                      aquasec/trivy:0.49.1 fs /workspace/temp_repo \
                      --scanners vuln \
                      --exit-code 1 \
                      --severity HIGH,CRITICAL
                '''
            }
        }

        stage('FOSSA Scan (Policy & License)') {
            steps {
                echo "Running FOSSA scan..."

                withCredentials([string(credentialsId: 'fossa-api-key', variable: 'FOSSA_API_KEY')]) {
                    sh '''
                        docker run --rm \
                          -e FOSSA_API_KEY=$FOSSA_API_KEY \
                          -v $(pwd)/temp_repo:/workspace \
                          -w /workspace \
                          fossa-cli analyze || true
                    '''
                }
            }
        }
    }

    post {
        always {
            echo "Archiving reports..."
            archiveArtifacts artifacts: 'sca/**/*.json', fingerprint: true
        }

        failure {
            echo "❌ Pipeline failed due to security issues!"
        }

        success {
            echo "✅ Pipeline passed security checks!"
        }
    }
}
